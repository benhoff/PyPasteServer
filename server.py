from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordRequestForm
from typing import List
from jose import jwt, JWTError
from datetime import datetime, timedelta
import secrets

app = FastAPI()

# In-memory "database"
USERS = {
    "alice": {
        "password": "secret123"  # Obviously, store hashed passwords in production
    }
}
JWT_SECRET = "supersecretkey"  # In production, use a secure, random key
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

clipboard_content = "Initial Clipboard Content"

# Store active WebSocket connections
active_connections: List[WebSocket] = []

#######################
# Authentication Utils #
#######################

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(token: str = Header(None)):
    if token is None:
        raise HTTPException(status_code=401, detail="Missing token")
    username = decode_token(token)
    if username not in USERS:
        raise HTTPException(status_code=401, detail="Invalid user")
    return username

###############
# HTTP Routes #
###############

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Simple user check
    username = form_data.username
    password = form_data.password

    user = USERS.get(username)
    if not user or user["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password"
        )

    access_token_expires = timedelta(minutes=JWT_EXPIRATION_MINUTES)
    access_token = create_access_token(data={"sub": username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/clipboard")
async def get_clipboard():
    return {"text": clipboard_content}

@app.post("/clipboard")
async def update_clipboard(text: str, current_user: str = Depends(get_current_user)):
    global clipboard_content
    clipboard_content = text

    # Broadcast the updated content to all connected websockets
    await broadcast_clipboard_update(text)
    return {"status": "updated", "text": clipboard_content}


#####################
# WebSocket Handler #
#####################

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    # Authenticate the WebSocket connection
    if token is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        username = decode_token(token)
        if username not in USERS:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Accept the connection
    await websocket.accept()
    # Add this websocket connection to our active connections
    active_connections.append(websocket)

    try:
        # Optionally, we could send the initial clipboard content to the client immediately
        await websocket.send_json({"type": "init", "text": clipboard_content})

        # Keep the connection open until the client disconnects
        while True:
            # We might expect some kind of heartbeat or message from the client.
            # This will block until a message is received or the connection is closed.
            await websocket.receive_text()

    except WebSocketDisconnect:
        # Remove the connection when the client disconnects
        active_connections.remove(websocket)
    except Exception as e:
        # Handle other exceptions and remove the connection
        active_connections.remove(websocket)


####################
# Helper Functions #
####################

async def broadcast_clipboard_update(text: str):
    """
    Broadcast the updated clipboard content to all connected websocket clients.
    """
    to_remove = []
    for connection in active_connections:
        try:
            await connection.send_json({"type": "update", "text": text})
        except Exception:
            # If sending fails, mark the connection for removal
            to_remove.append(connection)
    # Clean up broken connections
    for conn in to_remove:
        active_connections.remove(conn)


################
# Run the app! #
################

# To run:
# uvicorn filename:app --reload
#
# Then test by:
# 1. Login:
#    curl -X POST -F "username=alice" -F "password=secret123" http://127.0.0.1:8000/login
#
# 2. GET clipboard:
#    curl http://127.0.0.1:8000/clipboard
#
# 3. POST (update) clipboard:
#    curl -X POST http://127.0.0.1:8000/clipboard -H "token: <your_access_token>" -d "text=New clipboard content"
#
# 4. WebSocket connection:
#    Using a WebSocket client (like wscat or browser JS), connect to ws://127.0.0.1:8000/ws
#    wscat example: `wscat -c ws://127.0.0.1:8000/ws`
#    You will receive updates whenever someone posts a new clipboard content.
