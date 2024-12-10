# main.py

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Header, Query
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Optional
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import secrets

# ##############
# Configuration
# ##############

DATABASE_URL = "sqlite:///./clipboard.db"
JWT_SECRET = "supersecretkey"  # In production, use a secure, random key from environment variables
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

# Initialize SQLAlchemy
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}  # Needed for SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Initialize Passlib for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize FastAPI
app = FastAPI()

# #################
# Database Models
# #################

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

class Clipboard(Base):
    __tablename__ = "clipboard"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)

# Create all tables
Base.metadata.create_all(bind=engine)

# #################
# Pydantic Schemas
# #################

from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class ClipboardCreate(BaseModel):
    text: str

class ClipboardResponse(BaseModel):
    text: str

class Token(BaseModel):
    access_token: str
    token_type: str

# #################
# Utility Functions
# #################

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get current user
def get_current_user(token: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    if token is None:
        raise HTTPException(status_code=401, detail="Missing token")
    username = decode_token(token)
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    return user

# #################
# Initialize Clipboard
# #################

def initialize_clipboard(db: Session):
    clipboard = db.query(Clipboard).first()
    if not clipboard:
        initial_text = "Initial Clipboard Content"
        clipboard = Clipboard(text=initial_text)
        db.add(clipboard)
        db.commit()

# Initialize clipboard on startup
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    initialize_clipboard(db)
    db.close()

# #################
# User Management
# #################

@app.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_pw = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token_expires = timedelta(minutes=JWT_EXPIRATION_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password"
        )
    access_token_expires = timedelta(minutes=JWT_EXPIRATION_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# #################
# Clipboard Management
# #################

@app.get("/clipboard", response_model=ClipboardResponse)
def get_clipboard(db: Session = Depends(get_db)):
    clipboard = db.query(Clipboard).first()
    if not clipboard:
        raise HTTPException(status_code=404, detail="Clipboard not found")
    return {"text": clipboard.text}

@app.post("/clipboard", response_model=ClipboardResponse)
def update_clipboard(
    clipboard: ClipboardCreate, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    clipboard_entry = db.query(Clipboard).first()
    if not clipboard_entry:
        clipboard_entry = Clipboard(text=clipboard.text)
        db.add(clipboard_entry)
    else:
        clipboard_entry.text = clipboard.text
    db.commit()
    db.refresh(clipboard_entry)

    # Broadcast the updated content to all connected websockets
    import asyncio
    asyncio.create_task(broadcast_clipboard_update(clipboard_entry.text))

    return {"text": clipboard_entry.text}

# #################
# WebSocket Handler
# #################

# Store active WebSocket connections
active_connections: List[WebSocket] = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    # Authenticate the WebSocket connection
    if token is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        username = decode_token(token)
        # Optional: Verify the user exists in the database
        db = SessionLocal()
        user = db.query(User).filter(User.username == username).first()
        db.close()
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Accept the connection
    await websocket.accept()
    # Add to active connections
    active_connections.append(websocket)

    try:
        # Send initial clipboard content
        db = SessionLocal()
        clipboard = db.query(Clipboard).first()
        db.close()
        initial_text = clipboard.text if clipboard else ""
        await websocket.send_json({"type": "init", "text": initial_text})

        while True:
            # Keep the connection open. Optionally, handle incoming messages
            await websocket.receive_text()

    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception as e:
        active_connections.remove(websocket)

# ####################
# Helper Functions
# ####################

async def broadcast_clipboard_update(text: str):
    """
    Broadcast the updated clipboard content to all connected websocket clients.
    """
    to_remove = []
    for connection in active_connections:
        try:
            await connection.send_json({"type": "update", "text": text})
        except Exception:
            to_remove.append(connection)
    # Clean up broken connections
    for conn in to_remove:
        active_connections.remove(conn)

# ################
# Run the app! #
# ################

# To run:
# uvicorn main:app --reload
#
# Then test by:
# 1. Register a new user:
#    curl -X POST "http://127.0.0.1:8000/register" -H "Content-Type: application/json" -d '{"username": "alice", "password": "secret123"}'
#
#    Response:
#    {
#      "access_token": "<token>",
#      "token_type": "bearer"
#    }
#
# 2. Or Login with existing user:
#    curl -X POST -F "username=alice" -F "password=secret123" http://127.0.0.1:8000/login
#
# 3. GET clipboard:
#    curl http://127.0.0.1:8000/clipboard
#
# 4. POST (update) clipboard:
#    curl -X POST http://127.0.0.1:8000/clipboard \
#         -H "Authorization: Bearer <your_access_token>" \
#         -H "Content-Type: application/json" \
#         -d '{"text": "New clipboard content"}'
#
# 5. WebSocket connection with authentication:
#    Using wscat:
#    wscat -c "ws://127.0.0.1:8000/ws?token=<your_access_token>"
#
#    Or using browser JavaScript:
#    const token = "<your_access_token>";
#    const ws = new WebSocket(`ws://127.0.0.1:8000/ws?token=${token}`);
#
#    ws.onmessage = (event) => {
#        const data = JSON.parse(event.data);
#        if (data.type === "init") {
#            console.log("Initial Clipboard Content:", data.text);
#        } else if (data.type === "update") {
#            console.log("Clipboard Updated:", data.text);
#        }
#    };

