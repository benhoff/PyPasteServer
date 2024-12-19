from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Header, Query
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Optional, Dict
from jose import jwt, JWTError
from datetime import datetime
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import asyncio
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
import uuid
import json

# ####################
# Configuration
# ####################

DATABASE_URL = "sqlite:///./clipboard.db"
JWT_SECRET = "supersecretkey"  # In production, use a secure, random key from environment variables
JWT_ALGORITHM = "HS256"

# Initialize SQLAlchemy
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}  # Needed for SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()  # Updated import path

# Initialize Passlib for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# #################
# Database Models
# #################

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    email_authenticated = Column(Boolean, default=False, nullable=False)

    clipboard = relationship("Clipboard", uselist=False, back_populates="owner")
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")


class Clipboard(Base):
    __tablename__ = "clipboards"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)

    owner = relationship("User", back_populates="clipboard")


class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(512), unique=True, nullable=False)  # Store the JWT
    jti = Column(String(36), unique=True, nullable=False)     # JWT ID
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="tokens")


# Create all tables
Base.metadata.create_all(bind=engine)

# #################
# Pydantic Schemas
# #################

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr  # Ensures valid email format

class ClipboardCreate(BaseModel):
    text: str

class ClipboardResponse(BaseModel):
    text: str

class TokenSchema(BaseModel):
    access_token: str
    token_type: str

# #################
# Utility Functions
# #################

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, db: Session) -> str:
    to_encode = data.copy()
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    # Omitting the "exp" claim for indefinite tokens
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Store the token in the database
    token_entry = Token(token=encoded_jwt, jti=jti, user_id=data["user_id"])
    db.add(token_entry)
    db.commit()
    
    return encoded_jwt

def decode_token(token: str, db: Session) -> User:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        if username is None or jti is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Retrieve the user
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid user")

        # Check if the token exists and is active
        token_entry = db.query(Token).filter(Token.jti == jti, Token.user_id == user.id).first()
        if not token_entry:
            raise HTTPException(status_code=401, detail="Token has been revoked or is invalid")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Dependency to get DB session
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get current user
def get_current_user(token: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    if token is None:
        raise HTTPException(status_code=401, detail="Missing token")
    user = decode_token(token, db)
    return user

# #################
# Initialize Clipboard
# #################

def initialize_user_clipboard(db: Session, user: User):
    """
    Initializes a clipboard for a newly registered user.
    """
    clipboard = Clipboard(text="Initial Clipboard Content", owner_id=user.id)
    db.add(clipboard)
    db.commit()
    db.refresh(clipboard)

# #################
# Connection Manager
# #################

class ConnectionManager:
    def __init__(self):
        # Maps user_id to a set of WebSocket connections
        self.active_connections: Dict[int, List[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []
            self.active_connections[user_id].append(websocket)
        print(f"User {user_id} connected. Total connections: {len(self.active_connections[user_id])}")

    async def disconnect(self, user_id: int, websocket: WebSocket):
        async with self.lock:
            if user_id in self.active_connections:
                if websocket in self.active_connections[user_id]:
                    self.active_connections[user_id].remove(websocket)
                    print(f"User {user_id} disconnected. Remaining connections: {len(self.active_connections[user_id])}")
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, user_id: int, message: dict):
        async with self.lock:
            connections = self.active_connections.get(user_id, []).copy()
        to_remove = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"Failed to send message to connection: {e}")
                to_remove.append(connection)
        if to_remove:
            async with self.lock:
                for conn in to_remove:
                    if conn in self.active_connections.get(user_id, []):
                        self.active_connections[user_id].remove(conn)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]

# Initialize the ConnectionManager
manager = ConnectionManager()

# #################
# Initialize FastAPI with Lifespan
# #################

app = FastAPI()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles the application lifespan events: startup and shutdown.
    """
    # Startup tasks (if any)
    yield
    # Shutdown tasks (if any)

# Assign the lifespan handler to the FastAPI app
app.router.lifespan_context = lifespan

# #################
# User Management
# #################

@app.post("/register", response_model=TokenSchema)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed_pw = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pw,
        email_authenticated=False  # Default to False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Initialize user's clipboard
    initialize_user_clipboard(db, new_user)

    access_token = create_access_token(
        data={"sub": new_user.username, "user_id": new_user.id}, db=db
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login", response_model=TokenSchema)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password"
        )
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id}, db=db
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout", status_code=200)
def logout(current_user: User = Depends(get_current_user), authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Invalid authorization header")
    
    token = authorization.split(" ")[1]
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Remove the token from the database to revoke it
        token_entry = db.query(Token).filter(Token.jti == jti, Token.user_id == current_user.id).first()
        if not token_entry:
            raise HTTPException(status_code=400, detail="Token already revoked or invalid")
        
        db.delete(token_entry)
        db.commit()
        
        return {"detail": "Successfully logged out"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# #################
# Clipboard Management
# #################

@app.get("/clipboard", response_model=ClipboardResponse)
def get_clipboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    clipboard = db.query(Clipboard).filter(Clipboard.owner_id == current_user.id).first()
    if not clipboard:
        raise HTTPException(status_code=404, detail="Clipboard not found")
    return {"text": clipboard.text}

@app.post("/clipboard", response_model=ClipboardResponse)
def update_clipboard(
    clipboard: ClipboardCreate, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    clipboard_entry = db.query(Clipboard).filter(Clipboard.owner_id == current_user.id).first()
    if not clipboard_entry:
        # This should not happen as clipboard is initialized on registration
        clipboard_entry = Clipboard(text=clipboard.text, owner_id=current_user.id)
        db.add(clipboard_entry)
    else:
        clipboard_entry.text = clipboard.text
    db.commit()
    db.refresh(clipboard_entry)

    # Broadcast the updated content to all connected websockets for this user
    asyncio.create_task(manager.broadcast(current_user.id, {"type": "update", "text": clipboard_entry.text}))

    return {"text": clipboard_entry.text}

# #################
# WebSocket Handler
# #################

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    # Authenticate the WebSocket connection
    if token is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        db = SessionLocal()
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        jti = payload.get("jti")
        if username is None or jti is None:
            raise JWTError

        # Retrieve the user
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise JWTError

        # Check if the token exists and is active
        token_entry = db.query(Token).filter(Token.jti == jti, Token.user_id == user.id).first()
        if not token_entry:
            raise JWTError

        db.close()
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Connect the WebSocket
    await manager.connect(user.id, websocket)

    try:
        # Send initial clipboard content
        db = SessionLocal()
        clipboard = db.query(Clipboard).filter(Clipboard.owner_id == user.id).first()
        db.close()
        initial_text = clipboard.text if clipboard else ""
        await websocket.send_json({"type": "init", "text": initial_text})

        while True:
            # Receive the incoming message
            data = await websocket.receive_text()
            # Here, you can define how to handle incoming messages.
            # For example, updating the clipboard or handling specific commands.

            # For demonstration, let's assume incoming messages are clipboard updates
            # Update the clipboard in the database
            db = SessionLocal()
            clipboard_entry = db.query(Clipboard).filter(Clipboard.owner_id == user.id).first()
            if not clipboard_entry:
                clipboard_entry = Clipboard(text=data, owner_id=user.id)
                db.add(clipboard_entry)
            else:
                clipboard_entry.text = data
            db.commit()
            db.refresh(clipboard_entry)
            db.close()

            # Broadcast the updated content to all connected websockets for this user
            await manager.broadcast(user.id, {"type": "update", "text": clipboard_entry.text})

    except WebSocketDisconnect:
        await manager.disconnect(user.id, websocket)
    except Exception as e:
        await manager.disconnect(user.id, websocket)
        print(f"WebSocket error for user {user.username}: {e}")
