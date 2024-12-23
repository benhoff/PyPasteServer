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
import redis.asyncio as redis

# ####################
# Configuration
# ####################

DATABASE_URL = "sqlite:///./clipboard.db"
JWT_SECRET = "supersecretkey"  # In production, use a secure, random key from environment variables
JWT_ALGORITHM = "HS256"

# Redis configuration
REDIS_URL = "redis://redis:6379"  # Update as needed

# Initialize SQLAlchemy
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}  # Needed for SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()  # Updated import path

# Initialize Passlib for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize Redis
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

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
    ciphertext = Column(Text, nullable=False)  # Encrypted text
    nonce = Column(String(255), nullable=False)  # Nonce for decryption
    tag = Column(String(255), nullable=False)    # Authentication tag
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
# Base.metadata.create_all(bind=engine)

# #################
# Pydantic Schemas
# #################

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr  # Ensures valid email format

class ClipboardCreate(BaseModel):
    ciphertext: str
    nonce: str
    tag: str

class ClipboardResponse(BaseModel):
    ciphertext: str
    nonce: str
    tag: str

    class Config:
        orm_mode = True

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
    Initializes a clipboard for a newly registered user with default encrypted content.
    """
    # Example: Initialize with empty encrypted fields or some default encrypted content
    # Here, we'll initialize with empty strings. Adjust as needed.
    clipboard = Clipboard(ciphertext="", nonce="", tag="", owner_id=user.id)
    db.add(clipboard)
    db.commit()
    db.refresh(clipboard)

# #################
# Connection Manager with Redis Pub/Sub and Connection Counting
# #################

class ConnectionManager:
    def __init__(self):
        # Maps user_id to a set of WebSocket connections (local to the worker)
        self.active_connections: Dict[int, List[WebSocket]] = {}
        self.lock = asyncio.Lock()
        self.pubsub = None
        self.redis_sub = None

    async def connect_redis(self):
        """
        Connect to Redis and subscribe to the clipboard_updates channel.
        """
        self.pubsub = redis_client.pubsub()
        await self.pubsub.subscribe("clipboard_updates")
        self.redis_sub = self.pubsub

    async def listen_redis(self):
        """
        Listen for messages from Redis and broadcast them to local WebSockets.
        """
        async for message in self.pubsub.listen():
            if message["type"] == "update":
                data = json.loads(message["data"])
                user_id = data.get("user_id")
                ciphertext = data.get("ciphertext")
                nonce = data.get("nonce")
                tag = data.get("tag")
                if user_id and ciphertext and nonce and tag:
                    update_message = {
                        "type": "update",
                        "ciphertext": ciphertext,
                        "nonce": nonce,
                        "tag": tag
                    }
                    await self.broadcast(user_id, update_message)

    async def start_listening(self):
        """
        Start the Redis listener in the background.
        """
        await self.connect_redis()
        asyncio.create_task(self.listen_redis())

    async def increment_connection_count(self, user_id: int):
        """
        Increment the Redis counter for the user's active connections.
        """
        key = f"user:{user_id}:connections"
        await redis_client.incr(key)

    async def decrement_connection_count(self, user_id: int):
        """
        Decrement the Redis counter for the user's active connections.
        """
        key = f"user:{user_id}:connections"
        # Use DECR only if the key exists to prevent negative counts
        current = await redis_client.decr(key)
        if current < 0:
            await redis_client.set(key, 0)

    async def get_connection_count(self, user_id: int) -> int:
        """
        Retrieve the current connection count for the user from Redis.
        """
        key = f"user:{user_id}:connections"
        count = await redis_client.get(key)
        return int(count) if count else 0

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []
            self.active_connections[user_id].append(websocket)
        await self.increment_connection_count(user_id)
        total_connections = await self.get_connection_count(user_id)
        print(f"User {user_id} connected. Total connections: {total_connections}")

    async def disconnect(self, user_id: int, websocket: WebSocket):
        async with self.lock:
            if user_id in self.active_connections:
                if websocket in self.active_connections[user_id]:
                    self.active_connections[user_id].remove(websocket)
                    await self.decrement_connection_count(user_id)
                    total_connections = await self.get_connection_count(user_id)
                    print(f"User {user_id} disconnected. Remaining connections: {total_connections}")
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
                        await self.decrement_connection_count(user_id)
                        total_connections = await self.get_connection_count(user_id)
                        print(f"User {user_id} connection removed due to error. Remaining connections: {total_connections}")
                if user_id in self.active_connections and not self.active_connections[user_id]:
                    del self.active_connections[user_id]

    async def publish_update(self, user_id: int, message: dict):
        """
        Publish an encrypted update to Redis to notify all workers.
        """
        message_json = json.dumps(message)
        await redis_client.publish("clipboard_updates", message_json)

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
    Base.metadata.create_all(bind=engine)
    # Startup tasks
    await manager.start_listening()
    yield
    # Shutdown tasks
    await manager.pubsub.unsubscribe("clipboard_updates")
    await manager.pubsub.close()
    await redis_client.close()

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
    return ClipboardResponse(
        ciphertext=clipboard.ciphertext,
        nonce=clipboard.nonce,
        tag=clipboard.tag
    )

@app.post("/clipboard", response_model=ClipboardResponse)
def update_clipboard(
    clipboard: ClipboardCreate, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    clipboard_entry = db.query(Clipboard).filter(Clipboard.owner_id == current_user.id).first()
    if not clipboard_entry:
        # Initialize clipboard if it doesn't exist
        clipboard_entry = Clipboard(
            ciphertext=clipboard.ciphertext,
            nonce=clipboard.nonce,
            tag=clipboard.tag,
            owner_id=current_user.id
        )
        db.add(clipboard_entry)
    else:
        # Update existing clipboard
        clipboard_entry.ciphertext = clipboard.ciphertext
        clipboard_entry.nonce = clipboard.nonce
        clipboard_entry.tag = clipboard.tag
    db.commit()
    db.refresh(clipboard_entry)

    # Publish the updated encrypted content to Redis to broadcast to all workers
    message = {
        "type": "update",
        "ciphertext": clipboard_entry.ciphertext,
        "nonce": clipboard_entry.nonce,
        "tag": clipboard_entry.tag
    }
    asyncio.create_task(manager.publish_update(current_user.id, message))

    return ClipboardResponse(
        ciphertext=clipboard_entry.ciphertext,
        nonce=clipboard_entry.nonce,
        tag=clipboard_entry.tag
    )

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
        # Send initial encrypted clipboard content and connection count
        db = SessionLocal()
        clipboard = db.query(Clipboard).filter(Clipboard.owner_id == user.id).first()
        db.close()
        if clipboard:
            initial_message = {
                "type": "init",
                "ciphertext": clipboard.ciphertext,
                "nonce": clipboard.nonce,
                "tag": clipboard.tag,
                "connection_count": await manager.get_connection_count(user.id)
            }
        else:
            initial_message = {
                "type": "init",
                "ciphertext": "",
                "nonce": "",
                "tag": "",
                "connection_count": await manager.get_connection_count(user.id)
            }
        await websocket.send_json(initial_message)

        while True:
            # Receive the incoming encrypted message
            data = await websocket.receive_json()
            print(data)
            # Expecting a message with type, ciphertext, nonce, and tag

            if data.get("type") == "update":
                ciphertext = data.get("ciphertext")
                nonce = data.get("nonce")
                tag = data.get("tag")

                if not all([ciphertext, nonce, tag]):
                    # Invalid message format
                    continue

                """
                # Update the clipboard in the database
                clipboard_entry = db.query(Clipboard).filter(Clipboard.owner_id == user.id).first()
                if not clipboard_entry:
                    clipboard_entry = Clipboard(
                        ciphertext=ciphertext,
                        nonce=nonce,
                        tag=tag,
                        owner_id=user.id
                    )
                    db.add(clipboard_entry)
                else:
                    clipboard_entry.ciphertext = ciphertext
                    clipboard_entry.nonce = nonce
                    clipboard_entry.tag = tag
                db.commit()
                db.refresh(clipboard_entry)
                """
                # Broadcast the encrypted update to all connected clients via Redis
                message = {
                    "type": "update",
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "tag": tag
                }
                asyncio.create_task(manager.publish_update(user.id, message))

    except WebSocketDisconnect:
        await manager.disconnect(user.id, websocket)
    except Exception as e:
        await manager.disconnect(user.id, websocket)
        print(f"WebSocket error for user {user.username}: {e}")

