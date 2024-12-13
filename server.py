from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Header, Query
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Optional, Generator, Dict
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import asyncio
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
import uuid

# ####################
# Configuration
# ####################

DATABASE_URL = "sqlite:///./clipboard.db"
JWT_SECRET = "supersecretkey"  # In production, use a secure, random key from environment variables
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

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


class Clipboard(Base):
    __tablename__ = "clipboards"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)

    owner = relationship("User", back_populates="clipboard")


class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(36), unique=True, nullable=False)  # UUID4 has 36 characters
    expires_at = Column(DateTime, nullable=False)

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

def create_access_token(data: dict, expires_delta: timedelta = None) -> (str, str):
    to_encode = data.copy()
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt, jti  # Return jti along with the token

def decode_token(token: str, db: Session) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        if username is None or jti is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check if jti is in blacklist
        blacklisted = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
        if blacklisted:
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Dependency to get DB session
def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get current user
def get_current_user(token: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    if token is None:
        raise HTTPException(status_code=401, detail="Missing token")
    username = decode_token(token, db)
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
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

@app.post("/register", response_model=Token)
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

    access_token_expires = timedelta(minutes=JWT_EXPIRATION_MINUTES)
    access_token, jti = create_access_token(
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
    access_token, jti = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
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
        exp = payload.get("exp")
        if jti is None or exp is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check if the token is already blacklisted
        existing_blacklist = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
        if existing_blacklist:
            raise HTTPException(status_code=400, detail="Token already revoked")
        
        # Add the token's jti to the blacklist
        blacklist_entry = TokenBlacklist(jti=jti, expires_at=datetime.utcfromtimestamp(exp))
        db.add(blacklist_entry)
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
    asyncio.create_task(broadcast_clipboard_update(current_user.id, clipboard_entry.text))

    return {"text": clipboard_entry.text}

# #################
# WebSocket Handler
# #################

# Store active WebSocket connections per user
active_connections: Dict[int, List[WebSocket]] = {}

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
        # Check if the token is blacklisted
        blacklisted = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
        if blacklisted:
            raise JWTError
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise JWTError
        db.close()
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Accept the connection
    await websocket.accept()

    # Add to active connections
    if user.id not in active_connections:
        active_connections[user.id] = []
    active_connections[user.id].append(websocket)

    try:
        # Send initial clipboard content
        db = SessionLocal()
        clipboard = db.query(Clipboard).filter(Clipboard.owner_id == user.id).first()
        db.close()
        initial_text = clipboard.text if clipboard else ""
        await websocket.send_json({"type": "init", "text": initial_text})

        while True:
            # Keep the connection open. Optionally, handle incoming messages
            await websocket.receive_text()

    except WebSocketDisconnect:
        active_connections[user.id].remove(websocket)
        if not active_connections[user.id]:
            del active_connections[user.id]
    except Exception as e:
        active_connections[user.id].remove(websocket)
        if not active_connections[user.id]:
            del active_connections[user.id]
        # Optionally log the exception
        print(f"WebSocket error for user {user.username}: {e}")

# ####################
# Helper Functions
# ####################

async def broadcast_clipboard_update(user_id: int, text: str):
    """
    Broadcast the updated clipboard content to all connected websocket clients of a specific user.
    """
    connections = active_connections.get(user_id, [])
    to_remove = []
    for connection in connections:
        try:
            await connection.send_json({"type": "update", "text": text})
        except Exception:
            to_remove.append(connection)
    # Clean up broken connections
    for conn in to_remove:
        connections.remove(conn)
    if not connections:
        del active_connections[user_id]

