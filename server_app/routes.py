"""HTTP routes for the clipboard API."""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .clipboard import initialize_user_clipboard
from .config import JWT_ALGORITHM, JWT_SECRET
from .dependencies import get_current_user, get_db
from .manager import manager
from .models import Clipboard, Token, User
from .schemas import ClipboardCreate, ClipboardResponse, TokenSchema, UserCreate
from .security import create_access_token, get_password_hash, verify_password

router = APIRouter()


@router.post("/register", response_model=TokenSchema)
def register(user: UserCreate, db: Session = Depends(get_db)) -> TokenSchema:
    existing_user = (
        db.query(User)
        .filter((User.username == user.username) | (User.email == user.email))
        .first()
    )
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    hashed_pw = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pw,
        email_authenticated=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    initialize_user_clipboard(db, new_user)

    access_token = create_access_token({"sub": new_user.username, "user_id": new_user.id}, db=db)
    return TokenSchema(access_token=access_token, token_type="bearer")


@router.post("/login", response_model=TokenSchema)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenSchema:
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token = create_access_token({"sub": user.username, "user_id": user.id}, db=db)
    return TokenSchema(access_token=access_token, token_type="bearer")


@router.post("/logout", status_code=200)
def logout(
    current_user: User = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Invalid authorization header")

    token = authorization.split(" ")[1]

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        token_entry = (
            db.query(Token)
            .filter(Token.jti == jti, Token.user_id == current_user.id)
            .first()
        )
        if not token_entry:
            raise HTTPException(status_code=400, detail="Token already revoked or invalid")

        db.delete(token_entry)
        db.commit()
        return {"detail": "Successfully logged out"}
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@router.get("/clipboard", response_model=ClipboardResponse)
def get_clipboard(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ClipboardResponse:
    clipboard = db.query(Clipboard).filter(Clipboard.owner_id == current_user.id).first()
    if not clipboard:
        raise HTTPException(status_code=404, detail="Clipboard not found")
    return ClipboardResponse(
        ciphertext=clipboard.ciphertext,
        nonce=clipboard.nonce,
        tag=clipboard.tag,
    )


@router.post("/clipboard", response_model=ClipboardResponse)
def update_clipboard(
    clipboard: ClipboardCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ClipboardResponse:
    clipboard_entry = db.query(Clipboard).filter(Clipboard.owner_id == current_user.id).first()
    if not clipboard_entry:
        clipboard_entry = Clipboard(
            ciphertext=clipboard.ciphertext,
            nonce=clipboard.nonce,
            tag=clipboard.tag,
            owner_id=current_user.id,
        )
        db.add(clipboard_entry)
    else:
        clipboard_entry.ciphertext = clipboard.ciphertext
        clipboard_entry.nonce = clipboard.nonce
        clipboard_entry.tag = clipboard.tag
    db.commit()
    db.refresh(clipboard_entry)

    message = {
        "type": "update",
        "ciphertext": clipboard_entry.ciphertext,
        "nonce": clipboard_entry.nonce,
        "tag": clipboard_entry.tag,
        "user_id": current_user.id,
    }
    asyncio.create_task(manager.publish_update(message))

    return ClipboardResponse(
        ciphertext=clipboard_entry.ciphertext,
        nonce=clipboard_entry.nonce,
        tag=clipboard_entry.tag,
    )


__all__ = ["router"]
