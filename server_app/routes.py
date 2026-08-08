"""Account authentication routes used by kclip clients."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .config import JWT_ALGORITHM, JWT_SECRET
from .dependencies import get_current_user, get_db
from .models import Token, User
from .schemas import TokenSchema, UserCreate
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
__all__ = ["router"]
