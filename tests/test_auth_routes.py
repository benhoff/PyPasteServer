from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from server_app.db import Base
from server_app.dependencies import get_current_user
from server_app.models import Token
from server_app.routes import login, logout, register
from server_app.schemas import UserCreate


def test_kclip_account_lifecycle_uses_bearer_authorization() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    try:
        with session_factory() as session:
            credentials = UserCreate(
                username="kclip-user",
                email="kclip@example.com",
                password="correct horse battery staple",
            )
            registered = register(credentials, db=session)
            assert registered.token_type == "bearer"

            form = SimpleNamespace(
                username=credentials.username,
                password=credentials.password,
            )
            logged_in = login(form_data=form, db=session)
            authorization = f"Bearer {logged_in.access_token}"
            current_user = get_current_user(authorization=authorization, db=session)

            result = logout(
                current_user=current_user,
                authorization=authorization,
                db=session,
            )
            assert result == {"detail": "Successfully logged out"}
            assert session.query(Token).count() == 1

            with pytest.raises(HTTPException) as exc_info:
                get_current_user(authorization=authorization, db=session)
            assert exc_info.value.status_code == 401
    finally:
        engine.dispose()


def test_registration_rejects_passwords_beyond_bcrypt_limit() -> None:
    with pytest.raises(ValidationError):
        UserCreate(
            username="too-long",
            email="long@example.com",
            password="x" * 73,
        )
