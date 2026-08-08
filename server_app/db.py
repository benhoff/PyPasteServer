"""Database configuration and session management."""

from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import DATABASE_URL


def _engine_options(database_url: str) -> dict:
    options: dict = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False, "timeout": 30}
    return options


engine = create_engine(DATABASE_URL, **_engine_options(DATABASE_URL))

if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, expire_on_commit=False
)
Base = declarative_base()

__all__ = ["engine", "SessionLocal", "Base"]
