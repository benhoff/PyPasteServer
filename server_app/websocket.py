"""WebSocket endpoint for realtime clipboard sync."""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status, Query
from jose import JWTError, jwt

from .config import JWT_ALGORITHM, JWT_SECRET
from .db import SessionLocal
from .manager import manager
from .models import Clipboard, Token, User

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
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

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise JWTError

        token_entry = db.query(Token).filter(Token.jti == jti, Token.user_id == user.id).first()
        if not token_entry:
            raise JWTError
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    finally:
        db.close()

    await manager.connect(user.id, websocket)

    try:
        db = SessionLocal()
        clipboard = db.query(Clipboard).filter(Clipboard.owner_id == user.id).first()
        if clipboard:
            init_payload = {
                "type": "init",
                "ciphertext": clipboard.ciphertext,
                "nonce": clipboard.nonce,
                "tag": clipboard.tag,
                "connection_count": await manager.get_connection_count(user.id),
            }
        else:
            init_payload = {
                "type": "init",
                "ciphertext": "",
                "nonce": "",
                "tag": "",
                "connection_count": await manager.get_connection_count(user.id),
            }
        await websocket.send_json(init_payload)
    finally:
        db.close()

    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") != "update":
                continue
            ciphertext = data.get("ciphertext")
            nonce = data.get("nonce")
            tag = data.get("tag")
            if not all([ciphertext, nonce, tag]):
                continue
            message = {
                "type": "update",
                "ciphertext": ciphertext,
                "nonce": nonce,
                "tag": tag,
                "user_id": user.id,
            }
            asyncio.create_task(manager.publish_update(message))
    except WebSocketDisconnect:
        await manager.disconnect(user.id, websocket)
    except Exception as exc:  # pragma: no cover - websocket diagnostics
        await manager.disconnect(user.id, websocket)
        print(f"WebSocket error for user {user.username}: {exc}")
