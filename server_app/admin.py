"""Local account and per-device pairing administration."""

from __future__ import annotations

import argparse
import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .db import SessionLocal
from .models import PairedDevice, SyncUserState, User
from .pairing import create_pairing
from .security import get_password_hash


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pypasteserver-admin",
        description="Manage local accounts and Noise pairing credentials.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    account = commands.add_parser(
        "create-account", description="Create a passwordless local account."
    )
    account.add_argument("--username", required=True)
    account.add_argument("--email", required=True)

    create = commands.add_parser(
        "create-pairing", description="Issue one pairing code for a device."
    )
    create.add_argument("--username", required=True)
    create.add_argument("--device-name", required=True)

    listing = commands.add_parser("list-pairings")
    listing.add_argument("--username", required=True)

    revoke = commands.add_parser("revoke-pairing")
    revoke.add_argument("--pairing-id", required=True)
    return parser


def _user(session, username: str) -> User:
    user = session.scalar(select(User).where(User.username == username))
    if user is None:
        raise ValueError(f"account does not exist: {username}")
    return user


def _create_account(args: argparse.Namespace) -> None:
    username = args.username.strip()
    email = args.email.strip()
    if not username or len(username) > 150:
        raise ValueError("username must contain 1 to 150 characters")
    if not email or len(email) > 255:
        raise ValueError("email must contain 1 to 255 characters")
    # The random value is discarded. This account can only authenticate with a
    # locally issued pairing credential unless an administrator resets it using
    # some future password-management flow.
    password_hash = get_password_hash(secrets.token_urlsafe(48))
    with SessionLocal() as session:
        user = User(
            username=username,
            email=email,
            hashed_password=password_hash,
            email_authenticated=True,
        )
        session.add(user)
        try:
            session.flush()
            session.add(SyncUserState(user_id=user.id, next_server_sequence=1))
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise ValueError("username or email already exists") from exc
    print(f"Created account {username}")


def _create_pairing(args: argparse.Namespace) -> None:
    with SessionLocal() as session:
        user = _user(session, args.username)
        try:
            device, pairing = create_pairing(
                session, user=user, device_name=args.device_name
            )
        except IntegrityError as exc:
            session.rollback()
            raise ValueError("could not create pairing credential") from exc
    print(f"Pairing ID: {device.pairing_id}")
    print(f"Device: {device.device_name}")
    print("Pairing code (shown once):")
    print(pairing.encode())


def _list_pairings(args: argparse.Namespace) -> None:
    with SessionLocal() as session:
        user = _user(session, args.username)
        devices = session.scalars(
            select(PairedDevice)
            .where(PairedDevice.user_id == user.id)
            .order_by(PairedDevice.created_at, PairedDevice.id)
        ).all()
        if not devices:
            print("No pairings")
            return
        for device in devices:
            state = "revoked" if device.revoked_at is not None else "active"
            last_used = (
                device.last_used_at.isoformat() if device.last_used_at else "never"
            )
            print(
                f"{device.pairing_id}\t{state}\t{device.device_name}\t"
                f"last-used={last_used}"
            )


def _revoke_pairing(args: argparse.Namespace) -> None:
    with SessionLocal() as session:
        device = session.scalar(
            select(PairedDevice).where(PairedDevice.pairing_id == args.pairing_id)
        )
        if device is None:
            raise ValueError("pairing does not exist")
        if device.revoked_at is None:
            device.revoked_at = datetime.now(UTC)
            session.commit()
    print(f"Revoked pairing {args.pairing_id}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        {
            "create-account": _create_account,
            "create-pairing": _create_pairing,
            "list-pairings": _list_pairings,
            "revoke-pairing": _revoke_pairing,
        }[args.command](args)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
