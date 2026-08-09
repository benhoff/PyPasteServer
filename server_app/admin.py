"""Local account and per-device pairing administration."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .db import SessionLocal
from .models import PairedDevice, SyncUserState, User
from .pairing import DeviceSetupCode, create_pairing, validate_relay_url


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pypasteserver-admin",
        description="Manage local accounts and Noise pairing credentials.",
    )
    resources = parser.add_subparsers(dest="resource", required=True)

    account = resources.add_parser("account", description="Manage local accounts.")
    account_commands = account.add_subparsers(dest="action", required=True)
    create_account = account_commands.add_parser(
        "create", description="Create a passwordless local account."
    )
    create_account.add_argument("--username", required=True)
    account_commands.add_parser("list")

    device = resources.add_parser("device", description="Manage connected devices.")
    device_commands = device.add_subparsers(dest="action", required=True)
    add_device = device_commands.add_parser(
        "add", description="Create a versioned client setup code for a device."
    )
    add_device.add_argument("--username", required=True)
    add_device.add_argument("--device-name", required=True)
    add_device.add_argument("--relay-url", required=True)
    list_devices = device_commands.add_parser("list")
    list_devices.add_argument("--username", required=True)
    revoke_device = device_commands.add_parser("revoke")
    revoke_device.add_argument("--pairing-id", required=True)
    return parser


def _user(session, username: str) -> User:
    user = session.scalar(select(User).where(User.username == username))
    if user is None:
        raise ValueError(f"account does not exist: {username}")
    return user


def _create_account(args: argparse.Namespace) -> None:
    username = args.username.strip()
    if not username or len(username) > 150:
        raise ValueError("username must contain 1 to 150 characters")
    with SessionLocal() as session:
        user = User(username=username)
        session.add(user)
        try:
            session.flush()
            session.add(SyncUserState(user_id=user.id, next_server_sequence=1))
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise ValueError("username already exists") from exc
    print(f"Created account {username}")


def _list_accounts(args: argparse.Namespace) -> None:
    del args
    with SessionLocal() as session:
        users = session.scalars(select(User).order_by(User.username)).all()
        devices = session.scalars(select(PairedDevice)).all()
        if not users:
            print("No accounts")
            return
        totals: dict[int, tuple[int, int]] = {}
        for device in devices:
            active, total = totals.get(device.user_id, (0, 0))
            totals[device.user_id] = (
                active + int(device.revoked_at is None),
                total + 1,
            )
        print("USERNAME\tACTIVE-DEVICES\tTOTAL-DEVICES")
        for user in users:
            active, total = totals.get(user.id, (0, 0))
            print(f"{user.username}\t{active}\t{total}")


def _add_device(args: argparse.Namespace) -> None:
    relay_url = validate_relay_url(args.relay_url)
    with SessionLocal() as session:
        user = _user(session, args.username)
        try:
            device, pairing = create_pairing(
                session, user=user, device_name=args.device_name
            )
        except IntegrityError as exc:
            session.rollback()
            raise ValueError("could not create pairing credential") from exc
    setup = DeviceSetupCode(
        relay_url=relay_url,
        username=user.username,
        device_name=device.device_name,
        pairing=pairing,
    )
    print(f"Created device {device.device_name} for account {user.username}")
    print(f"Pairing ID: {device.pairing_id}")
    print(f"Device: {device.device_name}")
    print("Client setup code (contains the device credential; shown once):")
    print(setup.encode())


def _list_devices(args: argparse.Namespace) -> None:
    with SessionLocal() as session:
        user = _user(session, args.username)
        devices = session.scalars(
            select(PairedDevice)
            .where(PairedDevice.user_id == user.id)
            .order_by(PairedDevice.created_at, PairedDevice.id)
        ).all()
        if not devices:
            print("No devices")
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


def _revoke_device(args: argparse.Namespace) -> None:
    with SessionLocal() as session:
        device = session.scalar(
            select(PairedDevice).where(PairedDevice.pairing_id == args.pairing_id)
        )
        if device is None:
            raise ValueError("device does not exist")
        if device.revoked_at is None:
            device.revoked_at = datetime.now(UTC)
            session.commit()
    print(f"Revoked device {args.pairing_id}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        {
            ("account", "create"): _create_account,
            ("account", "list"): _list_accounts,
            ("device", "add"): _add_device,
            ("device", "list"): _list_devices,
            ("device", "revoke"): _revoke_device,
        }[(args.resource, args.action)](args)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
