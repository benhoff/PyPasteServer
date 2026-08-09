from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from server_app import admin
from server_app.db import Base
from server_app.models import PairedDevice, User
from server_app.pairing import DeviceSetupCode


def test_local_admin_creates_account_pairs_and_revokes(
    tmp_path, monkeypatch, capsys
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'admin.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(admin, "SessionLocal", factory)

    assert (
        admin.main(
            [
                "account",
                "create",
                "--username",
                "alice",
            ]
        )
        == 0
    )
    assert "Created account alice" in capsys.readouterr().out

    assert admin.main(["account", "list"]) == 0
    accounts = capsys.readouterr().out
    assert "USERNAME\tACTIVE-DEVICES\tTOTAL-DEVICES" in accounts
    assert "alice\t0\t0" in accounts

    with pytest.raises(SystemExit, match="relay URL"):
        admin.main(
            [
                "device",
                "add",
                "--username",
                "alice",
                "--device-name",
                "invalid-device",
                "--relay-url",
                "https://clipboard.example.test/sync/v1",
            ]
        )
    with factory() as session:
        assert session.scalars(select(PairedDevice)).all() == []

    assert (
        admin.main(
            [
                "device",
                "add",
                "--username",
                "alice",
                "--device-name",
                "workstation",
                "--relay-url",
                "wss://clipboard.example.test/sync/v1",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out.splitlines()
    setup_code = output[-1]
    setup = DeviceSetupCode.parse(setup_code)
    code = setup.pairing
    assert setup.relay_url == "wss://clipboard.example.test/sync/v1"
    assert setup.username == "alice"
    assert setup.device_name == "workstation"

    assert admin.main(["device", "list", "--username", "alice"]) == 0
    listing = capsys.readouterr().out
    assert code.pairing_id in listing
    assert "active" in listing
    assert "workstation" in listing
    assert setup_code not in listing

    assert admin.main(["account", "list"]) == 0
    assert "alice\t1\t1" in capsys.readouterr().out

    assert admin.main(["device", "revoke", "--pairing-id", code.pairing_id]) == 0
    capsys.readouterr()
    with factory() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        device = session.scalar(
            select(PairedDevice).where(PairedDevice.pairing_id == code.pairing_id)
        )
        assert user is not None
        assert device.user_id == user.id
        assert device.revoked_at is not None
        assert device.psk == code.psk

    assert admin.main(["account", "list"]) == 0
    assert "alice\t0\t1" in capsys.readouterr().out
    engine.dispose()
