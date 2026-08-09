from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from server_app import admin
from server_app.db import Base
from server_app.models import PairedDevice, User
from server_app.pairing import PairingCode


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
                "create-account",
                "--username",
                "alice",
                "--email",
                "alice@example.test",
            ]
        )
        == 0
    )
    assert "Created account alice" in capsys.readouterr().out

    assert (
        admin.main(
            [
                "create-pairing",
                "--username",
                "alice",
                "--device-name",
                "workstation",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out.splitlines()
    code = PairingCode.parse(output[-1])

    assert admin.main(["list-pairings", "--username", "alice"]) == 0
    listing = capsys.readouterr().out
    assert code.pairing_id in listing
    assert "active" in listing
    assert "workstation" in listing
    assert code.encode() not in listing

    assert admin.main(["revoke-pairing", "--pairing-id", code.pairing_id]) == 0
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
    engine.dispose()
