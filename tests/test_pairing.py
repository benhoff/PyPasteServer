from __future__ import annotations

import pytest

from server_app.pairing import (
    PAIRING_CODE_PREFIX,
    SETUP_CODE_PREFIX,
    DeviceSetupCode,
    PairingCode,
)


def test_pairing_code_round_trip() -> None:
    code = PairingCode(
        pairing_id="eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5",
        psk=bytes(range(32)),
    )
    encoded = code.encode()
    assert encoded.startswith(f"{PAIRING_CODE_PREFIX}:")
    assert "=" not in encoded
    assert PairingCode.parse(encoded) == code


@pytest.mark.parametrize(
    "value",
    [
        "",
        "wrong:eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5:AAAA",
        "kclip-pair-v1:not-a-uuid:AAAA",
        "kclip-pair-v1:eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5:AAAA",
        "kclip-pair-v1:eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5:not+url",
    ],
)
def test_pairing_code_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError, match="invalid pairing code"):
        PairingCode.parse(value)


def test_device_setup_code_round_trip() -> None:
    pairing = PairingCode(
        pairing_id="eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5",
        psk=bytes(range(32)),
    )
    setup = DeviceSetupCode(
        relay_url="wss://clipboard.example.test/sync/v1",
        username="alice",
        device_name="office laptop",
        pairing=pairing,
    )

    encoded = setup.encode()

    assert encoded.startswith(f"{SETUP_CODE_PREFIX}:")
    assert "clipboard.example.test" not in encoded
    assert DeviceSetupCode.parse(encoded) == setup


@pytest.mark.parametrize(
    "value",
    [
        "",
        "wrong:AAAA",
        "kclip-setup-v1:not+base64",
        "kclip-setup-v1:e30",
    ],
)
def test_device_setup_code_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError, match="invalid device setup code"):
        DeviceSetupCode.parse(value)


@pytest.mark.parametrize(
    "relay_url",
    [
        "https://clipboard.example.test/sync/v1",
        "ws:///sync/v1",
        "ws://clipboard.example.test/other",
        "ws://user:password@clipboard.example.test/sync/v1",
        "ws://clipboard.example.test/sync/v1?token=secret",
    ],
)
def test_device_setup_code_rejects_invalid_relay_url(relay_url: str) -> None:
    setup = DeviceSetupCode(
        relay_url=relay_url,
        username="alice",
        device_name="laptop",
        pairing=PairingCode(
            pairing_id="eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5",
            psk=bytes(range(32)),
        ),
    )
    with pytest.raises(ValueError, match="relay URL"):
        setup.encode()
