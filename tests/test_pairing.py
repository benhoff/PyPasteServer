from __future__ import annotations

import pytest

from server_app.pairing import PAIRING_CODE_PREFIX, PairingCode


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
