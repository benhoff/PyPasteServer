from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from server_app.sync_protocol import (
    HelloMessage,
    PushMessage,
    SyncProtocolError,
    decode_base64url,
    decode_json_frame,
    encode_base64url,
    event_message,
    history_truncated_message,
    parse_client_message,
    push_ack_message,
    ready_message,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _wire_fixture() -> dict:
    return json.loads((FIXTURES / "sync-wire-v1.json").read_text())


def test_crypto_fixture_matches_companion_repository_when_available() -> None:
    fixture_path = FIXTURES / "sync-v1.json"
    assert sha256(fixture_path.read_bytes()).hexdigest() == (
        "49f2c402c63db4abe0f8a4d195f3a4cdeb759ad9d63e46596e119947b906ead3"
    )
    fixture = json.loads(fixture_path.read_text())
    assert bytes.fromhex(fixture["key_hex"]) == bytes([7]) * 32
    assert fixture["aad_utf8_and_hex_suffix"].replace("\\u0000", "\x00").encode() == (
        b"kclip-sync-v1\x00" + fixture["message_id"].encode()
    )
    assert len(decode_base64url(fixture["nonce"], "nonce")) == 24
    assert len(decode_base64url(fixture["tag"], "tag")) == 16
    assert len(decode_base64url(fixture["ciphertext"], "ciphertext")) == len(
        decode_base64url(fixture["canonical_cbor_base64url"], "canonical_cbor")
    )

    companion = FIXTURES.parent.parent / "dev_clipboard" / "fixtures" / "sync-v1.json"
    if companion.exists():
        assert fixture_path.read_bytes() == companion.read_bytes()


def test_wire_fixture_matches_companion_repository_when_available() -> None:
    local = FIXTURES / "sync-wire-v1.json"
    assert sha256(local.read_bytes()).hexdigest() == (
        "e4c6646bde7f58cb30439817af76359dd9cdaf911c903c16e45d4044d1061d20"
    )
    companion = (
        FIXTURES.parent.parent / "dev_clipboard" / "fixtures" / "sync-wire-v1.json"
    )
    if companion.exists():
        assert local.read_bytes() == companion.read_bytes()


def test_shared_wire_fixture_matches_protocol_helpers() -> None:
    fixture = _wire_fixture()

    hello = parse_client_message(fixture["hello"], max_event_bytes=1024)
    assert hello == HelloMessage(device_id="device-contract", resume_after=42)
    assert (
        ready_message(
            connection_id="connection-contract",
            latest_sequence=57,
            earliest_sequence=1,
            resume_after=42,
        )
        == fixture["ready"]
    )
    assert (
        history_truncated_message(earliest_sequence=50, latest_sequence=57)
        == fixture["history_truncated"]
    )

    push = parse_client_message(fixture["push"], max_event_bytes=1024)
    assert isinstance(push, PushMessage)
    assert push.nonce == bytes([9]) * 24
    assert push.ciphertext == b"\x00"
    assert push.tag == bytes(16)
    assert (
        push_ack_message(
            message_id=push.message_id, server_sequence=58, duplicate=False
        )
        == fixture["push_ack"]
    )

    assert (
        event_message(
            server_sequence=58,
            message_id=push.message_id,
            sender_device_id="device-contract",
            algorithm=push.algorithm,
            nonce=push.nonce,
            ciphertext=push.ciphertext,
            tag=push.tag,
            accepted_at=datetime.fromtimestamp(1770000000, tz=UTC),
        )
        == fixture["event"]
    )


def test_ready_reports_a_truncated_replay_window() -> None:
    assert ready_message(
        connection_id="connection-contract",
        latest_sequence=57,
        earliest_sequence=50,
        resume_after=42,
    ) == {
        "type": "ready",
        "protocol_version": 1,
        "connection_id": "connection-contract",
        "latest_sequence": 57,
        "earliest_sequence": 50,
        "replay_from": 50,
        "history_truncated": True,
    }
    assert history_truncated_message(earliest_sequence=50, latest_sequence=57) == {
        "type": "history_truncated",
        "protocol_version": 1,
        "earliest_sequence": 50,
        "latest_sequence": 57,
        "replay_from": 50,
    }


def test_ready_reports_an_empty_retained_window() -> None:
    assert ready_message(
        connection_id="connection-contract",
        latest_sequence=57,
        earliest_sequence=58,
        resume_after=42,
    ) == {
        "type": "ready",
        "protocol_version": 1,
        "connection_id": "connection-contract",
        "latest_sequence": 57,
        "earliest_sequence": 58,
        "replay_from": 58,
        "history_truncated": True,
    }


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (
            {
                "type": "hello",
                "protocol_version": 2,
                "device_id": "d",
                "resume_after": 0,
            },
            "protocol_mismatch",
        ),
        (
            {
                "type": "hello",
                "protocol_version": 1,
                "device_id": "",
                "resume_after": 0,
            },
            "invalid_message",
        ),
        (
            {
                "type": "checkpoint",
                "protocol_version": 1,
                "server_sequence": 0,
            },
            "invalid_message",
        ),
        ({"type": "unknown"}, "invalid_message"),
    ],
)
def test_rejects_invalid_outer_messages(value: dict, code: str) -> None:
    with pytest.raises(SyncProtocolError) as error:
        parse_client_message(value, max_event_bytes=1024)
    assert error.value.code == code


@pytest.mark.parametrize("value", ["AA==", "+w", "/w", "A", "not base64!"])
def test_base64url_must_be_unpadded_and_canonical(value: str) -> None:
    with pytest.raises(SyncProtocolError, match="base64url"):
        decode_base64url(value, "ciphertext")


def test_base64url_round_trip() -> None:
    payload = bytes(range(255))
    assert decode_base64url(encode_base64url(payload), "payload") == payload


def test_push_enforces_uuid_lengths_algorithm_and_size() -> None:
    push = _wire_fixture()["push"]

    variants = [
        ({**push, "message_id": push["message_id"].upper()}, "invalid_message", None),
        (
            {**push, "algorithm": "chacha20-poly1305"},
            "invalid_message",
            push["message_id"],
        ),
        ({**push, "nonce": "AA"}, "invalid_message", push["message_id"]),
        ({**push, "tag": "AA"}, "invalid_message", push["message_id"]),
    ]
    for value, code, related_message_id in variants:
        with pytest.raises(SyncProtocolError) as error:
            parse_client_message(value, max_event_bytes=1024)
        assert error.value.code == code
        assert error.value.message_id == related_message_id

    with pytest.raises(SyncProtocolError) as error:
        parse_client_message(push, max_event_bytes=0)
    assert error.value.code == "event_too_large"


def test_json_frames_are_bounded_objects_with_finite_numbers() -> None:
    assert (
        decode_json_frame(
            '{"type":"hello","protocol_version":1,"device_id":"d","resume_after":0}',
            max_frame_bytes=100,
        )["type"]
        == "hello"
    )
    for frame in ("[]", "not-json", '{"value": NaN}'):
        with pytest.raises(SyncProtocolError) as error:
            decode_json_frame(frame, max_frame_bytes=100)
        assert error.value.code == "invalid_message"

    with pytest.raises(SyncProtocolError) as error:
        decode_json_frame("{}", max_frame_bytes=1)
    assert error.value.code == "event_too_large"
    assert error.value.close_code == 1009
