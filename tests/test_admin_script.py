from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _environment(tmp_path: Path) -> tuple[dict[str, str], Path]:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -eu
if [[ ${1:-} == compose && ${2:-} == version ]]; then
    exit 0
fi
if [[ ${1:-} == info ]]; then
    exit 0
fi
if [[ ${1:-} == compose && ${2:-} == ps && ${3:-} == -q ]]; then
    printf 'test-container\\n'
    exit 0
fi
if [[ ${1:-} == inspect ]]; then
    printf 'true\\n'
    exit 0
fi
if [[ ${1:-} == compose && ${2:-} == exec ]]; then
    printf '%s\\n' "$*" >>"$FAKE_DOCKER_LOG"
    if [[ "$*" == *"server_app.admin account list"* && -n ${FAKE_ACCOUNTS_OUTPUT:-} ]]; then
        printf '%b' "$FAKE_ACCOUNTS_OUTPUT"
        exit 0
    fi
    printf 'admin output\\n'
    exit 0
fi
printf 'unexpected docker command: %s\\n' "$*" >&2
exit 1
"""
    )
    docker.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["FAKE_DOCKER_LOG"] = str(log)
    return environment, log


def _script(tmp_path: Path) -> Path:
    script = tmp_path / "admin.sh"
    shutil.copy2(PROJECT_ROOT / "admin.sh", script)
    script.chmod(0o755)
    return script


def test_admin_wrapper_routes_human_commands_to_container(tmp_path) -> None:
    script = _script(tmp_path)
    environment, log = _environment(tmp_path)

    accounts = subprocess.run(
        [str(script), "account", "list"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert accounts.returncode == 0, accounts.stderr
    assert "admin output" in accounts.stdout

    created = subprocess.run(
        [str(script), "account", "create", "alice"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert created.returncode == 0, created.stderr

    calls = log.read_text().splitlines()
    assert calls[0].endswith("server_app.admin account list")
    assert calls[1].endswith("server_app.admin account create --username alice")


def test_device_add_emits_one_guided_client_handoff(tmp_path) -> None:
    script = _script(tmp_path)
    (tmp_path / ".env").write_text(
        "PYP_SERVER_BIND_ADDRESS=0.0.0.0\n"
        "PYP_SERVER_PORT=8001\n"
        "PYP_SERVER_PUBLIC_RELAY_URL=wss://clipboard.example.test/sync/v1\n"
    )
    environment, log = _environment(tmp_path)

    result = subprocess.run(
        [str(script), "device", "add", "alice", "office-laptop"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert "kclip sync setup" in result.stdout
    assert "kclip auth pair" not in result.stdout
    assert log.read_text().strip().endswith(
        "server_app.admin device add --username alice --device-name office-laptop "
        "--relay-url wss://clipboard.example.test/sync/v1"
    )


def test_interactive_device_workflow_selects_account_by_number(tmp_path) -> None:
    script = _script(tmp_path)
    (tmp_path / ".env").write_text(
        "PYP_SERVER_BIND_ADDRESS=127.0.0.1\n"
        "PYP_SERVER_PORT=8001\n"
        "PYP_SERVER_PUBLIC_RELAY_URL=ws://127.0.0.1:8001/sync/v1\n"
    )
    environment, log = _environment(tmp_path)
    environment["FAKE_ACCOUNTS_OUTPUT"] = (
        "USERNAME\\tACTIVE-DEVICES\\tTOTAL-DEVICES\\n"
        "alice\\t1\\t1\\n"
    )

    result = subprocess.run(
        [str(script)],
        input="1\n1\noffice-laptop\n6\n",
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert "Connect a new device" in result.stdout
    assert "alice (1 active device(s))" in result.stdout
    assert "Creating a credential for office-laptop on account alice" in result.stdout
    assert "kclip sync setup" in result.stdout
    assert log.read_text().splitlines()[-1].endswith(
        "server_app.admin device add --username alice --device-name office-laptop "
        "--relay-url ws://127.0.0.1:8001/sync/v1"
    )


def test_admin_wrapper_help_does_not_require_running_server(tmp_path) -> None:
    result = subprocess.run(
        [str(_script(tmp_path)), "--help"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0
    assert "Run without a command for an interactive menu" in result.stdout
    assert "device add" in result.stdout
    assert "pair create" not in result.stdout
