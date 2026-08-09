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
        [str(script), "accounts"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert accounts.returncode == 0, accounts.stderr
    assert "admin output" in accounts.stdout

    created = subprocess.run(
        [str(script), "account", "create", "alice", "alice@example.test"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert created.returncode == 0, created.stderr

    calls = log.read_text().splitlines()
    assert calls[0].endswith("server_app.admin list-accounts")
    assert calls[1].endswith(
        "server_app.admin create-account --username alice --email alice@example.test"
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
