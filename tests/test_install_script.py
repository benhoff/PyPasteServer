from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run_installer(installation_root: Path, *arguments: str) -> subprocess.CompletedProcess:
    fake_bin = installation_root / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    fake_docker = fake_bin / "docker"
    fake_docker.write_text("#!/usr/bin/env bash\nexit 0\n")
    fake_docker.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["HOME"] = str(installation_root / "home")
    environment.pop("XDG_DATA_HOME", None)

    return subprocess.run(
        [str(installation_root / "install.sh"), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _settings(environment_file: Path) -> dict[str, str]:
    return {
        key: value
        for line in environment_file.read_text().splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }


def test_installer_generates_private_config_and_preserves_secret(tmp_path) -> None:
    installer = tmp_path / "install.sh"
    shutil.copy2(PROJECT_ROOT / "install.sh", installer)
    installer.chmod(0o755)
    data_directory = tmp_path / "server-data"

    first = _run_installer(
        tmp_path,
        "--listen",
        "127.0.0.1",
        "--port",
        "8123",
        "--data-dir",
        str(data_directory),
        "--no-build",
        "--no-start",
    )
    assert first.returncode == 0, first.stderr

    environment_file = tmp_path / ".env"
    initial = _settings(environment_file)
    assert initial["PYP_SERVER_BIND_ADDRESS"] == "127.0.0.1"
    assert initial["PYP_SERVER_PORT"] == "8123"
    assert initial["PYP_SERVER_PUBLIC_RELAY_URL"] == "ws://127.0.0.1:8123/sync/v1"
    assert initial["PYP_SERVER_DATA_DIRECTORY"] == str(data_directory)
    assert len(initial["JWT_SECRET"]) == 64
    assert initial["SYNC_ALLOW_LEGACY_BEARER"] == "0"
    assert stat.S_IMODE(environment_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(data_directory.stat().st_mode) == 0o700

    reconfigured = _run_installer(
        tmp_path,
        "--reconfigure",
        "--port",
        "9000",
        "--no-build",
        "--no-start",
    )
    assert reconfigured.returncode == 0, reconfigured.stderr

    updated = _settings(environment_file)
    assert updated["PYP_SERVER_PORT"] == "9000"
    assert updated["PYP_SERVER_PUBLIC_RELAY_URL"] == "ws://127.0.0.1:9000/sync/v1"
    assert updated["JWT_SECRET"] == initial["JWT_SECRET"]


def test_installer_records_explicit_client_facing_relay(tmp_path) -> None:
    installer = tmp_path / "install.sh"
    shutil.copy2(PROJECT_ROOT / "install.sh", installer)
    installer.chmod(0o755)

    result = _run_installer(
        tmp_path,
        "--listen",
        "0.0.0.0",
        "--relay-url",
        "wss://clipboard.example.test/sync/v1",
        "--no-build",
        "--no-start",
    )

    assert result.returncode == 0, result.stderr
    settings = _settings(tmp_path / ".env")
    assert settings["PYP_SERVER_PUBLIC_RELAY_URL"] == (
        "wss://clipboard.example.test/sync/v1"
    )
    assert "Relay: wss://clipboard.example.test/sync/v1" in result.stdout
    assert "./admin.sh device add" in result.stdout


def test_installer_requires_reconfigure_for_existing_config_changes(tmp_path) -> None:
    installer = tmp_path / "install.sh"
    shutil.copy2(PROJECT_ROOT / "install.sh", installer)
    installer.chmod(0o755)

    initial = _run_installer(tmp_path, "--no-build", "--no-start")
    assert initial.returncode == 0, initial.stderr

    changed = _run_installer(
        tmp_path,
        "--port",
        "9000",
        "--no-build",
        "--no-start",
    )
    assert changed.returncode != 0
    assert "use --reconfigure" in changed.stderr


def test_installer_requires_reconfigure_for_partial_environment(tmp_path) -> None:
    installer = tmp_path / "install.sh"
    shutil.copy2(PROJECT_ROOT / "install.sh", installer)
    installer.chmod(0o755)
    (tmp_path / ".env").write_text("JWT_SECRET=" + "a" * 64 + "\n")

    result = _run_installer(tmp_path, "--no-build", "--no-start")

    assert result.returncode != 0
    assert "incomplete; rerun with --reconfigure" in result.stderr
