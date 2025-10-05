# PyPasteServer

This repository contains two cooperating components:

- **FastAPI server** (package `pypasteserver`, code under `server_app/`)
- **Local clipboard daemon** (package `pypasteserver-daemon`, code under `daemon/`)

Use the server if you want to host the synced clipboard backend, and install the daemon on desktops that publish or subscribe to that backend.

---

## Server (FastAPI backend)

### Quick start with Docker

1. Build and start the stack (server + Redis):

   ```bash
   docker compose up --build app
   ```

2. The API is available on [http://localhost:8001](http://localhost:8001). The SQLite database is bind-mounted at `./clipboard.db`.

### Local development install

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install the server package (installs FastAPI, SQLAlchemy, redis client, etc.):

   ```bash
   pip install -e .
   ```

3. Run the API with Uvicorn:

   ```bash
   uvicorn server_app.main:app --reload --port 8001
   ```

Environment variables recognised by the server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./clipboard.db` | SQLAlchemy database URL |
| `JWT_SECRET` | `supersecretkey` | Secret used to sign JWT access tokens |
| `JWT_ALGORITHM` | `HS256` | Signing algorithm |
| `REDIS_URL` | `redis://redis:6379` | Redis connection string used for websocket fanout |

---

## Daemon (desktop clipboard client)

The daemon uses GLib/DBus bindings and optional crypto/websocket support for encrypted sync.

### System prerequisites

Install the platform libraries first (Ubuntu/Debian example):

```bash
sudo apt install python3-gi gir1.2-glib-2.0 dbus-python
```

### Installation

Create a venv that can see the system GI modules (the `--system-site-packages` flag is the easiest option):

```bash
python3 -m venv --system-site-packages venv
source venv/bin/activate
pip install -e ./daemon
```

Optional extras:

- `pycryptodome` + `websocket-client` provide encrypted websocket sync (already included in the package dependencies)
- KDE Klipper integration requires DBus support (provided by the system packages above)

### Running the daemon

Activate the venv and launch:

```bash
source venv/bin/activate
python -m daemon
```

Configure `~/.config/clipboard_app/config.ini` with the server URL and token locations. The CLI (`cli.py`) can generate the config, register users, and manage access tokens.

### Loading the kclip kernel module

The daemon reads clipboard updates from `/dev/kclip`, which is provided by the out-of-tree `kclip` kernel module (see the sibling `kclip/` project). To load it automatically at boot:

1. Copy the provided modules-load configuration into place:

   ```bash
   sudo install -m 0644 conf/kclip.conf /etc/modules-load.d/pypasteserver-kclip.conf
   sudo systemctl restart systemd-modules-load.service
   ```

2. Verify the module is loaded and the device node exists:

   ```bash
   lsmod | grep kclip
   ls -l /dev/kclip
   ```

   If `/dev/kclip` is missing, run `sudo modprobe kclip` (after installing `kclip.ko` under `/usr/lib/modules/$(uname -r)/extra/` and running `sudo depmod`).

### Running the daemon under systemd

Install the unit as a system service that runs under the desktop user (update `User=`, `Group=`, `WorkingDirectory`, and `PYTHONPATH` first):

```bash
sudo install -m 0644 conf/pypasteserver-daemon.service /etc/systemd/system/pypasteserver-daemon.service
sudo systemctl daemon-reload
sudo systemctl enable --now pypasteserver-daemon.service
```

Check logs with `journalctl -u pypasteserver-daemon.service -f`. If you prefer using a per-user systemd instance instead, drop the `User=`/`Group=` lines and copy the unit into `~/.config/systemd/user/` before enabling it with `systemctl --user`.

---

## CLI utility

`cli.py` exposes commands for registration, login, key management, syncing, and status. Run `python cli.py --help` for the current command list.

---

## Repository layout

```
server_app/          FastAPI backend modules
daemon/              Desktop clipboard daemon package
cli/                 CLI helpers used by cli.py
cli.py               Entry point for the command-line interface
docker-compose.yml   Container stack (FastAPI + Redis)
Dockerfile           Server image definition
tests/               Pytest suite
```
