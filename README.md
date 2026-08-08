# PyPasteServer

This repository contains a FastAPI relay and migration-era Python clients:

- **FastAPI server** (package `pypasteserver`, code under `server_app/`) with
  the durable, end-to-end-encrypted kclip sync-v1 relay
- **Legacy local clipboard daemon** (package `pypasteserver-daemon`, code under
  `daemon/`), retained while users migrate to Rust `kclipd`

New desktop installations should use `kclipd` and connect to `/sync/v1`. The
legacy `/ws` and clipboard APIs remain available during the migration window.

---

## Server (FastAPI backend)

### Quick start with Docker

1. Build and start the stack (server + Redis):

   ```bash
   docker compose up --build app
   ```

2. The API is available on [http://localhost:8001](http://localhost:8001). The
   SQLite database is stored at `./clipboard.db` through the development bind
   mount and is created/migrated automatically.

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

3. Apply versioned database migrations and run the API with Uvicorn:

   ```bash
   alembic upgrade head
   uvicorn server_app.main:app --reload --port 8001 --ws-max-size 16777216
   ```

   Migrations run automatically at application startup by default for simple
   single-process installations. For multi-worker production deployments, run
   `alembic upgrade head` once as a deployment step and set
   `RUN_DATABASE_MIGRATIONS_ON_STARTUP=0`. The Docker image does this before it
   starts Gunicorn.

Environment variables recognised by the server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_ENV` | `development` | Set to `production` to enforce production secret/TLS checks |
| `DATABASE_URL` | `sqlite:///./clipboard.db` | SQLAlchemy database URL |
| `JWT_SECRET` | `supersecretkey` | Secret used to sign JWT access tokens |
| `JWT_ALGORITHM` | `HS256` | Signing algorithm |
| `REDIS_URL` | `redis://redis:6379` | Redis connection string used for websocket fanout |
| `RUN_DATABASE_MIGRATIONS_ON_STARTUP` | `true` | Apply Alembic migrations during lifespan startup |
| `SYNC_ENABLED` | `true` | Enable `/sync/v1` |
| `LEGACY_WEBSOCKET_ENABLED` | `true` | Keep migration-era `/ws` enabled |
| `SYNC_ALLOW_QUERY_TOKEN` | `false` | Temporarily allow `?token=` authentication for sync-v1 |
| `SYNC_REQUIRE_TLS` | `false` | Require `wss` or trusted `X-Forwarded-Proto: https` |
| `SYNC_MAX_FRAME_BYTES` | `16777216` | Maximum UTF-8 JSON frame size |
| `SYNC_MAX_EVENT_BYTES` | `11534336` | Maximum decoded ciphertext size |
| `SYNC_REPLAY_BATCH_SIZE` | `500` | Maximum events loaded per SQL replay query |
| `SYNC_MAX_QUEUE_BYTES` | `33554432` | Maximum queued outbound bytes per connection |
| `SYNC_MAX_INVALID_MESSAGES` | `3` | Invalid messages allowed before disconnect |
| `SYNC_HELLO_TIMEOUT_SECONDS` | `15` | Time allowed for the required first hello |
| `SYNC_ACCOUNT_MAX_EVENTS` | `0` | Durable event-count quota; zero disables it |
| `SYNC_ACCOUNT_MAX_STORAGE_BYTES` | `0` | Opaque payload storage quota; zero disables it |
| `SYNC_RATE_LIMIT_EVENTS` | `120` | Accepted events per account/window; zero disables it |
| `SYNC_RATE_LIMIT_WINDOW_SECONDS` | `60` | Durable rate-limit window |
| `SYNC_DATABASE_WORKERS` | `8` | Bounded workers for sync database operations |
| `SYNC_REDIS_PUBLISH_TIMEOUT_SECONDS` | `2` | Redis notification publish timeout |

In production, `APP_ENV=production` refuses startup unless `JWT_SECRET` is a
non-default value of at least 32 characters and `SYNC_REQUIRE_TLS=true` when
sync is enabled. Configure the reverse proxy to terminate TLS, enforce the same
frame bound, and configure Uvicorn's trusted proxy IPs so it rewrites the ASGI
scheme to `wss`; the application does not trust a raw client-supplied
`X-Forwarded-Proto` header.

### kclip sync-v1

Clients connect to `wss://HOST/sync/v1` with an `Authorization: Bearer TOKEN`
header, then send `hello` before `push` or `checkpoint`. Accepted XChaCha20-
Poly1305 envelopes are base64url-decoded and stored as opaque binary values.
The server never decrypts them. SQL is the durable source of truth; Redis only
notifies workers to load newly committed sequences, so reconnect/replay still
works after notification loss.

The event log is intentionally unpruned in protocol version 1. Configure a
quota to reject new uploads explicitly rather than deleting history needed by
offline clients. Wire and cryptographic contract fixtures shared with the Rust
repository live in `fixtures/`.

---

## Legacy daemon (desktop clipboard client)

The Python daemon uses GLib/DBus bindings and the legacy WebSocket protocol. It
is retained for controlled migration; it is not a sync-v1 client.

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
