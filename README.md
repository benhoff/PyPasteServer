# PyPasteServer

This repository contains the FastAPI backend for the Rust `kclip` client:

- account registration, login, logout, and JWT validation;
- a durable, end-to-end-encrypted sync-v1 event relay; and
- SQL-backed replay with Redis notification fanout.

Desktop clipboard state, encryption, conflict handling, and user-facing CLI
commands live in the `dev_clipboard` repository. Its `kclipd` daemon connects
to this server at `/sync/v1`.

---

## Server (FastAPI backend)

### Quick start with Docker

For a persistent local installation, run:

```bash
./install.sh
```

The installer checks Docker, generates a private `.env` containing a random
JWT secret, stores the SQLite database under the normal XDG data directory,
builds the image, and starts the server and Redis in the background. It binds
to `127.0.0.1:8001` by default. To accept clients from the local network, use:

```bash
./install.sh --listen 0.0.0.0
```

Paired clients encrypt and authenticate every application frame over this
`ws://` endpoint with Noise. Network observers can still see endpoints, timing,
and message sizes, so use TLS as an additional layer before exposing it to the
Internet. Run `./install.sh --help` for data-directory, port, reconfiguration,
build, and startup options.

Create an account and one independent pairing credential per client on the
server host:

```bash
docker compose exec app python -m server_app.admin create-account \
  --username alice --email alice@example.test
docker compose exec app python -m server_app.admin create-pairing \
  --username alice --device-name laptop
```

The second command prints a pairing code once. Transfer it to the client over
an offline channel, run `kclip auth pair`, and paste it into the hidden prompt.
List or revoke credentials without exposing their secrets:

```bash
docker compose exec app python -m server_app.admin list-pairings --username alice
docker compose exec app python -m server_app.admin revoke-pairing \
  --pairing-id PAIRING_ID
```

To run the development stack directly instead:

1. Build and start the server and Redis:

   ```bash
   docker compose up --build app
   ```

2. The API is available on [http://localhost:8001](http://localhost:8001). The
   SQLite database is created and migrated automatically. Without an
   installer-generated `.env`, it is stored at `./clipboard.db` through the
   development bind mount.

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
| `SYNC_ALLOW_QUERY_TOKEN` | `false` | Temporarily allow `?token=` authentication for sync-v1 |
| `SYNC_ALLOW_LEGACY_BEARER` | `false` | Permit the old JWT WebSocket authentication path |
| `SYNC_REQUIRE_TLS` | `false` | Require TLS when legacy bearer sync is enabled; Noise pairing can use `ws` |
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

Paired clients connect to `ws://HOST/sync/v1` with a public pairing ID, perform
`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`, and then send `hello` before `push` or
`checkpoint`. Each post-handshake JSON message is split into bounded chunks;
every chunk is encrypted and authenticated in a binary WebSocket frame. Noise
transport nonces enforce strict frame order and reject replay. Fresh ephemeral
keys give every connection new directional transport keys.

The per-device Noise secret authenticates and protects the network session. It
is separate from kclip's shared end-to-end sync key. The server stores the
device PSK because a Noise responder must possess it, so the SQL database must
be protected as credential material; compromising it permits impersonation but
does not reveal clipboard plaintext without the separate sync key.

Accepted XChaCha20-
Poly1305 envelopes are base64url-decoded and stored as opaque binary values.
The server never decrypts them. SQL is the durable source of truth; Redis only
notifies workers to load newly committed sequences, so reconnect/replay still
works after notification loss.

The event log is intentionally unpruned in protocol version 1. Configure a
quota to reject new uploads explicitly rather than deleting history needed by
offline clients. Wire and cryptographic contract fixtures shared with the Rust
repository live in `fixtures/`.

The former bearer-token WebSocket mode is disabled by default. During a TLS-
protected migration it can be enabled with `SYNC_ALLOW_LEGACY_BEARER=true` and
`SYNC_REQUIRE_TLS=true`; do not enable it on a plaintext LAN endpoint.

## Repository layout

```
server_app/          FastAPI backend modules
docs/                Sync-v1 server protocol specification
fixtures/            Cross-repository protocol and encryption vectors
migrations/          Alembic database migrations
docker-compose.yml   Container stack (FastAPI + Redis)
Dockerfile           Server image definition
tests/               Pytest suite
```
