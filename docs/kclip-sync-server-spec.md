# kclip Sync Server Specification

- Status: Draft 0.1
- Audience: PyPasteServer and kclip maintainers
- Companion specification: `dev_clipboard/docs/pypasteserver-sync-client-spec.md`

## 1. Purpose

This document specifies the PyPasteServer responsibilities required to support
the Rust `kclipd` daemon as the only supported desktop synchronization client.
PyPasteServer becomes an authenticated, durable, opaque event relay. It does
not interpret clipboard slots, content, revision clocks, or conflicts, and it
never receives plaintext clipboard data.

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Goals

- Support an offline-first Rust client with durable upload and replay.
- Preserve end-to-end encryption between a user's devices.
- Give each accepted event a stable, per-user server sequence.
- Make retries idempotent.
- Recover after client, server, Redis, and network interruptions.
- Keep account authentication and authorization in PyPasteServer.
- Permit independent client and server releases through a versioned protocol.

## 3. Non-goals

- Decrypting, indexing, previewing, or validating clipboard content.
- Resolving revision conflicts on the server.
- Managing the local clipboard, KDE Plasma, or `kclip` slots.
- Rotating the separate account encryption key in protocol version 1.
- Exactly-once network delivery. The protocol provides at-least-once delivery
  with idempotent processing.
- Supporting the experimental `/dev/kclip` kernel interface.

## 4. System boundary

```text
kclip CLI / desktop adapters
             |
           kclipd
  revisions, inbox/outbox, crypto
             |
      WebSocket sync v1
             |
       PyPasteServer
   auth, event log, replay, fanout
             |
       SQL database + Redis
```

The server SQL database is the source of truth for accepted encrypted events.
Redis is only a low-latency notification mechanism. Losing a Redis message MUST
NOT lose an event because clients can replay it from SQL.

## 5. Transport and authentication

### 5.1 Endpoint

The server MUST expose the WebSocket endpoint:

```text
/sync/v1
```

Each device receives an independent random 32-byte secret through an offline
channel. The client sends the non-secret pairing ID in `X-Kclip-Pairing-ID`,
sets `X-Kclip-Transport: noise-psk-v1`, and performs
`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` as initiator. The server is the Noise
responder. Both ephemeral keys contribute to fresh directional keys, while the
`psk0` token authenticates the first handshake message.

#### 5.1.1 Administrative device setup code

The supported administrative handoff is one line with this form:

```text
kclip-setup-v1:BASE64URL(JSON_UTF8)
```

`BASE64URL` is unpadded base64url. The decoded JSON object contains exactly:

```json
{
  "version": 1,
  "relay_url": "wss://clipboard.example.test/sync/v1",
  "username": "alice",
  "device_name": "office-laptop",
  "pairing_id": "canonical-lowercase-uuid",
  "pairing_secret": "unpadded-base64url-32-bytes"
}
```

`relay_url` MUST use `ws://` or `wss://`, MUST contain a host, MUST have the
exact path `/sync/v1`, and MUST NOT contain user information, a query, or a
fragment. `username` and `device_name` are display context; authorization comes
only from the pairing credential.

The setup code contains the long-lived device secret and MUST be transferred
through a private channel, accepted through hidden client input, stored with
secret-file permissions, and never logged. Administrative tooling displays it
only when the device is created, but the credential remains valid until the
device is revoked. The setup code MUST NOT contain the separate account
synchronization key used for end-to-end payload encryption.

The server MUST reject an unknown or revoked pairing ID before upgrade. After
upgrade it MUST complete the Noise handshake before accepting any sync
protocol message. Every application message after the handshake MUST use the
encrypted binary framing below. A client with pairing credentials MUST NOT
fall back to bearer authentication after a handshake failure.

The legacy JWT path MAY be enabled explicitly during migration, but it MUST use
TLS and MUST send the token in the `Authorization` header rather than a URL.
It is disabled by default. Pairing credentials are account-scoped and revoking
one MUST NOT revoke any other device. Every database query and fanout operation
MUST be scoped to the authenticated user ID.

### 5.2 WebSocket messages

Protocol messages are UTF-8 JSON objects inside the Noise transport. Unknown object fields MUST be ignored
when doing so is safe. Unknown message types or unsupported protocol versions
MUST produce a structured error.

Implementations MUST enforce configurable limits for:

- JSON frame size;
- decoded nonce, tag, and ciphertext size;
- replay batch size;
- outstanding unacknowledged outbound bytes; and
- events accepted per account over a time window.

The initial maximum encrypted event size SHOULD accommodate the `kclipd`
content limit plus envelope and base64 overhead. The client default is 10 MiB
of plaintext, so a 16 MiB WebSocket limit is a reasonable initial minimum.

### 5.3 Encrypted binary framing

Noise ciphertext is limited to 65,535 bytes. A JSON message is therefore split
into chunks of at most 65,518 bytes. Each encrypted plaintext chunk begins with
one byte: `0x00` means more chunks follow and `0x01` marks the final chunk. One
Noise ciphertext is carried in each binary WebSocket data frame. Receivers
MUST enforce the configured logical-message limit while reassembling chunks.

Noise transport nonces are implicit counters. Either peer MUST terminate the
session when authentication fails; replayed, missing, or reordered frames must
never be retried under a different counter. WebSocket ping, pong, and close are
transport control frames and carry no sync data.

## 6. Protocol

All examples omit optional diagnostic fields.

### 6.1 Client hello

The first client message MUST be:

```json
{
  "type": "hello",
  "protocol_version": 1,
  "device_id": "device-...",
  "resume_after": 42
}
```

`device_id` identifies the local kclip installation. `resume_after` is the
highest contiguous server sequence the client has durably processed. A new
client sends zero.

The server MUST reject a second `hello` on the same connection. It MUST NOT
trust `device_id` for authorization; it is an account-scoped synchronization
identifier only.

### 6.2 Server ready

After validating the hello, the server responds:

```json
{
  "type": "ready",
  "protocol_version": 1,
  "connection_id": "5c3f...",
  "latest_sequence": 57,
  "replay_from": 43
}
```

The server then sends all events with `server_sequence > resume_after` in
strict ascending order. Events committed while replay is running MUST be sent
after the replayed prefix without gaps or reordering on that connection.

### 6.3 Push

A client uploads one encrypted revision using:

```json
{
  "type": "push",
  "protocol_version": 1,
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "algorithm": "xchacha20-poly1305",
  "nonce": "base64url-no-padding",
  "ciphertext": "base64url-no-padding",
  "tag": "base64url-no-padding"
}
```

`message_id` MUST be a canonical lowercase UUID generated once and retained by
the client outbox across retries. The server MUST enforce uniqueness on
`(user_id, message_id)`.

The server MUST validate only the outer encoding, lengths, supported algorithm,
and authentication. It cannot validate the encrypted revision.

Acceptance MUST be transactional:

1. Allocate the next per-user `server_sequence`.
2. Insert the event or find the existing event for a duplicate `message_id`.
3. Commit the database transaction.
4. Send an acknowledgement.
5. Publish a Redis notification for newly inserted events.

If the connection fails after commit but before acknowledgement, retrying the
same `message_id` MUST return the original sequence and MUST NOT create a new
event.

### 6.4 Push acknowledgement

```json
{
  "type": "push_ack",
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "server_sequence": 58,
  "duplicate": false
}
```

The acknowledgement means the encrypted event is durably stored. It does not
mean another device has processed it.

### 6.5 Event delivery

Replay and live fanout use the same message:

```json
{
  "type": "event",
  "server_sequence": 58,
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "sender_device_id": "device-...",
  "algorithm": "xchacha20-poly1305",
  "nonce": "base64url-no-padding",
  "ciphertext": "base64url-no-padding",
  "tag": "base64url-no-padding",
  "accepted_at": 1770000000000
}
```

The server MAY deliver an event to the connection that uploaded it. Clients
MUST therefore deduplicate events. Correctness MUST NOT depend on suppressing
self-echoes at the server.

`sender_device_id` is informational and MUST be populated from the authenticated
connection, not from the push body.

### 6.6 Processing checkpoint

After durably recording and successfully processing a contiguous event prefix,
the client sends:

```json
{
  "type": "checkpoint",
  "server_sequence": 58
}
```

The server stores the greatest checkpoint for `(user_id, device_id)` and MUST
NOT move it backwards. A checkpoint is advisory for operations and future
retention; the client's durable local cursor remains authoritative on reconnect.

The client MUST NOT checkpoint an event merely because it was received. It
checkpoints only after inbox persistence and successful application or durable
classification as an ignorable duplicate.

### 6.7 Errors

Recoverable protocol errors use:

```json
{
  "type": "error",
  "code": "quota_exceeded",
  "message": "account event quota exceeded",
  "retryable": false,
  "message_id": "optional-related-message-id"
}
```

Stable version 1 codes are:

- `invalid_message`
- `protocol_mismatch`
- `authentication_failed`
- `permission_denied`
- `event_too_large`
- `quota_exceeded`
- `rate_limited`
- `server_unavailable`
- `replay_unavailable`
- `internal_error`

The server SHOULD close connections that continue sending invalid messages or
that exceed backpressure limits. Authentication failures MUST close the
connection without revealing account details.

## 7. Encryption contract

The server treats `nonce`, `ciphertext`, and `tag` as opaque bytes.

Protocol version 1 uses:

- a 32-byte account synchronization key;
- XChaCha20-Poly1305;
- a fresh 24-byte random nonce for every encryption; and
- a 16-byte authentication tag.

The authenticated additional data is the byte concatenation:

```text
UTF8("kclip-sync-v1") || 0x00 || UTF8(message_id)
```

The encrypted plaintext is the canonical CBOR revision envelope defined by the
companion client specification. Binding `message_id` into the authenticated
data prevents the server or an intermediary from relabeling ciphertext.

The server MUST NOT log encryption keys, tokens, ciphertext bodies, nonces, or
tags. Diagnostic logs MAY contain user ID, message ID, server sequence, byte
counts, error category, and timing.

## 8. Persistence model

The implementation MUST use versioned database migrations. Startup-only
`create_all` behavior is insufficient for this protocol once deployed.

The logical schema is:

### 8.1 `sync_user_state`

- `user_id`, primary and foreign key
- `next_server_sequence`, non-null integer starting at 1
- `created_at`
- `updated_at`

### 8.2 `sync_events`

- internal primary key
- `user_id`, foreign key and indexed
- `server_sequence`, positive integer
- `message_id`, canonical UUID string
- `sender_device_id`
- `protocol_version`
- `algorithm`
- `nonce`
- `ciphertext`
- `tag`
- `accepted_at`

Required unique constraints:

- `(user_id, server_sequence)`
- `(user_id, message_id)`

The event columns SHOULD use binary storage after base64url decoding. The API
must reproduce the canonical base64url form on output.

### 8.3 `sync_device_cursors`

- `user_id`
- `device_id`
- `processed_server_sequence`
- `first_seen_at`
- `last_seen_at`
- optional `revoked_at`

Primary key: `(user_id, device_id)`.

Allocating a sequence and inserting its event MUST occur in one transaction.
Concurrent connections for one user MUST serialize sequence allocation without
creating duplicates or gaps caused by rolled-back transactions.

## 9. Replay, retention, and quotas

The first production implementation MUST retain every accepted sync event. It
MUST NOT silently prune events because protocol version 1 has no encrypted
snapshot or compaction mechanism from which a device can recover.

The server MAY enforce account storage quotas. When a quota is exhausted, it
MUST reject new pushes explicitly; it MUST NOT delete older events behind an
offline client's cursor.

A later protocol may add snapshots and bounded retention. Until that protocol
is deployed to all supported clients, `replay_unavailable` is a terminal state
requiring explicit operator or user recovery, not an invitation to skip ahead.

## 10. Fanout and Redis

After committing a new event, the accepting worker publishes a notification
containing at least the user ID and event primary key or server sequence.
Listening workers load the committed event from SQL and fan it out to active
connections for that user.

Requirements:

- Never publish before the SQL commit.
- Never treat Redis as durable storage.
- Preserve ascending sequence order per WebSocket connection.
- Bound each connection's send queue.
- Disconnect slow consumers before their queue can exhaust server memory.
- Let disconnected clients recover through replay.

Duplicate Redis delivery is harmless and SHOULD be suppressed by sequence at
the connection layer when convenient.

## 11. Supported client surface

The supported client APIs are registration, login, logout, token validation,
and `/sync/v1`. The retired `/ws` and `/clipboard` endpoints and Python desktop
client are not part of the sync-v1 server. End-user key management and
clipboard commands belong to the Rust `kclip` CLI.

## 12. Configuration

The server should add explicit settings for:

- sync endpoint enablement;
- maximum encrypted event size;
- maximum replay batch size;
- per-connection queue bytes;
- per-account event/storage quota;
- rate limits.

Secure production defaults MUST require TLS at the reverse proxy, a non-default
JWT secret, bounded frames, and bounded connection queues.

## 13. Observability

Metrics SHOULD include:

- active sync connections;
- accepted and deduplicated pushes;
- push and replay bytes;
- replay lag by event count;
- authentication failures;
- event-too-large, quota, and rate-limit errors;
- Redis notification failures;
- slow-consumer disconnects; and
- SQL commit latency.

Logs and metrics MUST NOT include plaintext or cryptographic secrets.

## 14. Required tests

### 14.1 Protocol tests

- Authentication and cross-user isolation.
- Hello required before other messages.
- Unsupported protocol version.
- Outer-message and base64url validation.
- Maximum frame and ciphertext limits.
- Canonical error codes.

### 14.2 Durability tests

- Push is visible after server restart.
- Disconnect after commit and before acknowledgement deduplicates on retry.
- WebSocket upload updates SQL before fanout.
- Redis loss does not prevent replay.
- Concurrent pushes receive unique increasing per-user sequences.

### 14.3 Replay tests

- New device replays from zero.
- Reconnecting device resumes after its local cursor.
- Events committed during replay follow the replay prefix in order.
- Duplicate notifications do not duplicate events on a connection.
- A checkpoint never moves backwards.

### 14.4 Security tests

- One user cannot fetch or subscribe to another user's events.
- Revoked and invalid tokens are rejected.
- Oversized frames are rejected before large allocation.
- Secrets and payload bodies do not appear in captured logs.
- Slow clients cannot create unbounded queues.

### 14.5 Cross-repository contract tests

Both repositories MUST share committed protocol fixtures for:

- the hello/ready exchange;
- push, push acknowledgement, event, and checkpoint messages;
- XChaCha20-Poly1305 additional-data construction;
- canonical base64url encoding; and
- a known CBOR-envelope encryption/decryption vector.

Fixtures may be duplicated into each repository, but CI MUST fail if either
implementation stops matching them.

## 15. Acceptance criteria

The server portion is complete when:

1. Two independently running `kclipd` instances for one account exchange an
   encrypted revision without the server learning its slot or content.
2. An accepted event survives API, Redis, and client restarts.
3. Retrying a push cannot create a duplicate event.
4. An offline client resumes without missing committed events.
5. Events remain strictly isolated by authenticated user.
6. No Python desktop process is required for Rust-to-server synchronization.
