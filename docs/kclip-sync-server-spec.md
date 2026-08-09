# kclip Sync Server Specification

- Status: Draft 0.4
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

- Support an offline-first Rust client with durable upload and bounded replay.
- Preserve end-to-end encryption between a user's devices.
- Give each accepted event a stable, per-user server sequence.
- Make retries idempotent.
- Recover after client, server, Redis, and network interruptions.
- Keep account authentication and authorization in PyPasteServer.
- Define one required sync-v1 contract deployed with the matching Rust client.

## 3. Non-goals

- Decrypting, indexing, previewing, or validating clipboard content.
- Resolving revision conflicts on the server.
- Managing the local clipboard, KDE Plasma, or `kclip` slots.
- Rotating the separate account encryption key in protocol version 1.
- Exactly-once network delivery. The protocol provides at-least-once delivery
  with idempotent processing.
- Supporting the experimental `/dev/kclip` kernel interface.
- Guaranteeing complete state recovery after a device falls behind the retained
  event window.

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
fall back to another authentication method after a handshake failure. Bearer
headers, query-string tokens, and plaintext application messages are not
supported by `/sync/v1`. Pairing credentials are account-scoped and revoking
one MUST NOT revoke any other device. Every database query and fanout operation
MUST be scoped to the authenticated user ID.

### 5.2 WebSocket messages

Protocol messages are UTF-8 JSON objects inside the Noise transport. Unknown
object fields MUST be ignored when doing so is safe. Unknown message types or
unsupported protocol versions MUST produce a structured error.

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
  "earliest_sequence": 50,
  "replay_from": 50,
  "history_truncated": true
}
```

Every field shown is required. The server MUST NOT emit the earlier draft form
that omitted `earliest_sequence` and `history_truncated`.

`earliest_sequence` is the first event still available. When the buffer is
empty it is one greater than `latest_sequence`. `history_truncated` is true
when `resume_after + 1 < earliest_sequence`; the client MUST then durably skip
through `earliest_sequence - 1` and accept the intentionally lossy replay.

The server sends retained events beginning at `replay_from` in strict ascending
order. Events committed while replay is running MUST follow the replayed
suffix without gaps or reordering on that connection.

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

While an event remains in the rolling buffer, retrying the same `message_id`
MUST return the original sequence and MUST NOT create a new event. Deduplication
is not guaranteed after the original event expires from the buffer.

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

If retention advances beyond an already-connected client's next sequence, the
server sends this control message before resuming delivery:

```json
{
  "type": "history_truncated",
  "protocol_version": 1,
  "earliest_sequence": 50,
  "latest_sequence": 57,
  "replay_from": 50
}
```

The client MUST durably skip through `earliest_sequence - 1`, then accept event
delivery from `replay_from`. Expiration is informational and does not close the
connection.

### 6.6 Errors

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

This clean-break release establishes the single `0001_sync_baseline` migration.
Databases stamped with the retired migration history are unsupported: startup
MUST fail without adopting or rewriting them. An operator may archive or remove
the old database before starting this release. Schema changes after this
baseline MUST use forward versioned migrations; startup-only `create_all`
behavior is insufficient once the baseline is deployed.

The logical schema is:

### 8.1 `sync_user_state`

- `user_id`, primary and foreign key
- `next_server_sequence`, non-null integer starting at 1
- `earliest_retained_sequence`, non-null integer starting at 1
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

Allocating a sequence and inserting its event MUST occur in one transaction.
Concurrent connections for one user MUST serialize sequence allocation without
creating duplicates or gaps caused by rolled-back transactions.

## 9. Replay, retention, and quotas

The relay is a lossy rolling event buffer. The default policy independently
limits each account to:

- seven days since server acceptance;
- 1,000 retained events; and
- 128 MiB across stored nonce, ciphertext, and tag bytes.

After accepting an event and during periodic cleanup, the server MUST delete
the oldest contiguous prefix until every enabled limit is satisfied. It MUST
advance `earliest_retained_sequence` in the same transaction and MUST never
reuse or renumber deleted sequences. A single newest event MAY exceed the byte
limit so an accepted push is not immediately deleted.

Client cursors do not block retention and are never stored by the server.
Missing revisions, slot values, and tombstones on a long-offline or new device
are accepted consequences. The server cannot select a latest event per slot
because slot identity is encrypted. No snapshot or compaction baseline is
retained.

The server MAY additionally enforce hard account quotas. A hard quota rejects
new pushes explicitly and is distinct from automatic rolling retention. A zero
value disables its individual rolling limit for operational use and testing.

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

The supported client API is the Noise-authenticated `/sync/v1` endpoint. Local
account and device administration use the server administrator CLI. Public
registration, password login, logout, bearer-token validation, the retired
`/ws` and `/clipboard` endpoints, and the Python desktop client are not part of
the sync-v1 server. End-user key management and clipboard commands belong to
the Rust `kclip` CLI.

## 12. Configuration

The server should add explicit settings for:

- sync endpoint enablement;
- maximum encrypted event size;
- maximum replay batch size;
- per-connection queue bytes;
- per-account event/storage quota;
- rolling retention age, event count, stored bytes, and cleanup interval;
- rate limits.

Secure production defaults MUST require TLS at the reverse proxy, bounded
frames, and bounded connection queues. `/sync/v1` MUST NOT require or issue a
JWT or other bearer token.

## 13. Observability

Metrics SHOULD include:

- active sync connections;
- accepted and deduplicated pushes;
- push and replay bytes;
- replay lag by event count;
- events and bytes removed by retention;
- events skipped during truncated replay;
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
- Reconnect below the retained floor reports truncation and replays from the
  earliest available event.
- Retention passing an active connection emits `history_truncated` before
  delivery resumes at the retained floor.
- Retention deletes only a contiguous prefix and never reuses a sequence.

### 14.4 Security tests

- One user cannot fetch or subscribe to another user's events.
- Missing, unknown, and revoked pairing credentials are rejected before the
  WebSocket is accepted.
- Bearer headers, query-string tokens, and plaintext sync frames are rejected.
- Oversized frames are rejected before large allocation.
- Secrets and payload bodies do not appear in captured logs.
- Slow clients cannot create unbounded queues.

### 14.5 Cross-repository contract tests

Both repositories MUST share committed protocol fixtures for:

- the hello/ready exchange;
- active `history_truncated` control messages;
- push, push acknowledgement, and event messages;
- XChaCha20-Poly1305 additional-data construction;
- canonical base64url encoding; and
- a known CBOR-envelope encryption/decryption vector.

Fixtures may be duplicated into each repository, but CI MUST fail if either
implementation stops matching them.

## 15. Acceptance criteria

The server portion is complete when:

1. Two independently running `kclipd` instances for one account exchange an
   encrypted revision without the server learning its slot or content.
2. An accepted event survives API, Redis, and client restarts while it remains
   inside the rolling retention window.
3. Retrying a push cannot create a duplicate event.
4. An offline client within the retained window resumes without missing events;
   an older client is explicitly advanced to the retained floor.
5. Events remain strictly isolated by authenticated user.
6. No Python desktop process is required for Rust-to-server synchronization.
