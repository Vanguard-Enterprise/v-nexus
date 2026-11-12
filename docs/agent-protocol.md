# Agent protocol

Status: proposed sketch. This is not a full specification. Message names and fields may change in the implementation pull requests. The guarantees stated here must not.

The decisions behind this protocol are in [Agent synchronization and jobs](architecture.md#agent-synchronization-and-jobs): Ed25519 agent keys, single-use enrollment tokens, and one WebSocket connection per agent.

## Connection setup

The agent opens a connection in three requests. All requests go to the configured server URL over HTTPS. Authentication does not depend on where TLS terminates.

| Step | Request | Result |
| --- | --- | --- |
| 1 | `POST /api/v1/agent/auth/challenge` with the agent ID | A challenge ID, a random 32-byte nonce, an expiry 60 seconds ahead, and a MAC. The server stores nothing. |
| 2 | `POST /api/v1/agent/auth/session` with the agent ID, key ID, the challenge fields, and a signature | A session token valid for 15 minutes. |
| 3 | `GET /api/v1/agent/connect` with `Authorization: Bearer <session token>` and `Sec-WebSocket-Protocol: vn-agent.v1` | A WebSocket connection. |

Challenges are stateless. The MAC is HMAC-SHA256 over the agent ID, challenge ID, nonce, and expiry, keyed with a challenge key from server configuration that all server replicas share. The challenge endpoint answers for unknown agent IDs too and writes nothing, so it does not reveal which agents exist and gives unauthenticated clients no write path.

The session endpoint checks the MAC and the expiry before it verifies the signature. It enforces single use only when it creates a session: the same transaction inserts the challenge ID into a table of consumed challenges with a unique constraint. Rows are deleted once their challenge has expired. Rotating the challenge key invalidates only outstanding challenges.

The challenge, session, and enrollment endpoints are rate-limited per source address, resolved through configured trusted proxies.

The signature covers a domain-separated message:

```text
"vn-agent-session-v1" 0x00 installation_id agent_id key_id challenge_id nonce
```

The installation ID comes from enrollment and is stored by the agent. Including it stops a challenge from one VN installation being answered for another. Enrollment signatures use the prefix `vn-agent-enroll-v1` over the token ID, public key, and installation ID. The agent reads the installation ID from an unauthenticated server information endpoint before enrolling.

Session tokens are random, carry a recognizable prefix, and are stored as SHA-256 hashes. A token only authorizes opening connections. An open connection stays authorized while the agent remains active.

The server rejects failed steps with an HTTP status and a JSON error before upgrading, so proxies and logs record a normal HTTP failure.

### Close codes

| Code | Meaning | Agent action |
| --- | --- | --- |
| 4000 | Protocol error | Reconnect with backoff and report the error. |
| 4001 | Session invalid or expired | Request a new challenge and session. |
| 4003 | Agent revoked | Stop connecting and report that re-enrollment is needed. |
| 4009 | Superseded by a newer connection for the same agent | Back off and warn: two agent instances may be running. |
| 4010 | Identity mismatch, such as a different cluster fingerprint | Stop connecting and report the mismatch. |

## Envelope

Messages are JSON text frames in version 1. Each message has the same envelope:

```json
{ "type": "upsert", "seq": 42, "body": { } }
```

- `type` names the message.
- `seq` is a per-connection, per-direction counter that starts at 1 and increases by 1. A gap or a repeat is a protocol error.
- `body` holds the message fields.

Receivers ignore unknown fields. A receiver that gets an unknown message type replies with `error { code: "unsupported_type", ref_seq }` and continues. The server limits message size (proposed: 1 MiB) and announces the limit in `welcome`.

## Versioning

- The WebSocket subprotocol selects the major version. The agent offers every version it supports, for example `vn-agent.v2, vn-agent.v1`. The server selects the highest common version, or rejects the upgrade with a JSON error listing its supported versions. The agent checks the selected subprotocol before sending.
- Changes within a major version are additive. Optional behavior is gated by capability strings exchanged in `welcome` and `hello`.
- The server supports at least the previous major version, so agents can be upgraded after the server.

## Session start

1. The server sends `welcome` with the connection ID, the sync epoch, the heartbeat interval, the acknowledgement window, the message size limit, and its capabilities.
2. The agent sends `hello` with its version, capabilities, cluster fingerprint, and, once jobs exist, its unfinished and unacknowledged jobs.

The server allocates a sync epoch each time it accepts a connection, by atomically incrementing a counter on the source record in PostgreSQL. For a cluster agent the source record is the cluster record. The counter belongs to the source, not the agent, so it keeps increasing when a replacement agent enrolls for an existing cluster. A cluster has one active agent at a time. A new connection supersedes any older connection for the same agent, which the server closes with code 4009. The sync epoch orders observations across connections and across agent replacements.

## Collections and scope

A collection is one resource type, such as `v1/nodes`, `v1/namespaces`, or `apps/v1/deployments`. Its scope is exactly what the agent listed: the namespace (or all namespaces) plus any label or field selector. The server stores the scope recorded by the last completed snapshot of each collection.

## Snapshots

| Message | Body |
| --- | --- |
| `snapshot_start` | `snapshot_id`, `collection`, `scope` |
| `upsert` | Observation fields plus `snapshot_id` |
| `snapshot_end` | `snapshot_id`, `item_count`, list `resource_version` |
| `snapshot_abort` | `snapshot_id`, `reason` |
| `collection_error` | `collection`, `scope`, `reason` (for example `forbidden`) |

Snapshots map to `kube-runtime` watcher events: `Init` starts a snapshot, each `InitApply` becomes an `upsert` in it, and `InitDone` ends it. Later `Apply` and `Delete` events become `upsert` and `delete`. A watcher relist within a connection, for example after an expired resource version, produces a new snapshot. The agent lists with the most recent (quorum read) list semantic.

Deletion rules:

- Only `snapshot_end` can infer deletions. The snapshot must have started in this connection, its scope must match, and the server must have received `item_count` items for it.
- At `snapshot_end`, the server marks resources in that collection and scope as deleted when their stored order key is lower than the order key of the `snapshot_start` message. Every `upsert` in the snapshot advances the order key of the resource it names, even when the content is unchanged, so listed resources keep newer keys. Resources updated after the snapshot started also have newer keys.
- Each inferred deletion leaves a tombstone with the order key of the `snapshot_end` message.
- An aborted snapshot, a disconnect, a `collection_error`, a count mismatch, or a new `snapshot_start` for the same collection before the end leaves earlier resources unchanged.
- Resources outside a narrower scope are not deleted. How they are shown is an open question in the architecture document.

## Observations

| Message | Body |
| --- | --- |
| `upsert` | `collection`, `uid`, `namespace`, `name`, `resource_version`, `observed_at`, sanitized `object` |
| `delete` | `collection`, `uid`, `namespace`, `name`, last known `resource_version`, `observed_at` |

The agent sanitizes objects before sending them. Secret data, managed fields, and other excluded attributes never leave the cluster. The server validates the result again. An object larger than the message limit is sent without its body and with a `truncated` flag, so it still counts toward the snapshot.

Ordering:

- Each observation's order key is `(sync_epoch, seq)`. The server stores one order key per resource (cluster and UID): the key of the latest observation accepted for it.
- An observation whose key is not greater than the stored key is ignored. A delayed message from an older connection or a replaced agent has a lower epoch and is ignored.
- An accepted `upsert` always advances the stored key, which records that the resource was seen. It replaces the stored content only when it passes the resource version rule.
- Resource version rule: when both resource versions are decimal strings, the server rejects content whose resource version is lower than the stored one. Kubernetes guarantees this ordering for 1.35 and later API servers within one resource type. It protects against a stale list after a reconnect.
- An accepted `delete` advances the stored key and replaces the resource with a tombstone that keeps its last known resource version. A replacement with the same name has a new UID and is a new resource.
- Kubernetes does not reuse UIDs, so an accepted `upsert` for a tombstoned UID that passes the resource version rule means the deletion was wrong. The server applies it, clears the tombstone, logs the anomaly, and increments a counter. An `upsert` with a lower order key is still ignored.

## Acknowledgements and flow control

- The server sends `ack { seq }` after the transaction containing that message commits. Acknowledgements are cumulative.
- The agent keeps no more unacknowledged messages than the window announced in `welcome`. When the window is full, it stops sending and coalesces pending changes per collection and UID, keeping only the latest. A `delete` replaces a pending `upsert`. Memory is bounded by the number of resources, not the event rate.
- The server processes each connection's messages in order and may batch consecutive observations into one transaction. Each ingest transaction checks that the agent is still active.
- Acknowledgements are for flow control and durability, not retransmission. TCP delivers messages in order within a connection. After a disconnect, the agent discards unacknowledged observations and reconciles from scratch.

## Duplicate delivery

Duplicates come from reconnect snapshots, watcher relists, and a superseded connection whose messages are still being processed. All are harmless:

- An `upsert` with the same UID and resource version as the stored observation leaves the content unchanged. If its order key is greater, it still advances the stored key and the last-confirmed time, so a snapshot that lists an unchanged resource does not delete it.
- An observation with an older order key is ignored.
- Snapshot IDs are UUIDs. A repeated `snapshot_end` is a no-op.

## Reconnect

- The agent reconnects with exponential backoff and jitter, from 1 second up to 60 seconds, and follows the close code table.
- Every new connection starts fresh watchers and sends a full snapshot of every collection. Version 1 does not resume watches from an earlier connection. Resuming can be added later as a capability.

## Heartbeats, connection status, and freshness

- The server sends a WebSocket ping every 15 seconds and closes the connection after 45 seconds without traffic. The interval stays below the 60-second idle timeout common in proxies.
- The agent sends `status` every 30 seconds with each collection's state (`snapshotting`, `watching`, or `error` with a reason) and the time of its last watch event.
- Connection status belongs to the agent. It is connected while an authenticated connection is open and has carried traffic within 45 seconds, and disconnected since a recorded time otherwise. The server records the connection's last-seen time at most every 30 seconds. A record older than 90 seconds counts as disconnected, which covers a server process that stopped without recording the disconnect.
- Data freshness belongs to each collection. A collection is current when its agent is connected, a snapshot has completed in this connection, and the latest `status` reports its watch healthy. Otherwise it is stale since the time it stopped being current. The UI shows the last completed snapshot time, the last observation time, and any collection error.
- Freshness and status use server receive times. The agent's `observed_at` is stored for display but does not decide freshness, so clock skew cannot make data look current.

## Jobs

Jobs reuse the same connection once deployment controls exist.

| Direction | Message | Body |
| --- | --- | --- |
| Server to agent | `job_offer` | `job_id`, `attempt`, `idempotency_key`, `kind`, `params`, `deadline` |
| Agent to server | `job_accepted`, `job_rejected` | `job_id`, `attempt`, `reason` |
| Agent to server | `job_progress` | `job_id`, `attempt`, progress details |
| Agent to server | `job_result` | `job_id`, `attempt`, `idempotency_key`, `outcome` (`succeeded` or `failed`), details |

- The server persists a job before offering it and offers pending jobs for an agent when it connects.
- The idempotency key stays the same across attempts of one job. The agent records the keys it has started, and their results, before acting. A repeated offer returns the recorded state or result instead of running the job again.
- Unlike observations, job results cannot be rebuilt from a snapshot. The agent keeps unacknowledged results across reconnects and lists them in `hello`, with jobs still in progress.
- If a disconnect leaves an outcome unknown and the agent does not report it after reconnecting, the server marks the job `outcome_unknown`. It retries automatically only job kinds declared safe to repeat. Later observations confirm the actual state.
