# Oord Agent + CLI Error Model (v1)

This document defines the exit-code contract for the Oord CLI and the **actual, implemented** crash-safe behavior of the Oord Agent (sender and receiver).

It reflects **current v1 behavior**, including known limitations that are explicitly accepted and documented.

---

## CLI Exit Codes

### `oord seal`

| Code | Meaning |
| --- | --- |
| **0** | Bundle created successfully. |
| **2** | Environment / infrastructure failure (Core unreachable, bad config, IO error, unexpected exception). A retry may succeed once the environment is fixed. |

*There is no logical/content failure mode for `seal` in v1.*

### `oord verify`

| Code | Meaning |
| --- | --- |
| **0** | Verification passed. |
| **1** | Verification failed due to content or cryptographic mismatch (hash, Merkle root, signature, JWKS, etc.). |
| **2** | Environment / infrastructure failure (bad ZIP, path missing, tool error, TL unreachable in strict mode). |

---

## Agent Error Handling Rules (Implemented Behavior)

### Sender

* **CLI exit 0:**
* Batch is marked `sealed` in sender state.


* **CLI exit 2 (or any non-zero):**
* Batch is marked `retry`.
* Retry metadata is persisted (`attempts`, `next_retry_at_ms`, `last_exit_code`, `last_error`).
* State writes are **atomic** (`.tmp` write + rename).



The sender state machine in v1 is:

```text
retry → sealed

```

*There is no explicit `processing` state.*

### Receiver

* **CLI exit 0:**
* Bundle is verified.
* Payload files are extracted.
* Bundle is marked `verified` in receiver state.


* **CLI exit 1:**
* Bundle is moved to the quarantine directory.
* Bundle is marked `quarantined` in receiver state.


* **CLI exit 2 (or any non-0/1):**
* Bundle remains in the incoming directory.
* Bundle is marked `retry` in receiver state with backoff metadata.
* No extraction occurs.



The receiver state machine in v1 is:

```text
retry → verified
retry → quarantined

```

*There is no explicit `processing` state.*

---

## Crash-Safe and Idempotency Guarantees

### State Files

Sender and receiver state files are written atomically using:

1. write to `state.json.tmp`
2. atomic rename to `state.json`

Corrupt or unreadable state files are treated as empty.

**This guarantees:**

* no partially written JSON
* no crash loops due to malformed state

### Sender Crash Behavior

If the sender crashes **after a successful seal but before state is written**, the batch may be re-sealed on restart.
This is accepted behavior in v1 and documented explicitly.

**Planned v2 mitigation options:**

* per-batch claim/lock markers
* deterministic bundle identity with idempotent duplicate detection

The sender **does not guarantee** “exactly once” sealing in v1.

### Receiver Extraction

Extraction is performed into a staging directory:

```text
<bundle_stem>.tmp/

```

After extraction completes, the directory is atomically renamed to:

```text
<bundle_stem>/

```

* Receiver state is updated **only after** the rename.
* If the receiver crashes mid-extraction:
* a `.tmp` directory may remain
* the next run will delete or overwrite it before retrying



This prevents partially extracted payloads from appearing as verified output.

---

## Retry and Backoff Policy (v1)

* Environment failures (exit 2) are retried automatically.
* Exponential backoff with jitter is applied:
* **base:** 500ms
* **cap:** 60s


* Backoff state is persisted so crashes do not reset retry timing.
* There is no maximum retry count in v1.

---

## Observability

The Agent emits structured log events for:

* startup and shutdown
* discovery of ready batches/bundles
* seal/verify start
* success (`seal_success`, `verify_pass`)
* failure (`seal_failed`, `verify_fail`, `verify_env_error`)
* retry scheduling (`next_retry_in_ms`)

Logs are designed to make retry behavior and failure modes explicit and diagnosable.

---

## Known Limitations (Accepted for v1)

* No explicit `processing` state.
* Sender does not guarantee exactly-once sealing.
* Mid-extract crash behavior is implemented correctly but not exhaustively stress-tested.
* No automatic cleanup of abandoned `.tmp` directories beyond overwrite on retry.

These are documented tradeoffs and are candidates for v2 hardening.