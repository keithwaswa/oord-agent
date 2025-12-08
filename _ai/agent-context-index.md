# Oord-Agent Context Index

## Directory Tree (trimmed)
.
├── _ai
│   └── agent-context-index.md
├── api
│   ├── __init__.py
│   └── app
├── cli
│   └── oord_cli.py
├── docs
│   └── ADR-008-oord-seal-v1.md
├── gateway
│   ├── _data
│   ├── _out
│   ├── Cargo.toml
│   ├── src
│   └── tests
├── main.py
├── Makefile
├── pyproject.toml
├── pytest.ini
├── scripts
│   └── ctx.sh
├── tests
│   ├── cli
│   ├── schemas
│   └── utils
└── utils

17 directories, 10 files

## Grep (gateway/portal/merkle/signature)
gateway/src/pipeline.rs:34:    let sha = sha256_file(src)?;
gateway/src/pipeline.rs:137:    let sig = core_client::sign_session(&ctx, &sess.session_id)?;
gateway/src/pipeline.rs:192:        "signature": { "key_id": sig.kid, "algorithm": "Ed25519" },
gateway/src/pipeline.rs:215:        "bundle_sha256": session.bundle_sha256,
gateway/src/pipeline.rs:230:    // deterministic; in real-Core mode it reflects the current signing keys.
gateway/src/pipeline.rs:303:    println!("attestation_path={} sha256={}", out_pdf.display(), sha);
gateway/src/pipeline.rs:308:fn sha256_file(p: &Path) -> Result<String> {
gateway/src/main.rs:9:use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
gateway/src/main.rs:106:    // Core session + sign + TL submit
gateway/src/main.rs:108:    let _sig = core_client::sign_session(&ctx, &sess_resp.session_id)?;
gateway/src/main.rs:416:                        "bundle_sha256": sess.bundle_sha256,
gateway/src/main.rs:717:                println!("vault_loader_canonical_path={} sha256={}", out_path, digest);
gateway/src/main.rs:759:                println!("IQOQ_canonical_path={} sha256={}", out_path, digest);
gateway/src/main.rs:839:        let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())?;
docs/ADR-008-oord-seal-v1.md:17:- The reference CLI (`oord seal`, `oord verify`).
docs/ADR-008-oord-seal-v1.md:18:- Agents/watchers that build and verify sealed bundles.
docs/ADR-008-oord-seal-v1.md:32:- `key_id` — string; identifier of the Ed25519 key used to sign the manifest.
docs/ADR-008-oord-seal-v1.md:33:- `hash_alg` — string; currently `"sha256"`.
docs/ADR-008-oord-seal-v1.md:34:- `merkle` — object describing the Merkle tree:
docs/ADR-008-oord-seal-v1.md:35:  - `root_cid` — string; `"cid:sha256:<64hex>"`, derived from the Merkle root bytes.
docs/ADR-008-oord-seal-v1.md:36:  - `tree_alg` — string; `"binary_merkle_sha256"`.
docs/ADR-008-oord-seal-v1.md:39:  - `sha256` — string; 64-char lowercase hex SHA-256 digest of the file contents.
docs/ADR-008-oord-seal-v1.md:41:- `signature` — string; URL-safe base64 (no padding) Ed25519 signature over the JCS-canonicalized manifest **without** the `signature` field.
docs/ADR-008-oord-seal-v1.md:47:1. Construct a manifest object containing all fields **except** `signature`.
docs/ADR-008-oord-seal-v1.md:50:4. Encode the raw 64-byte signature in URL-safe base64 without padding.
docs/ADR-008-oord-seal-v1.md:51:5. Insert this string into the `signature` field.
docs/ADR-008-oord-seal-v1.md:57:2. Extract and temporarily ignore `signature`.
docs/ADR-008-oord-seal-v1.md:59:4. Fetch the verifying key corresponding to `key_id` from JWKS.
docs/ADR-008-oord-seal-v1.md:60:5. Verify the Ed25519 signature over the canonical bytes.
docs/ADR-008-oord-seal-v1.md:61:6. Re-hash files, recompute Merkle root, and confirm it matches `merkle.root_cid`.
docs/ADR-008-oord-seal-v1.md:65:- `hash_alg` must be `"sha256"` in v1.
docs/ADR-008-oord-seal-v1.md:66:- `merkle.tree_alg` must be `"binary_merkle_sha256"` in v1.
docs/ADR-008-oord-seal-v1.md:67:- `merkle.root_cid` must match the Merkle root computed from `files[*].sha256` in a deterministic order (exact ordering rules are defined in the agent/CLI/bundle ADR).
docs/ADR-008-oord-seal-v1.md:68:- All `files[*].sha256` must be 64-char lowercase hex.
docs/ADR-008-oord-seal-v1.md:73:`proof.json` provides an optional Transparency Log anchoring proof for a manifest’s Merkle root.
docs/ADR-008-oord-seal-v1.md:79:- `merkle_root` — string; `"cid:sha256:<64hex>"`, must match `manifest.merkle.root_cid`.
docs/ADR-008-oord-seal-v1.md:82:  - `root_hash` — string; `"sha256:<64hex>"` Merkle root of the TL tree.
docs/ADR-008-oord-seal-v1.md:84:  - `key_id` — string; identifier of the Ed25519 key used to sign the STH.
docs/ADR-008-oord-seal-v1.md:85:  - `signature` — string; URL-safe base64 (no padding) Ed25519 signature over the STH payload.
docs/ADR-008-oord-seal-v1.md:93:## 4. JSON Schemas
docs/ADR-008-oord-seal-v1.md:95:The following JSON Schemas are added under `oc/schemas/`:
docs/ADR-008-oord-seal-v1.md:108:## 5. Pydantic Models
docs/ADR-008-oord-seal-v1.md:110:To make these contracts easy to use inside the API service, we define Pydantic models under:
docs/ADR-008-oord-seal-v1.md:117:- `MerkleInfo`
docs/ADR-008-oord-seal-v1.md:124:- Mirror the JSON Schema shapes.
docs/ADR-008-oord-seal-v1.md:139:- Constructs example `SealManifest` and `TlProof` instances using Pydantic.
Makefile:4:	cargo build --manifest-path gateway/Cargo.toml
Makefile:10:	cargo test --manifest-path gateway/Cargo.toml

## Recent Commits
- e97dd12 chore: establish seal/proof contracts and passing test baseline

## Timestamp
Generated: 2025-12-08 01:18:03Z (UTC)
