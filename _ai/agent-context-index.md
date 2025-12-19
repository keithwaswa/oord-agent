# Oord-Agent Context Index

## Directory Tree (trimmed)
.
├── __main__.py
├── _ai
│   └── agent-context-index.md
├── ~
├── agent
│   ├── __init__.py
│   ├── config.py
│   ├── receiver.py
│   └── sender.py
├── api
│   ├── __init__.py
│   └── app
├── cli
│   └── oord_cli.py
├── docs
│   ├── ADR-008-oord-seal-v1.md
│   ├── Agent-Runbook.md
│   └── Install-Guide.md
├── Makefile
├── oord_agent.egg-info
│   ├── dependency_links.txt
│   ├── entry_points.txt
│   ├── PKG-INFO
│   ├── requires.txt
│   ├── SOURCES.txt
│   └── top_level.txt
├── pyproject.toml
├── pytest.ini
├── scripts
│   ├── ctx.sh
│   ├── systemd
│   └── windows
├── tests
│   ├── agent
│   ├── cli
│   ├── determinism
│   ├── fixtures
│   ├── schemas
│   └── utils
└── utils

20 directories, 21 files

## Grep (gateway/portal/merkle/signature)
_ai/agent-context-index.md:48:## Grep (gateway/portal/merkle/signature)
api/app/models/seal_manifest.py:12:    sha256: str = Field(..., description="Hex-encoded SHA-256 digest of file contents")
api/app/models/seal_manifest.py:16:class MerkleInfo(BaseModel):
api/app/models/seal_manifest.py:19:        description="Content ID for Merkle root, e.g. 'cid:sha256:<hex>'",
api/app/models/seal_manifest.py:21:    tree_alg: Literal["binary_merkle_sha256"] = Field(
api/app/models/seal_manifest.py:22:        "binary_merkle_sha256",
api/app/models/seal_manifest.py:23:        description="Merkle tree algorithm identifier",
api/app/models/seal_manifest.py:38:    signer_key_id: Optional[str] = None
api/app/models/seal_manifest.py:51:            key_id="org-DEMO-LABS-ed25519-1",
api/app/models/seal_manifest.py:52:            merkle=MerkleInfo(...),
api/app/models/seal_manifest.py:54:            signature="dummy-signature",
api/app/models/seal_manifest.py:79:        description="Key ID used to sign this manifest, e.g. 'org-DEMO-LABS-ed25519-1'",
api/app/models/seal_manifest.py:82:    hash_alg: Literal["sha256"] = Field(
api/app/models/seal_manifest.py:83:        "sha256",
api/app/models/seal_manifest.py:84:        description="Hash algorithm used for per-file digests and Merkle leaves",
api/app/models/seal_manifest.py:87:    merkle: MerkleInfo = Field(
api/app/models/seal_manifest.py:89:        description="Merkle tree summary for this batch",
api/app/models/seal_manifest.py:97:    signature: str = Field(
api/app/models/seal_manifest.py:99:        description="Detached signature over the canonical manifest payload",
api/app/models/seal_manifest.py:102:    def unsigned_dict(self) -> dict:
api/app/models/seal_manifest.py:104:        Return the manifest as a plain dict without the signature field.
api/app/models/seal_manifest.py:106:        This is the view that is canonicalized and signed.
api/app/models/seal_manifest.py:109:        data.pop("signature", None)
api/app/models/seal_manifest.py:112:    def unsigned_bytes(self) -> bytes:
api/app/models/seal_manifest.py:114:        Return JCS-style canonical bytes for the unsigned manifest view.
api/app/models/seal_manifest.py:121:            self.unsigned_dict(),
api/app/models/seal_manifest.py:131:    "MerkleInfo",
scripts/ctx.sh:33:  echo "## Grep (gateway/portal/merkle/signature)"
scripts/ctx.sh:43:     -e '@router\.|FastAPI\(|Pydantic|Schema|type ' \
scripts/ctx.sh:44:     -e 'Merkle|verify|sign|ed25519|sha256|reqwest|notify|Cargo\.toml' \
agent/receiver.py:27:      [receiver] 2025-... level=INFO event=verify_pass bundle=...
agent/receiver.py:110:def verify_bundle_via_cli(cfg: AgentConfig, bundle_path: Path) -> Tuple[int, str, str]:
agent/receiver.py:112:    Call the Oord CLI as a subprocess to verify a bundle.
agent/receiver.py:116:    _log("info", "verify_start", bundle=str(bundle_path))
agent/receiver.py:122:        "verify",
agent/receiver.py:223:            code, stdout, stderr = verify_bundle_via_cli(cfg, bundle_path)
agent/receiver.py:238:                    "verify_pass",
agent/receiver.py:251:                    "verify_fail",
agent/receiver.py:262:                    "verify_env_error",
oord_agent.egg-info/PKG-INFO:4:Summary: Oord courier agent + CLI (seal/verify + sender/receiver watcher).
cli/oord_cli.py:16:    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
cli/oord_cli.py:18:    Ed25519PublicKey = None  # type: ignore[assignment]
cli/oord_cli.py:47:def _sha256_bytes(b: bytes) -> str:
cli/oord_cli.py:48:    return hashlib.sha256(b).hexdigest()
cli/oord_cli.py:137:    lines.append(f"jwks_fp_sha256: {jwks_fp}")
cli/oord_cli.py:141:    lines.append(f"tl_signer_kid: {tl_kid or '-'}")
cli/oord_cli.py:148:    Compute Merkle root CID from manifest-style file entries:
cli/oord_cli.py:150:      { "path": "files/...", "sha256": "<64-hex>", "size_bytes": int }

## Recent Commits
- ffef880 fixed test problem
- 96e83c1 Task 4 Complete
- bdbb959 Phase 2 complete
- 137fc3a a bunch of stuff
- 7b71de9 Make oord seal deterministic and tighten bundle layout
- 6c2f506 CI: install pytest+pydantic directly, drop pip install .
- 5f53daa CI: install oord-agent via pyproject and drop Rust build
- 804b977 MVP-Phase1: Remove legacy gateway/Rust stack and finalize Python-only agent
- e97dd12 chore: establish seal/proof contracts and passing test baseline

## Timestamp
Generated: 2025-12-17 00:02:28Z (UTC)
