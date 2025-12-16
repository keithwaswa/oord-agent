
# Install Guide (MVP)

This MVP ships as a Python package with two console commands:

- `oord` — seal/verify + setup
- `oord-agent` — runs sender/receiver watchers from TOML config

## 1) Install (dev / editable)

From the `oord-agent` repo root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
````

You should now have:

```bash
which oord
which oord-agent
```

## 2) Configure Core

You need Core URL + API key for sealing and JWKS fetch.

```bash
export OORD_CORE_URL="http://127.0.0.1:8000"
export OORD_CORE_API_KEY="dev-dev-dev"
```

## 3) Bootstrap local scaffolding

```bash
oord setup
```

This creates:

* `~/.oord/jwks_cache.json`
* `~/.oord/config/sender.toml`
* `~/.oord/config/receiver.toml`
* pipeline folders under `~/.oord/` (watch/out/incoming/verified/quarantine/state/logs)

Re-run safely any time. Use `--force` to overwrite the generated files:

```bash
oord setup --force
```

## 4) First seal / verify

```bash
mkdir -p /tmp/demo-in
echo "hello" >/tmp/demo-in/a.txt

oord seal --input-dir /tmp/demo-in --out /tmp/demo-out --tl-mode required
oord verify /tmp/demo-out/oord_bundle_*.zip --json | jq .
```

## 5) Run the agent (watchers)

### Sender

```bash
oord-agent sender --config ~/.oord/config/sender.toml --once
```

For long-lived mode, omit `--once`.

### Receiver

```bash
oord-agent receiver --config ~/.oord/config/receiver.toml --once
```

## Notes

* `OORD_HOME` can override the default `~/.oord` directory:

```bash
export OORD_HOME="/tmp/oord-home"
oord setup
```

* If Core is unreachable or JWKS fetch fails, `oord setup` exits with code `2`.