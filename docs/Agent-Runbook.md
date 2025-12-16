````md
# Oord Agent Runbook (Sender + Receiver)

This doc covers how to run the Oord Agent as a deployable service:

- Single entrypoint: `python -m agent sender|receiver --config ...`
- Stable config loading from a TOML file
- Structured log lines suitable for systemd / Windows services

The Agent is **just a watcher around the courier engine** – no pre-pivot lab logic, no domain semantics.

---

## 1. Config Overview

The Agent reads a single TOML config file. Minimal example:

```toml
mode = "sender"  # or "receiver"

[core]
base_url = "http://127.0.0.1:8000"

[org]
id = "DEMO-ORG"
batch_prefix = "BATCH"

[agent]
poll_interval_sec = 2
settle_seconds = 5
recursive = true

[logging]
level = "INFO"
file = "/var/log/oord/sender.log" # optional; omit to log only to stdout

[sender.paths]
watch_dir = "/data/exports"
out_dir = "/data/ready_to_send"
state_file = "/var/lib/oord/sender_state.json"
````

Receiver uses:

```toml
mode = "receiver"

[core]
base_url = "http://127.0.0.1:8000"

[org]
id = "DEMO-ORG"

[agent]
poll_interval_sec = 2
settle_seconds = 5
recursive = true

[logging]
level = "INFO"
file = "/var/log/oord/receiver.log" # optional

[receiver.paths]
incoming_dir = "/data/incoming"
verified_root = "/data/verified"
quarantine_dir = "/data/quarantine"
state_file = "/var/lib/oord/receiver_state.json"
```

If `[logging]` is omitted, the Agent defaults to `INFO` and logs only to stdout.

---

## 2. How to Run Manually (Dev / One-Off)

From the `oord-agent` repo root:

```bash
export PYTHONPATH=.

python -m agent sender --config /tmp/sender.toml
python -m agent receiver --config /tmp/receiver.toml
```

Log lines look like:

```text
[sender] 2025-12-13T18:23:45Z level=INFO event=agent_start watch_dir=/data/exports out_dir=/data/ready_to_send ...
[sender] 2025-12-13T18:23:50Z level=INFO event=batches_ready count=1 watch_dir=/data/exports
[sender] 2025-12-13T18:23:50Z level=INFO event=seal_start batch_name=run_001 batch_id=BATCH-run_001 ...
[sender] 2025-12-13T18:23:51Z level=INFO event=seal_success batch_name=run_001 batch_id=BATCH-run_001 ...
```

You can override the log level from the CLI:

```bash
python -m agent sender --config /tmp/sender.toml --log-level DEBUG
```

---

## 3. Linux: systemd Service

Example units live under `scripts/systemd/`:

* `scripts/systemd/oord-sender.service`
* `scripts/systemd/oord-receiver.service`

### 3.1 Install the service

Copy the unit file into `/etc/systemd/system`:

```bash
sudo cp scripts/systemd/oord-sender.service /etc/systemd/system/oord-sender.service
sudo cp scripts/systemd/oord-receiver.service /etc/systemd/system/oord-receiver.service

sudo systemctl daemon-reload
```

Make sure:

* Python and `oord-agent` are installed in `/opt/oord-agent` (or adjust `ExecStart`/`WorkingDirectory`).
* Sender and receiver configs are present at `/etc/oord/sender.toml` and `/etc/oord/receiver.toml`.

### 3.2 Start, enable, and inspect

```bash
sudo systemctl enable --now oord-sender.service
sudo systemctl enable --now oord-receiver.service

sudo systemctl status oord-sender.service
sudo systemctl status oord-receiver.service

sudo journalctl -u oord-sender.service -f
sudo journalctl -u oord-receiver.service -f
```

systemd will capture the same structured log lines as manual runs.

---

## 4. Windows: Service Wrapper

We don’t ship a custom Windows service binary. Operators use their usual service tooling (e.g. `sc.exe`, `nssm`) to wrap a simple PowerShell command.

A helper script lives at `scripts/windows/oord-agent-service.ps1`:

```powershell
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("sender", "receiver")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

python -m agent $Mode --config $ConfigPath
```

Example `nssm` usage:

```powershell
nssm install OordAgentSender "C:\Python\python.exe" `
    "-m agent sender --config C:\Oord\sender.toml"

nssm install OordAgentReceiver "C:\Python\python.exe" `
    "-m agent receiver --config C:\Oord\receiver.toml"
```

Logs go wherever you configure them:

* stdout/stderr -> Windows Event Log (if you wire it that way), and/or
* `[logging].file` in the Agent config.

---

## 5. How to Test the Agent

1. Prepare minimal sender/receiver configs in `/tmp/sender.toml` and `/tmp/receiver.toml`.

2. Create the watch / incoming / verified / quarantine directories.

3. Run:

   ```bash
   export PYTHONPATH=.

   python -m agent sender --config /tmp/sender.toml
   python -m agent receiver --config /tmp/receiver.toml
   ```

4. Drop a stable batch folder under the sender `watch_dir` and confirm:

   * Sender logs `batches_ready`, `seal_start`, `seal_success`.
   * A new `oord_bundle_*.zip` appears in the sender `out_dir`.

5. Move that bundle into the receiver `incoming_dir` and confirm:

   * Receiver logs `bundles_ready`, `verify_start`, `verify_pass`.
   * Files appear under `verified_root/<bundle_stem>/`.
   * State files are updated under the configured `state_file` paths.

If anything fails, check:

* Agent logs for `seal_failed`, `verify_fail`, or `verify_env_error`.
* That `mode` in the config matches the command (`sender` vs `receiver`).
* That `core.base_url` is reachable.

