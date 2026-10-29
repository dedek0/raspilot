# ✈ RASPilot

> 🇧🇷 [Versão em Português](README.md)

**Automatic RASP auditing pilot for Android.** RASPilot connects to a
device over ADB, runs anti-root, anti-Frida, anti-hooking,
anti-tampering, anti-emulator, anti-proxy/VPN and SSL-pinning checks,
and writes JSON/HTML reports. It also exposes everything as an **MCP**
server for Claude Code, OpenCode, Codex and other harnesses.

- [Quick start](#quick-start) · [Sessions](#sessions-and-stages) ·
  [MCP](#mcp-server) · [Troubleshooting](#troubleshooting) ·
  [Full reference](REFERENCE.en.md)

## Requirements

- Python **3.9+** (3.11+ recommended)
- `adb` in `PATH` and an authorized device (`adb devices` must show `device`)
- `frida`/`frida-tools` on the host; root on the device for `frida-server`
- **Optional:** Android SDK + JDK to build the instrumentation module
- **Optional:** `apktool`/`zipalign`/`apksigner` for repack
- **Optional:** Droid ASC for semantic static analysis (Python 3.10+)

## Install

```bash
git clone https://github.com/dedek0/raspilot
cd raspilot

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# optional: semantic static analysis
pip install -r requirements-static.txt

# optional: MCP server
pip install -r requirements-mcp.txt
```

Check the device:

```bash
adb devices
```

## Quick start

```bash
# Static APK profile
python main.py --package com.example.app --stage static

# Detection only — the output prints the session ID
python main.py --package com.example.app --stage detect

# Bypass on the same session
python main.py --session <SESSION_ID> --stage bypass

# Report from saved state (no device needed)
python main.py --session <SESSION_ID> --stage report
```

Full pipeline in one call:

```bash
python main.py --package com.example.app --stage full
```

Useful examples:

```bash
# specific device / Wi-Fi ADB
python main.py --package com.example.app --device-id emulator-5554
python main.py --package com.example.app --wifi 192.168.0.10:5555

# one check / skip checks
python main.py --package com.example.app --only anti_proxy
python main.py --package com.example.app --skip anti_emulator ssl_pinning

# use the on-device module (when a hooking framework is available)
python main.py --package com.example.app \
  --hook-method module --proxy-method module --emulator-method module

# local APK (no device) for the static stage
python main.py --stage static --apk ./app.apk
```

### Main flags

| Flag | Purpose |
|---|---|
| `--package` | Target package name |
| `--device-id` / `--wifi` | ADB serial or Wi-Fi address |
| `--stage` | `static`, `detect`, `bypass`, `full` (default) or `report` |
| `--session` | Resume an existing session |
| `--state-dir` | Session directory (default `~/.raspilot/sessions`) |
| `--list-sessions` / `--show-session` | List or inspect sessions |
| `--only` / `--skip` | Run or skip specific checks |
| `--window` | Dynamic observation window (default 15s) |
| `--output-dir` | Report directory (default `reports/`) |
| `--json-only` | JSON only, no HTML |
| `--apk` | Local APK (skips `adb pull`) |
| `--hook-method` / `--proxy-method` / `--emulator-method` | `auto`, `frida` or `module` |
| `--module-apk` | Use a prebuilt module APK |
| `--tamper-method repack` | Destructive repack test |
| `--tamper-allow-reinstall` | Confirms app data may be wiped |

The full table, including timeouts and repack options, is in
[REFERENCE.en.md](REFERENCE.en.md#arguments).

## Sessions and stages

Each run creates a session under `~/.raspilot/sessions/<id>/`:

```text
session.json   full state
static.json    static APK profile
report.json    JSON report
summary.json   per-check summary
report.html    visual report
checks/        raw result per check
artifacts/     repack APKs, when kept
```

Commands:

```bash
python main.py --list-sessions
python main.py --show-session <SESSION_ID>
python main.py --session <SESSION_ID> --stage report
```

`detect` observes without bypassing; `bypass` requires `detect` in the
same session; `full` runs the whole pipeline; `report` only regenerates
files. Running sessions are locked per device — two runs on the same
phone fail fast.

## MCP server

The server uses **stdio** by default — the transport supported by Claude
Code, OpenCode, Codex and any MCP harness.

```bash
pip install -r requirements-mcp.txt
python mcp_server.py
```

Ready-made configs are in [`examples/mcp/`](examples/mcp/). Short
examples:

**Claude Code** (`.mcp.json`):

```json
{
  "mcpServers": {
    "raspilot": {
      "command": "/path/to/.venv/bin/python",
      "args": ["/path/to/mcp_server.py"],
      "env": {"RASPILOT_DEVICE": "SERIAL"}
    }
  }
}
```

**OpenCode** (`opencode.json`):

```json
{
  "mcp": {
    "raspilot": {
      "type": "local",
      "command": ["/path/to/.venv/bin/python", "/path/to/mcp_server.py"],
      "enabled": true,
      "environment": {"RASPILOT_DEVICE": "SERIAL"}
    }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.raspilot]
command = "/path/to/.venv/bin/python"
args = ["/path/to/mcp_server.py"]
env = { RASPILOT_DEVICE = "SERIAL" }
```

Useful environment variables:

| Variable | Purpose |
|---|---|
| `RASPILOT_DEVICE` | Default serial when a tool omits `device_id` |
| `RASPILOT_STATE_DIR` | Session directory |
| `RASPILOT_OUTPUT_DIR` | Report directory |
| `RASPILOT_TIMEOUT` | Default tool timeout, in seconds |
| `RASPILOT_MCP_TOKEN` | Bearer token for HTTP transport |
| `RASPILOT_LOG_LEVEL` | Log level (logs go to stderr) |

### Tools

- `raspilot_start_assessment`
- `raspilot_status`
- `raspilot_wait`
- `raspilot_cancel`
- `raspilot_list_sessions`
- `raspilot_get_report`
- `raspilot_get_summary`
- `raspilot_list_resources`
- `raspilot_run_check`
- `raspilot_check_anti_root`
- `raspilot_check_anti_frida`
- `raspilot_check_anti_tampering`
- `raspilot_check_anti_emulator`
- `raspilot_check_anti_hooking`
- `raspilot_check_proxy_vpn`
- `raspilot_bypass_ssl_pinning`
- `raspilot_test_repack` (destructive, two steps)

Typical harness flow:

```text
1. raspilot_start_assessment(package_name="com.example.app", device_id="SERIAL", stage="full")
2. raspilot_wait(session_id="...")
3. raspilot_get_report(session_id="...", format="json")
```

Resources: `raspilot://sessions`,
`raspilot://sessions/{id}/session.json`, `summary.json`, `report.json`,
`report.html`, `static.json` and `checks/{check}.json`.

**Optional HTTP:**

```bash
python mcp_server.py --transport streamable-http --host 127.0.0.1 --port 8000
```

A non-loopback bind requires `--auth-token`/`RASPILOT_MCP_TOKEN`.

## Checks

| Check | What it verifies |
|---|---|
| `anti_root` | root, RootBeer, typical binaries/properties |
| `anti_frida` | Frida artifacts and app reaction |
| `anti_hooking` | hooking frameworks and instrumentation detection |
| `anti_tampering` | APK signature/integrity (repack is destructive) |
| `anti_emulator` | emulator signals |
| `anti_proxy` | proxy/VPN queries and bypass |
| `ssl_pinning` | certificate pinning and bypass |

Each check has two verdicts: **detection** and **bypass**. `SKIP` means
the condition was not exercised — not “OK”. Full semantics are in
[REFERENCE.en.md](REFERENCE.en.md#two-verdicts-per-check).

## Instrumentation module

When the device has a hooking framework, RASPilot can use a generic
Xposed module instead of injecting Frida:

```bash
./instrumentation/build.sh --hook bypass --root bypass --tamper off \
  --emu mask --proxy bypass --out ./module.apk

python main.py --package com.example.app --module-apk ./module.apk \
  --hook-method module --proxy-method module --emulator-method module
```

Build details and layers: [instrumentation/README.md](instrumentation/README.md).

## Repack (destructive)

The repack test uninstalls and reinstalls the app — **app data is
wiped**. Use a disposable device/AVD:

```bash
python main.py --package com.example.app \
  --tamper-method repack --tamper-allow-reinstall \
  --tamper-variant dex --only anti_tampering
```

Prepare the host with:

```bash
./tools/setup_repack.sh
```

## Reports

- JSON/HTML in `reports/` (or `--output-dir`)
- Stable copies inside the session (`report.json`, `summary.json`, `report.html`)
- `summary` contains status, detection and bypass per check
- `metadata.session_id` identifies the session and `metadata.schema_version`
  versions the JSON

Use `--json-only` for automation. Full schema and error/skip/cancel codes
are in [REFERENCE.en.md](REFERENCE.en.md#output).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `adb not found` | Install platform-tools and add it to `PATH` |
| `UNAUTHORIZED` | Accept USB debugging on the device |
| `frida-server did not respond` | `pip install -U frida frida-tools` and retry |
| `Static: timeout` | Increase `--static-timeout` or use `--static-engine builtin` |
| `module build failed` | Install SDK/JDK or use `--module-apk` |
| `apktool not found` | Install apktool 3.x and run `./tools/setup_repack.sh` |
| MCP lists no tools | Confirm `pip install -r requirements-mcp.txt` and the harness command |
| MCP `device_required` | Pass `device_id` or set `RASPILOT_DEVICE` |

## Limitations

- Repack is destructive and does not cover server-side attestation/Play Integrity.
- Static analysis shows attack surface, not behavior.
- The Java layer depends on agent attachment; if the app blocks it, checks
  become `SKIP` with a reason.
- Native coverage is partial (low-volume libc calls; no `strcmp`/`memcmp`).
- Logcat is supporting evidence, not a verdict.

## Development

```bash
pip install -r requirements-dev.txt
pytest -q
```

For architecture, verdict semantics, JSON schema, limitations and the
implementation history, see [REFERENCE.en.md](REFERENCE.en.md).
