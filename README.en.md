# ✈ RASPilot

> 🇧🇷 [Versão em Português](README.md)

**RASPilot — Automatic RASP Auditing Pilot for Android.**

Orchestrates Anti-Root, Anti-Frida, Anti-Emulator and SSL Pinning checks
against Android apps, producing structured reports ready for LLM consumption
via MCP.

RASPilot connects to an Android device (USB or Wi-Fi ADB), automatically
installs and validates the `frida-server`, runs a RASP verification pipeline
against the target app and produces **JSON** and **HTML** reports with the
status of each protection (`OK` / `FALHOU` / `N/A` / `SKIP` / `ERROR`) and
the collected evidence.

---

## Requirements

- Python 3.9+
- `adb` (Android Platform Tools) on `PATH`
- Android device with **USB Debugging** enabled (physical or emulator)
- Frida — a compatible `frida-server` is downloaded automatically matching
  the locally installed `frida` package version

## Installation

```bash
git clone <repo> raspilot && cd raspilot
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# test dependencies (optional)
pip install -r requirements-dev.txt
```

Quick check:

```bash
python main.py --version
adb devices   # should list your device as "device"
```

## Usage

```bash
# USB — first available device
python main.py --package com.example.app

# Wi-Fi ADB
python main.py --package com.example.app --wifi 192.168.0.10:5555

# Specific device + verbose + custom output dir
python main.py --package com.example.app \
    --device-id emulator-5554 \
    --output-dir ./my_reports \
    --verbose

# Longer observation window (seconds) for dynamic checks
python main.py --package com.example.app --window 20

# Skip checks
python main.py --package com.example.app --skip anti_emulator ssl_pinning
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--package` | yes | Target app package name (e.g. `com.example.app`) |
| `--device-id` | no | ADB serial (e.g. `emulator-5554`) |
| `--wifi HOST:PORT` | no | Address for `adb connect` |
| `--output-dir` | no | Reports directory (default `reports/`) |
| `--window SECS` | no | Observation window in seconds for dynamic checks (default `15`) |
| `--verbose` | no | DEBUG-level logging |
| `--skip CHECK...` | no | Checks to skip (`anti_root`, `anti_frida`, `anti_emulator`, `ssl_pinning`) |

### Output

- Terminal: colored **"RASPilot — Relatório de Auditoria RASP"** summary table
- `reports/<package>_<timestamp>.json` — structured document (metadata,
  summary, details) for LLM/MCP consumption
- `reports/<package>_<timestamp>.html` — visual report with status badges
  and evidence

Status semantics:

| Status | Meaning |
|---|---|
| `OK` | Environment/protection OK (e.g. physical device, SSL pinning resisted the bypass, app detected and blocked Frida) |
| `FALHOU` | Threat present or bypass won (e.g. root/emulator in the environment, pinning circumvented, app failed to detect Frida) |
| `N/A` | Not applicable (e.g. no SSL pinning — bypass does not apply) |
| `SKIP` | Check skipped via `--skip` |
| `ERROR` | Check could not run (pipeline continues) |

> **Important:** RASPilot **does not permanently modify** the device.
> After each run it stops the `frida-server`, removes
> `/data/local/tmp/frida-server` and force-stops the target app.

---

## Checks

### 1. Anti-Root (`checks/anti_root.py`)

Multiple independent vectors consolidated into `is_rooted` + `confidence`:

- `su` binaries across 7 canonical paths
- Magisk (package, `/data/adb/magisk`, `/sbin/.magisk`, `which magisk`)
- APatch and KernelSU (`me.bmax.apatch`, `me.weishu.kernelsu`, `/data/adb/ap`,
  `/data/adb/ksu`, `apd`, `ksud`)
- Build properties (`ro.debuggable`, `ro.secure`, `service.adb.root`,
  `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`)
- Root manager apps (Magisk, SuperSU, KingRoot, APatch, KernelSU...)
- `/system` mounted `rw`
- Busybox

Confidence: `high` (≥2 vectors), `medium` (1), `low` (0).

### 2. Anti-Frida (`checks/anti_frida.py`)

- Processes (`ps -A | grep frida`)
- Ports 27042/27043 (`netstat`/`ss`/`/proc/net/tcp`)
- Frida modules loaded in the target process (via Frida)
- `gum-js-loop`, `gmain`, `pool-frida` threads (`/proc/<pid>/task`)
- Observation of Frida detection **by the app** (observation hooks on
  `File.exists`, `Runtime.exec`, `ProcessBuilder`, `strstr`/`strcmp`,
  `connect` to Frida ports and `open`/`access`/`stat`/`faccessat` on
  Frida paths)
- During the observation window the process is monitored: if the app
  terminates (typical RASP reaction to a detected threat), that becomes
  evidence and the verdict flips to `vulnerable=False`

`vulnerable=True` ⇒ the app did **not** detect Frida (RASP failure).
The corresponding bypass lives in `scripts/anti_frida_bypass.js`.

### 3. Anti-Emulator (`checks/anti_emulator.py`)

Combines QEMU properties, kernel files, CPU architecture (x86 without
Chromebook), sensor count, placeholder Bluetooth MAC and specific detection
for Genymotion/LDPlayer/BlueStacks/Nox/Waydroid. Classifies
`emulator_type` (`qemu_avd`, `genymotion`, `ldplayer`, `bluestacks`,
`nox`, `waydroid`) with confidence.

### 4. SSL Pinning (`checks/ssl_pinning.py`)

- **Static detection**: pulls the APK (`pm path` + `adb pull`) and scans
  for OkHttp `CertificatePinner`, TrustKit, NetworkSecurityConfig, Flutter
  and Conscrypt/native signatures (binary Manifest, DEX, native libs).
- **Dynamic bypass**: injects `scripts/ssl_bypass.js` (universal) covering
  TrustManager, HostnameVerifier, OkHttp 3/4, NSC, Conscrypt, Apache
  HttpClient, WebView, BoringSSL/OpenSSL and Flutter. Bypass is only
  considered successful with **real evidence** (intercepted host or a
  `check()` circumvention log). The process is monitored during the
  window — if the app terminates, that is recorded in the result.

---

## Repository structure

```
raspilot/
├── main.py                     # CLI + auditing pipeline
├── device_manager.py           # ADB (USB/Wi-Fi) + frida-server lifecycle
├── reporter.py                 # JSON/HTML reports (Jinja2)
├── checks/
│   ├── anti_root.py            # Multi-vector root detection
│   ├── anti_frida.py           # Frida presence/detection
│   ├── anti_emulator.py        # Emulator classification
│   └── ssl_pinning.py          # SSL pinning detection + bypass
├── scripts/
│   ├── ssl_bypass.js           # Universal SSL pinning bypass (Frida)
│   ├── anti_frida_bypass.js    # Frida detection bypass (Frida)
│   └── anti_root_bypass.js     # Root detection bypass (Frida)
├── templates/report.html.j2    # HTML report template
├── reports/                    # Report output
└── tests/                      # pytest suite (100% mocked, no device)
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

The suite covers: ADB output parsing (mocked `subprocess.run`), `run_all`
consolidation of each check with mocked data, JSON report generation against
a schema snapshot, pinning detection on synthetic APKs and the full
end-to-end pipeline (with a mocked `DeviceManager`). No physical device is
required to run the tests.

---

## MCP integration (next phase — planned)

Every check's `run_all()` is a pure function: it receives an injected
`DeviceManager` and returns a `dict`, with no global side effects — ready to
be wrapped as MCP tools with `FastMCP`:

| Planned MCP tool | Internal mapping |
|---|---|
| `raspilot_start_assessment(package_name, device_id=None) -> dict` | `DeviceManager.connect_adb()` + `setup_frida_server()` + pipeline |
| `raspilot_check_anti_root(device_id) -> dict` | `AntiRootCheck(dm).run_all()` |
| `raspilot_check_anti_frida(device_id) -> dict` | `AntiFridaCheck(dm).run_all(session, pid)` |
| `raspilot_check_anti_emulator(device_id) -> dict` | `AntiEmulatorCheck(dm).run_all()` |
| `raspilot_bypass_ssl_pinning(device_id, package_name) -> dict` | `SSLPinningCheck(dm).run_all(package)` |
| `raspilot_get_report() -> dict` | `Reporter.generate_json()` |

The JSON emitted by RASPilot already follows a stable schema
(`metadata` / `summary` / `details`) designed for direct LLM reading.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `adb` not found | Platform Tools not on PATH | Install and add `adb` to PATH |
| `Dispositivo AUNAUTHORIZED` | USB debugging not confirmed | Accept the prompt on the device |
| `frida-server não respondeu` | Local version ≠ server version | `pip install -U frida frida-tools` and rerun |
| `Dispositivo não ficou pronto em 15s` | Offline/connection issue | Check cable / `adb kill-server` |
| App spawned but checks empty | App protected against debuggers | Use `--verbose` and inspect `details` in the JSON |
| Window too short for slow apps | Long splash or late RASP checks | Increase with `--window 20` (or more) |

## License and usage

Security auditing tool for **authorized** use only (apps and devices under
your control or within a contracted testing scope).
