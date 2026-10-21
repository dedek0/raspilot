# ✈ RASPilot

> 🇧🇷 [Versão em Português](README.md)

**RASPilot — Automatic RASP Auditing Pilot for Android.**

Orchestrates Anti-Root, Anti-Frida, Anti-Emulator, Anti-Hooking and SSL
Pinning checks against Android apps, producing structured reports ready for
LLM consumption via MCP.

RASPilot connects to an Android device (USB or Wi-Fi ADB), automatically
installs and validates the `frida-server`, runs a RASP verification pipeline
against the target app and produces **JSON** and **HTML** reports with the
status of each protection (`OK` / `FALHOU` / `N/A` / `SKIP` / `ERROR`) and
the collected evidence.

---

## Requirements

### On the host

- Python 3.9+
- `adb` (Android Platform Tools) on `PATH`
- Frida — a compatible `frida-server` is downloaded automatically matching
  the locally installed `frida` package version

### On the Android device

RASPilot runs on a **physical device or an emulator**, with the
requirements below. The closer to a real production environment, the more
useful the result: an emulator does not reproduce hardware-backed
protections.

| Item | Requirement | Why |
|---|---|---|
| Android version | API 24+ (Android 7.0) | the `frida-server` used for auditing does not support older versions |
| Architecture | `arm64-v8a`, `armeabi-v7a`, `x86_64` or `x86` | the `frida-server` is downloaded for the device ABI; `riscv64` is **not** supported |
| USB debugging | enabled in Developer options | `adb` needs to talk to the device |
| Debug authorisation | the "Allow USB debugging" prompt must be accepted | otherwise the device shows up as `unauthorized` and there is no connection |
| Root | **recommended** (Magisk, KernelSU, APatch) | without root the `frida-server` runs as the `shell` uid and some detection vectors (TracerPid, ports, reading another process's `/proc/<pid>/maps`) stay incomplete |
| SELinux | `permissive` is easier; `enforcing` works | under enforcing, `frida-server` needs root to inject into app processes |
| Free space | ~200 MB | `frida-server` (~60 MB) and the APK cache |
| Battery | auditing is CPU intensive | a 20–30 s observation window is enough |

Common setup (all optional, but they change the result):

```bash
# 1) USB debugging + accept the authorisation prompt
# 2) root (Magisk/KernelSU), if available
# 3) ADB over Wi-Fi, to avoid depending on the cable
adb tcpip 5555
```

**Audit environment hygiene.** RASPilot reports what is installed on the
device, and an active hooking tool **contaminates the result**: the log
of an installed hooking framework belongs to the operator, not to the
protection of the audited app. The report keeps those two apart — but for
a clean read, audit on a device without hooking frameworks installed.

### Permissions and artifacts used

RASPilot is **non-destructive**, but it uses the device in an observable
way:

- `/data/local/tmp` — receives the `frida-server` (under an opaque name)
  during the run and is **removed at the end**
- `adb forward` — a local tunnel to the Frida server, torn down at the end
- `logcat` — continuous read of the system buffer
- The target app is **force-stopped** at the end of every run

The `frida-server` and the tunnel are torn down even when the audit fails
halfway through.

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
| `--baseline-window SECS` | no | Uninstrumented baseline window (default `5`) |
| `--no-baseline` | no | Skip the uninstrumented baseline |
| `--mode MODE` | no | Mode: `detect` (observation only), `bypass` (observation+bypass) or `stealth` (native bootstrap before resume) |
| `--no-java` | no | Do not load Java hooks; useful when RASP blocks the Java bridge |
| `--java-timeout SEC` | no | Maximum time to load the Java scripts (default `30`). Bridge loading is dominated by the Java runtime initialisation in the target and by classloader enumeration |
| `--js-runtime RUNTIME` | no | Frida JavaScript runtime: `qjs` (default) or `v8` |
| `--verbose` | no | DEBUG-level logging |
| `--skip CHECK...` | no | Checks to skip (`anti_root`, `anti_frida`, `anti_emulator`, `anti_hooking`, `ssl_pinning`) |

### Output

- Terminal: colored **"RASPilot — Relatório de Auditoria RASP"** summary table
- `reports/<package>_<timestamp>.json` — structured document (metadata,
  summary, details) for LLM/MCP consumption
- `reports/<package>_<timestamp>.html` — visual report with status badges
  and evidence

During dynamic checks RASPilot also captures **logcat**. It is used as an
independent evidence source to correlate deaths (`SIGKILL`, `SIGSEGV`,
`am_kill`, `am_crash`, ANR), security-SDK messages and TLS/pinning errors.
Before any Frida spawn, an **uninstrumented baseline** checks whether the
app already dies by itself, so instrumentation crashes or normal app
lifecycle are not mistaken for a RASP reaction.
Anti-Frida + anti-hooking observation runs in a **single session**, and anti-hooking/SSL bypasses share another spawn. The anti-emulator check runs **last**, with its own spawns: the probe makes the app see an emulator, and a shared spawn would contaminate the other checks. The APK cache lives in `~/.raspilot/cache/apk` (disable with `RASPILOT_APK_CACHE=0`).

Status semantics:

| Status | Meaning |
|---|---|
| `OK` | Environment/protection OK (e.g. SSL pinning resisted the bypass, app detected and blocked Frida/hooking/emulator) |
| `FALHOU` | Threat present or bypass won (e.g. root in the environment, pinning circumvented, app failed to detect Frida or anti-hook/anti-emulator checks) |
| `N/A` | Not applicable: the protection being measured does not exist (e.g. no SSL pinning) |
| `SKIP` | A step did not run: skipped via `--skip`, or the bypass was not evaluated even though the protection exists (reason in `skip_reason`) |
| `ERROR` | Check could not conclude (pipeline continues) — includes inconclusive observation |

> **Golden rule:** RASPilot only claims a protection held when there is
> high-confidence evidence. Generic logcat terms (`root`, `hook`,
> `detected`, `checksum`), logs from hooking frameworks installed on the
> device and the crash of the instrumentation agent itself are context —
> they never support a verdict.
>
> **An app that blocks the audit is a protected app.** When the app
> survives the baseline (uninstrumented) and terminates once instrumented,
> the instrumentation is the trigger for the death: the app blocked the
> audit and the protection is credited as effective. Without a baseline
> proving the app is stable on its own, the death stays inconclusive
> (`ERROR`) — the cause cannot be attributed.
>
> Attribution uses the **crash backtrace** (logcat `crash` buffer, which
> needs no root): a fault inside the Frida agent — or in the ART JNI glue
> it triggers — is a failure of the **instrumentation**, and the verdict
> is then inconclusive, because the app demonstrated no reaction. A
> fault in the app's own code is the app reacting.
>
> The same applies to the bypass: a bypass that was **installed** but
> never **exercised** (no observed TLS request, for instance) does not
> prove that the protection held — the step stays `SKIP`, with the
> reason in `skip_reason`. And a bypass in which the app terminated is
> **not** a bypass that won: the app blocked the audit.

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
- Classic ports (27042/27043) **and the real stealth port** of
  `frida-server` (`netstat`/`ss`/`/proc/net/tcp`)
- Frida modules loaded in the target process (via Frida)
- `gum-js-loop`, `gmain`, `pool-frida` threads (`/proc/<pid>/task`)
- Observation of Frida detection **by the app** (observation hooks on
  `File.exists`, `Runtime.exec`, `ProcessBuilder`, `strstr`/`strcmp`,
  `connect` to Frida ports, `open`/`access`/`stat`/`faccessat` on
  Frida paths and `kill_trace`)
- Correlation with **logcat** and the **uninstrumented baseline**: a death
  becomes detection evidence only with a security signal, a traced kill,
  or when the app did not die in the baseline; without a baseline that
  isolates the cause, the crash stays `ERROR`/inconclusive, not `OK`
- If observation cannot run (script/attach failure), the result is
  `ERROR`, not `vulnerable=True`

`vulnerable=True` ⇒ the app did **not** detect Frida (RASP failure).
The corresponding bypass lives in `scripts/anti_frida_bypass.js`.

### 3. Anti-Emulator (`checks/anti_emulator.py`)

Answers two questions about the **target app** — not about the machine
running the audit:

1. does the app implement anti-emulator protection?
2. can that protection be circumvented?

Phases:

- **Device context**: QEMU properties, kernel files, CPU architecture (x86
  without Chromebook), sensor count, placeholder Bluetooth MAC and specific
  detection for Genymotion/LDPlayer/BlueStacks/Nox/Waydroid. It is
  **informative**: it tells which kind of machine the audit ran on, not
  whether the app is protected.
- **Static detection**: pulls the APK and scans for anti-emulator
  signatures (detection methods/classes of RASP SDKs and fingerprint
  strings such as `ro.kernel.qemu`, `goldfish`, `sdk_gphone`).
- **Dynamic detection (probe)**: suspended spawn with
  `scripts/emulator_spoof.js` in `probe` mode — the app starts to **see an
  emulator** (`Build.*`, `SystemProperties`, `/dev/qemu_pipe`, IMEI,
  `ANDROID_ID`). Every query the app makes to an emulator-sensitive
  primitive is recorded, and the verdict relies on the app's reaction
  (detection verdict, process death, threat log).
- **Bypass (mask)**: another spawn in `mask` mode — the **decisive**
  artifacts (Build, `ro.kernel.qemu`, `/dev/qemu_pipe`) are hidden while
  the **secondary** ones a real emulator still exposes (zeroed IMEI,
  emulator `ANDROID_ID`, carrier "Android") stay visible. That is the
  realistic "emulator with a stealth layer" scenario: if the app still
  reacts, it consults a channel that was not hidden — and the report says
  which one.

`protection_detected=False` ⇒ the app has no observable anti-emulator
checks (RASP failure). `bypass_successful=True` ⇒ the protection exists,
but the bypass won.

When the app kills the **instrumentation agent** (anti-Frida), the
observation is declared **inconclusive**: the death is not attributed to
emulator detection, and the bypass is reported as `SKIP` with the reason
recorded.

### 4. Anti-Hooking (`checks/anti_hooking.py`)

Checks whether the app detects hooking frameworks (Xposed, LSPosed,
EdXposed, Substrate and inline hooks: SandHook, YAHFA, LSPlant, Whale,
Dobby) and whether that protection resists a real bypass. Four independent
phases consolidated into `protection_detected` + `bypass_successful`:

- **Device vectors**: installed packages (`xposed`, `lsposed`, `riru`,
  `substrate`...), modules under `/data/adb` (`/data/adb/modules`,
  `/data/adb/lspd`) and hook libraries mapped into the process (Frida
  session with `/proc/<pid>/maps` fallback). Frida libraries are excluded —
  detecting them is the Anti-Frida check's job.
- **Static detection**: pulls the APK and scans for the signatures RASP
  SDKs use to probe hooks (Xposed classes, LSPosed/lspd/LSPlant, EdXposed,
  Substrate, SandHook/YAHFA/Whale/Dobby and Frida strings).
- **Dynamic observation**: suspended spawn with a script that records
  (without blocking) `Class.forName`/`ClassLoader.loadClass` of framework
  classes, `File.exists` and `open`/`fopen`/`access`/`stat` on framework
  paths and `/proc/*/maps`/`status`, `Runtime.exec`/`ProcessBuilder`,
  native string searches (`strstr`/`strcmp`/`memcmp`) and stack traces
  containing framework frames. Reading `maps`/`status` alone is a **weak**
  signal (it also has legitimate uses); app death during the window is a
  **strong** signal.
- **Bypass** (`scripts/anti_hooking_bypass.js`): a fresh spawn with hooks
  that make `Class.forName` of Xposed classes return `null`, hide
  framework paths/entries (`File.exists`/`File.list`/`File.listFiles`),
  block `Runtime.exec`, strip Xposed frames from stack traces, hide
  strings in `strstr`/`strcmp`/`memcmp`, return `ENOENT` from
  `open`/`access`/`stat` on framework paths, **filter hook library lines
  out of `/proc/self/maps`** (read/fgets) and zero `TracerPid`. The bypass
  only counts as a win with **real evidence** of a neutralized check
  **and** the app staying alive (death = the RASP reacted through another
  vector).

`protection_detected=False` ⇒ the app has no observable anti-hook checks
(RASP failure). `bypass_successful=True` ⇒ the protection exists, but the
bypass won.

### 5. SSL Pinning (`checks/ssl_pinning.py`)

- **Static detection**: pulls the APK (`pm path` + `adb pull`) and scans
  for OkHttp `CertificatePinner`, TrustKit, NetworkSecurityConfig, Flutter
  and Conscrypt/native signatures (binary Manifest, DEX, native libs).
- **Dynamic bypass**: injects `scripts/ssl_bypass.js` (universal) covering
  TrustManager, HostnameVerifier, OkHttp 3/4, NSC, Conscrypt, Apache
  HttpClient, WebView, BoringSSL/OpenSSL and Flutter. Bypass is only
  considered successful with a **real intercepted host and a live app**;
  hook-install/native-config logs are diagnostics only. Logcat is attached
  to corroborate TLS/pinning errors.

---

## Repository structure

```
raspilot/
├── main.py                     # CLI + auditing pipeline
├── device_manager.py           # ADB (USB/Wi-Fi) + frida-server + logcat/baseline
├── logcat_analyzer.py          # Death/security/TLS logcat correlation
├── reporter.py                 # JSON/HTML reports (Jinja2)
├── checks/
│   ├── anti_root.py            # Multi-vector root detection
│   ├── anti_frida.py           # Frida presence/detection
│   ├── anti_emulator.py        # Anti-emulator detection + bypass
│   ├── anti_hooking.py         # Anti-hooking detection + bypass
│   ├── combined.py             # Single-session observation/bypass
│   ├── stealth.py              # Native bootstrap before resume
│   ├── apk_utils.py            # Shared APK helpers + APK cache
│   └── ssl_pinning.py          # SSL pinning detection + bypass
├── scripts/
│   ├── ssl_bypass.js           # Universal SSL pinning bypass (Frida)
│   ├── anti_frida_bypass.js    # Frida detection bypass (Frida)
│   ├── anti_hooking_bypass.js  # Hooking detection bypass (Frida)
│   ├── emulator_spoof.js       # Emulator spoof: probe and mask (Frida)
│   ├── verdict_hook.js         # Neutralises the RASP threat callback
│   └── anti_root_bypass.js     # Root detection bypass (Frida)
├── rasp_vendors.py             # Catalogue of known RASP SDKs
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
a schema snapshot, pinning and anti-hooking detection on synthetic APKs, the
evidence model (high confidence vs context), the bypass layer and the full
end-to-end pipeline (with a mocked `DeviceManager`). No physical device is
required to run the tests.

Every test has a time ceiling: a test that freezes turns into a failure
with the stack of all threads, instead of holding the machine indefinitely.

There is also a **device test** for the SSL pinning bypass, which needs a
connected device and an installed app:

```bash
python tests/device_smoke.py --package <package>
```

It starts an HTTPS server with a self-signed certificate on the host and
makes a request through the app's JVM. The test requires the request to
**fail** without the bypass and **succeed** with it — the negative
control is what proves the bypass is the reason.

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
| `raspilot_check_anti_emulator(device_id, package_name) -> dict` | `AntiEmulatorCheck(dm).run_all(package)` |
| `raspilot_check_anti_hooking(device_id, package_name) -> dict` | `AntiHookingCheck(dm).run_all(package)` |
| `raspilot_bypass_ssl_pinning(device_id, package_name) -> dict` | `SSLPinningCheck(dm).run_all(package)` |
| `raspilot_get_report() -> dict` | `Reporter.generate_json()` |

The JSON emitted by RASPilot already follows a stable schema
(`metadata` / `summary` / `details`) designed for direct LLM reading.
`metadata.schema_version` detects incompatible changes and
`metadata.run` records the execution context (CLI arguments, Frida
version, port, sha256 hashes of the injection scripts, target pid and
baseline result) so the run can be reproduced.

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

---

## Known limitations

**The Java layer depends on the agent attaching to the app's virtual
machine.** The Java bridge obtains the `JNIEnv` of the instrumentation
thread. When a protection aborts or blocks that attachment, the Java
layer simply does not come up: the checks that depend on it end up
`SKIP` with the reason in `skip_reason`, and the native layer still
holds. This is per-app behaviour and needs a workaround specific to the
SDK.

**Self-destruction neutralisation is on by default.** RASP techniques
that abort the process or stop it with a signal are intercepted in the
native layer, so the observation window does not end prematurely. The
neutralised actions are listed in
`details.<check>.<phase>.neutralized_actions` — they are evidence of
what the app tried to do, not a detection of the app.

**The logcat is supporting evidence, never a verdict.** Generic terms
(`root`, `hook`, `detected`) and logs from operator tooling support no
conclusion. See *Status semantics*.

**The native evasion only covers low-volume entry points.** The libc
string functions (`strcmp`, `memcmp`) are called tens of thousands of
times per second by the app runtime and by the instrumentation agent's
own JavaScript engine. A hook at those points consumes the agent's time
and it stops responding — the symptom is a session that freezes without
an error. The native layer therefore concentrates on low-volume
functions (`strstr`, `raise`, `kill`, `abort`, `exit`); exact name
matching stays covered by the Java layer and by the `/proc` filter.

**Classes generated by the Java layer depend on the cache directory.**
The bridge writes the temporary class to a directory of its own; its
default is not writable by the app process and the registration fails.
The app's directory is applied at the point of use — the bridge resets
the value when it initialises, and that can happen after the script has
been loaded.

## License and usage

Security auditing tool for **authorized** use only (apps and devices under
your control or within a contracted testing scope).
