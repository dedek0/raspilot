# ✈ RASPilot

> 🇧🇷 [Versão em Português](README.md)

**RASPilot — Automatic RASP Auditing Pilot for Android.**

Orchestrates Anti-Root, Anti-Frida, Anti-Tampering, Anti-Emulator,
Anti-Hooking and SSL Pinning checks against Android apps, producing structured reports ready for
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
- Android SDK (`build-tools` + `platform`) and a JDK — to build the
  instrumentation module and for repack (`zipalign`, `apksigner`,
  `keytool`). Without them RASPilot keeps working with the `frida`
  method (see *Instrumentation module*). The toolchain is installed
  without system privileges: `./instrumentation/setup_toolchain.sh`
  (requirements in `instrumentation/requirements.txt`).
- `apktool` 3.x — required by the `dex`, `resource`, `manifest` and
  `gadget` repack variants.
- **Optional:** Frida Gadget for the device ABI — only for the `gadget`
  variant. `tools/setup_repack.sh` downloads the version matching the
  installed `frida` package.
- **Optional:** the app's original keystore (`--tamper-key`) to test
  modified content under the same signer. Without it, repack uses a
  debug key.
- **Optional:** Droid ASC (`pip install -r requirements-static.txt`,
  Python 3.10+) for semantic APK analysis. Without it RASPilot uses the
  built-in byte-signature scan.

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
| Free space | ~200 MB for normal audits; 1–6 GB for repack | `frida-server` (~60 MB), APK cache and repack artifacts |
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

RASPilot is **non-destructive by default**, but it uses the device in an
observable way. The repack test is the exception: it is **opt-in**,
uninstalls/reinstalls the app and erases app data.

- `/data/local/tmp` — receives the `frida-server` (under an opaque name)
  during the run and is **removed at the end**
- `adb forward` — a local tunnel to the Frida server, torn down at the end
- `logcat` — continuous read of the system buffer
- The target app is **force-stopped** at the end of every run
- During repack the app is uninstalled/reinstalled; original APKs are
  kept and restored at the end, but **app data is not restored**

The `frida-server` and the tunnel are torn down even when the audit fails
halfway through.

## Installation

```bash
git clone <repo> raspilot && cd raspilot
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# test dependencies (optional)
pip install -r requirements-dev.txt
# semantic static analysis (optional, requires Python 3.10+)
pip install -r requirements-static.txt

# repack + Frida Gadget setup (optional)
./tools/setup_repack.sh --abi arm64-v8a
```

`setup_repack.sh` validates `adb`, `apktool`, `zipalign`/`apksigner`,
`keytool`, `curl`/`xz` and the `frida` package; creates `~/.raspilot/keys`,
`~/.raspilot/gadgets` and `~/.raspilot/repack`; and downloads the Frida
Gadget matching the Python `frida` version for the device ABI. It does
not install system packages: it reports what is missing and how to fix it.

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
| `--stage STAGE` | no | `full` (default), `static` (APK only, no Frida), `detect` (detection only, no bypass) or `bypass` (detection + bypass) |
| `--only CHECK` | no | Run only the given check; repeatable. E.g. `--only anti_frida --only anti_root` |
| `--apk PATH` | no | Local target APK (skips `adb pull`); required for `--stage static` without a device |
| `--json-only` | no | Write only JSON, no HTML (automation/MCP) |
| `--window SECS` | no | Observation window in seconds for dynamic checks (default `15`) |
| `--baseline-window SECS` | no | Uninstrumented baseline window (default `5`) |
| `--no-baseline` | no | Skip the uninstrumented baseline |
| `--mode MODE` | no | Mode: `detect` (observation only), `bypass` (observation+bypass) or `stealth` (native bootstrap before resume) |
| `--no-java` | no | Do not load Java hooks; useful when RASP blocks the Java bridge |
| `--java-timeout SEC` | no | Maximum time to load the Java scripts (default `30`). Bridge loading is dominated by the Java runtime initialisation in the target and by classloader enumeration |
| `--hook-method METHOD` | no | Anti-hook bypass: `frida` (injected agent), `module` (hooking APK on the device, scoped to the target package) or `auto` (default: uses the module when a framework is available) |
| `--emulator-method METHOD` | no | Anti-emulator probe/bypass: `frida`, `module` or `auto` (default) |
| `--module-apk PATH` | no | Pre-built instrumentation module APK (skips the build, which requires the Android SDK) |
| `--static-engine ENGINE` | no | APK static analysis: `auto` (default; ASC when installed, otherwise byte scan), `asc` (require Droid ASC), `builtin` (byte scan only) or `off` |
| `--static-timeout SEC` | no | Timeout per Droid ASC query (default `60`) |
| `--js-runtime RUNTIME` | no | Frida JavaScript runtime: `qjs` (default) or `v8` |
| `--verbose` | no | DEBUG-level logging |
| `--skip CHECK...` | no | Checks to skip (`anti_root`, `anti_frida`, `anti_tampering`, `anti_emulator`, `anti_hooking`, `ssl_pinning`) |
| `--tamper-method METHOD` | no | `auto` (default; static + module/Frida probe), `static` (APK only), `frida` (in-memory probe only) or `repack` (destructive) |
| `--tamper-allow-reinstall` | no | Confirms repack may uninstall/reinstall the app; data is lost |
| `--tamper-variant VARIANT` | no | `asset`, `dex`, `resource`, `manifest`, `gadget` or `all`; repeatable. Default: `asset` and `dex`; `all` includes gadget (skipped when no binary) |
| `--tamper-installer PKG` | no | Installer simulated during repack (e.g. `com.android.vending`); default: current installer |
| `--tamper-no-restore` | no | Do not reinstall the original APK at the end |
| `--tamper-keep-artifacts` | no | Keep original/modified APKs under `reports/repack/` |
| `--tamper-timeout SECS` | no | Timeout per repack build (default `600`) |
| `--tamper-gadget PATH` | no | Frida Gadget `.so`/`.so.xz` for the `gadget` variant; default: `~/.raspilot/gadgets/` |
| `--tamper-gadget-port PORT` | no | Local Gadget port (default `27043`) |
| `--tamper-gadget-mode MODE` | no | `listen` (host connects), `wait` (app waits) or `script` (runs embedded script) |
| `--tamper-gadget-script PATH` | no | Embedded JS script for the `gadget` variant in `script` mode |
| `--tamper-key PATH` | no | Original keystore to preserve the signer; otherwise uses the debug key |
| `--tamper-key-alias ALIAS` | no | Original key alias (default `raspilot`) |
| `--tamper-key-pass PASS` | no | Original key password (default `android`) |
| `--tamper-store-pass PASS` | no | Original keystore password (default `android`) |
| `--avd` | no | Audit against the configured AVD instead of the physical device (boots the emulator, waits for boot and shuts it down afterwards) |
| `--avd-config PATH` | no | JSON configuration of the emulated environment (default `~/.raspilot/avd.json` or `$RASPILOT_AVD_CONFIG`) |
| `--avd-name NAME` | no | AVD name, overriding the configuration |
| `--avd-check` | no | Validate the emulated environment and show what is missing (no audit) |

### Default mode

Without explicit flags RASPilot runs with:

- `--mode bypass` — observe and attempt evasion;
- `--static-engine auto` — ASC when installed, otherwise byte scan;
- `--hook-method auto` / `--emulator-method auto` — module when a
  framework is available, otherwise Frida; anti-root follows the same
  preference (module first, Frida fallback);
- `--window 15` — observation window;
- `--static-timeout 60` — per-ASC-query timeout.

Anti-Frida bypass runs by default in `bypass` mode: it first measures
detection, then opens a separate spawn with native evasion. The weak SSL
probe uses a minimum 20s window and `uiautomator`/`monkey` navigation.
To disable, use `--static-engine off` and/or `--skip`.

### Staged analysis

To split the audit into phases:

```bash
# 1) static profile only; no Frida, no device needed
python main.py --package com.example.app \
    --apk ./app.apk --stage static --output-dir reports/stages

# 2) dynamic detection only (root/Frida/tampering/hooking/emulator/SSL), no bypass
python main.py --package com.example.app --stage detect

# 3) detection + bypass (full behavior)
python main.py --package com.example.app --stage bypass

# 4) a single check
python main.py --package com.example.app --stage detect --only anti_frida

# 5) automation/MCP: JSON only, no HTML
python main.py --package com.example.app --json-only
```

`--stage static` writes its own JSON (`..._static.json`) with `metadata`
and `static_profile`. `--stage detect` forces `--mode detect`. `--only`
is an allow-list; the other checks appear as `SKIP`. Persistent
session/state across stages belongs to the next roadmap phase.

### Output

- Terminal: colored **"RASPilot — Relatório de Auditoria RASP"** summary
  table followed by the **execution log** (what each check attempted,
  what it found and the reported status)
- `reports/<package>_<timestamp>.json` — structured document
  (`metadata`, `summary`, `execution_log`, `details`) for LLM/MCP
  consumption. Each `summary` item has `status`, `detection` and `bypass`;
  current schema is **5**.
- `reports/<package>_<timestamp>.html` — visual report with status badges,
  the **Detection × Bypass** table, evidence and the same execution trace

`execution_log` is a list of steps shaped as
`{check, phase, action, outcome, details, evidence, reported_status}`.
Phases are `context` (audit environment), `static` (APK analysis),
`detection` (runtime observation), `bypass` and `verdict`. Outcomes are
`detected`, `not_detected`, `success`, `blocked`, `resisted`,
`inconclusive`, `skipped`, `not_applicable` and `error`; `reported_status`
repeats the final verdict (`OK`/`FALHOU`/`SKIP`/`N/A`/`ERROR`).

During dynamic checks RASPilot also captures **logcat**. It is used as an
independent evidence source to correlate deaths (`SIGKILL`, `SIGSEGV`,
`am_kill`, `am_crash`, ANR), security-SDK messages and TLS/pinning errors.
Before any Frida spawn, an **uninstrumented baseline** checks whether the
app already dies by itself, so instrumentation crashes or normal app
lifecycle are not mistaken for a RASP reaction.
Before any spawn, an **APK static profile** is built once and shared by the
checks: byte-signature scan (always) + decoded manifest, class list and
method references via Droid ASC (when installed). The profile is cached
by APK hash and separates "the app has no protection" from "the bypass
beat the protection", while also flagging gaps in bypass-hook coverage.
It does **not** replace dynamic observation: presence in the APK is not
proof of execution.

Anti-Frida + anti-hooking observation runs in a **single session**, and anti-hooking/SSL bypasses share another spawn. Anti-tampering runs a control phase and a second phase with an in-memory package signature change, preferably through the module (`TamperShield`) with Frida fallback. Anti-Frida detection and bypass use separate spawns: first the app reaction is measured; then native evasion is loaded before resume. The anti-emulator check runs **last**, with its own spawns: the probe makes the app see an emulator, and a shared spawn would contaminate the other checks. The APK cache lives in `~/.raspilot/cache/apk` (disable with `RASPILOT_APK_CACHE=0`); the static profile cache lives in `~/.raspilot/cache/static` (disable with `RASPILOT_STATIC_CACHE=0`).

Status semantics:

| Status | Meaning |
|---|---|
| `OK` | Environment/protection OK (e.g. SSL pinning resisted the bypass, app detected and blocked Frida/hooking/emulator) |
| `FALHOU` | Threat present or bypass won (e.g. root in the environment, pinning circumvented, anti-hook/anti-emulator protection exists but the bypass got through) |
| `N/A` | Not applicable: the protection being measured does not exist (e.g. no SSL pinning, or no high-confidence anti-Frida reference in the APK and no runtime detection) |
| `SKIP` | A step did not run: skipped via `--skip`, or the bypass was not evaluated even though the protection exists (reason in `skip_reason`) |
| `ERROR` | Check could not conclude (pipeline continues) — includes inconclusive observation |

> **Anti-Frida:** when the static profile is available and finds **no**
> high-confidence Frida reference, and the app does not react at runtime,
> the status becomes `N/A` (there was no protection to beat). If the APK
> references the check but the app does not react, the status stays
> `FALHOU`: the protection exists in code but was not observed in the
> window. The reason is stored in `verdict_reason`. When evasion runs, the
> final status follows `bypass_successful`: `True` ⇒ `FALHOU` (RASP
> bypassed), `False` ⇒ `OK` (protection resisted evasion).

> **Anti-Root:** `is_rooted` remains the **device** verdict and stays in
> the summary. When the in-app phase runs, `protection_detected` and
> `bypass_successful` determine the app protection status; if the Java
> bridge cannot load, the bypass is `SKIP` with the reason, without
> claiming the app does not detect root.

### Two verdicts per check

Besides the consolidated `status`, every check publishes `detection` and
`bypass`:

| Field | Values | Meaning |
|---|---|---|
| `detection.status` | `detected` | protection observed at runtime |
| | `indicated` | static indication, not dynamically confirmed |
| | `suspected` | weak indication (e.g. weak SSL), unconfirmed |
| | `not_detected` | no protection observed |
| | `inconclusive` | observation did not conclude |
| | `not_applicable` | check skipped/no target |
| | `error` | analysis error |
| `bypass.status` | `bypassed` | evasion won (RASP bypassed) |
| | `resisted` | protection resisted evasion |
| | `not_exercised` | protection existed, bypass was not exercised |
| | `not_applicable` | no protection to bypass |
| | `error` | bypass error |

The Portuguese labels (`Detectado`, `Bypass venceu`, `Proteção
resistiu`, `Não exercitado`, etc.) are for terminal/HTML display. JSON
consumers should use the `status` values.

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

### 0. Static APK analysis (`checks/static/`)

The static profile is built once per run and shared by all six checks.
It has two layers:

1. **Byte scan (always available)** — reads `AndroidManifest.xml`,
   `*.dex`, `lib/**/*.so`, `assets/flutter_assets*` and `res/xml/*` and
   looks for ASCII/UTF-16LE signatures. It is the same base already used
   by the checks, now consolidated into one pass.
2. **Droid ASC (optional)** — runs `getmanifest`, `listclass` and a
   curated set of `findrefs` queries to find **which class/method**
   references the API or string. This is what turns "the APK contains
   the string" into "class `X` references `X509TrustManager`".

For each vector (`frida`, `hooking`, `root`, `emulator`, `pinning`, `tamper`) the
profile records `present`, `confidence`, `findings` (source, class,
method, evidence) and `possible_gaps` — techniques the current bypass
scripts do not cover, such as native BoringSSL pinning or native
`/proc/self/maps` reads. Static presence is **not** treated as proof of
execution.

Confidence is calibrated to avoid false positives: bundled
`okhttp`/Flutter/Conscrypt do not count as pinning; a custom
`X509TrustManager` only counts with a pinning hint; a lone `getStackTrace`
does not count as anti-hook; and a generic `frida` string does not count
as anti-Frida.

Each finding also receives an **owner**: `app`, `rasp_sdk`,
`third_party_sdk`, `framework`, `library` or `unknown` (obfuscated code).
The report exposes `static_owners` and `app_evidence` to separate an app
check from a bundled library or third-party SDK class.

The ASC runs as a subprocess with a timeout and per-APK cache. Without
it (or with `--static-engine builtin`) RASPilot keeps working with the
byte scan and records the limitation in the report. Cache lives in
`~/.raspilot/cache/static` and can be disabled with
`RASPILOT_STATIC_CACHE=0`.

Limitations: ASC reads the installed APK; native code, packed DEX and
runtime-loaded DEX are not covered. A referenced string may live in dead
code. The profile is surface evidence, not behaviour evidence.

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

Besides the device verdict, the check measures the **app's root
detection** and attempts a bypass:

- **Module (Xposed/LSPosed)**: when available, observes RootBeer, `File`,
  `Runtime.exec`, `SystemProperties` and `PackageManager` without an
  external Frida agent; the bypass neutralizes those APIs via the module.
- **Frida observation**: loads `root_detection.js` natively before resume
  and Java afterwards; covers the case where the app blocks the bridge.
- **Frida bypass**: `anti_root_bypass.js` has a native layer (paths,
  `strstr`/`strcmp`, `__system_property_get`) before resume and a Java
  layer (RootBeer/File/exec/SystemProperties) afterwards.
  `bypass_successful=True` ⇒ RASP bypassed (`FALHOU`); `False` ⇒
  protection resisted (`OK`); `None` ⇒ not exercised (`SKIP`).

`is_rooted` remains the **device** verdict. The report shows
`protection_detected`, `bypass_successful` and
`app_root_detection.dynamic_detected` separately, so "rooted device" is
not confused with "app detects root".

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
- **Static analysis**: APK signatures (`frida` as a whole word,
  `gum-js-loop`, `libfrida`, `linjector`, `frida-gadget`) and, via ASC,
  class/method references. Generic references (UI text, app name) stay at
  low/medium confidence and do not enter the verdict; only high-confidence
  evidence (detection context, `gum-js-loop`, `linjector`, `libfrida`)
  counts as anti-Frida protection.
- **Bypass (evasion)**: after detection, a fresh spawn loads
  `proc_filter.js` + `anti_frida_bypass.js` before resume. Hooks cover
  `strstr`, `strcmp`, `strncmp` and `memcmp` (fast-path by size/first
  byte), Frida paths/ports, thread names, self-termination
  (`raise`/`abort`/`kill`/`exit`) and direct `syscall` for
  `exit_group`/`kill`/`tkill`/`tgkill`. Detection and evasion are separate
  results: `bypass_successful=True` ⇒ the app survived without reacting
  (RASP bypassed); `False` ⇒ the protection resisted evasion.

`vulnerable=True` ⇒ the app did **not** detect Frida (RASP failure).
When the static profile is available and finds no high-confidence
anti-Frida protection, and the app does not react either, the check
returns `N/A` instead of `FALHOU` — there was no protection to beat. If
the APK references the check but the app does not react, the verdict
stays `FALHOU` and the reason is stored in `verdict_reason`.
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
- **Static detection**: anti-emulator signatures (detection
  methods/classes of RASP SDKs and fingerprint strings such as
  `ro.kernel.qemu`, `goldfish`, `sdk_gphone`), enriched by the ASC
  profile (`SystemProperties.get` refs, SDK classes and so on).
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

With `--emulator-method module` (the default when a hooking framework is
available on the device) the probe and the mask run **without** external
instrumentation: the app runs normally while the module performs the
spoof. That removes the agent death as a confounding factor — the verdict
reflects the app's reaction to the emulated environment, not to the tool.

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
- **Static detection**: scans for the signatures RASP SDKs use to probe
  hooks (Xposed classes, LSPosed/lspd/LSPlant, EdXposed, Substrate,
  SandHook/YAHFA/Whale/Dobby and Frida strings), enriched by the ASC
  profile (`findrefs` of `XposedBridge`, `org.lsposed`, `getStackTrace`
  and framework classes).
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

Anti-hook detection uses only hooking artifacts (Xposed, LSPosed,
Substrate, SandHook/YAHFA/LSPlant/Whale/Dobby, Riru/Zygisk). Frida
artifacts belong to the anti-Frida vector: an app death during
instrumentation is **not** credited to anti-hook without a specific
anti-hook signal.

With `--hook-method module` (the default when a hooking framework is
available on the device) the observation and the bypass run **without**
external instrumentation: the module is scoped to the target package,
records the app's anti-hook queries and neutralises them. The verdict then
rests on the app's reaction to the device's own hooking framework — the
vector the protection actually inspects.

### 5. SSL Pinning (`checks/ssl_pinning.py`)

- **Static detection**: scans the APK (`pm path` + `adb pull`) for OkHttp
  `CertificatePinner`, TrustKit, NetworkSecurityConfig, Flutter and
  Conscrypt/native signatures (binary Manifest, DEX, native libs). With
  ASC the manifest is decoded (`networkSecurityConfig`, `debuggable`) and
  `findrefs impl X509TrustManager` locates custom TrustManagers.
  References inside the bundled library (okhttp/TrustKit) do not count as
  app usage.
- **Weak evidence**: if only weak indicators exist (custom TrustManager,
  `networkSecurityConfig` without `pin-set`, BoringSSL) and a plausible
  native gap, the bypass runs as a **probe** with a minimum 20s window and
  directed navigation: `uiautomator` taps clickable nodes of the app and
  falls back to `monkey` when no dump is available. Without TLS traffic
  the result is `SKIP`; with intercepted traffic the report records
  `tls_observed=true` and keeps `pinning_detected=false` (pinning was not
  confirmed from the APK).
- **Dynamic bypass**: injects `scripts/ssl_bypass.js` (universal) covering
  TrustManager, HostnameVerifier, OkHttp 3/4, NSC, Conscrypt, Apache
  HttpClient, WebView, BoringSSL/OpenSSL and Flutter. Bypass is only
  considered successful with a **real intercepted host and a live app**;
  hook-install/native-config logs are diagnostics only. Logcat is attached
  to corroborate TLS/pinning errors.

### 6. Anti-Tampering (`checks/anti_tampering.py`)

Two non-destructive layers, plus the opt-in destructive repack described below:

- **Static**: scans the APK for `GET_SIGNATURES`,
  `GET_SIGNING_CERTIFICATES`, `PackageInfo.signatures`,
  `checkSignatures`, `SigningInfo`, `MessageDigest`, CRC/checksum,
  `getPackageCodePath` and Play Integrity/SafetyNet references.
- **In-memory dynamic**: runs a control phase with no change and a second
  phase with the package signature altered in memory
  (`PackageManager.getPackageInfo` and `checkSignatures`). If the app dies
  or blocks only in the second phase, the anti-tampering protection was
  exercised; if it stays alive and usable, the bypass won. When the
  instrumentation module is available the probe runs through it
  (`TamperShield`), without Frida's Java bridge; otherwise it uses Frida.

The result has two verdicts: **detection** (`tamper_detected`) and
**bypass** (`bypass_successful`). `--mode detect` and `--tamper-method
static` skip the dynamic probe; `--no-java` also blocks it. The method is
explicit in `bypass_method` (`module` or `frida`).

### 6.1. Repack test (`checks/tamper_repack.py`)

The opt-in destructive test answers whether the app detects a modified,
re-signed APK. Flow:

1. pull and keep the original APKs (base + splits);
2. observe the original app as control;
3. install a **re-signed control with unchanged content**;
4. install content-modified re-signed variants;
5. restore the original APK at the end.

Variants:

- `asset` — add a marker asset (tests ZIP/CRC/asset integrity);
- `dex` — add a harmless smali class and rebuild DEX (tests DEX integrity);
- `resource` — add a resource (tests `resources.arsc`);
- `manifest` — add a harmless meta-data (tests the manifest);
- `gadget` — inject Frida Gadget + config and a provider that loads the
  library on a background thread; tests whether the app accepts the
  instrumentation payload. Modes: `listen` (host connects), `wait` (app
  waits) and `script` (embedded JS with an execution marker). A
  `gadget-control` injects the provider and libs without loading Gadget,
  separating provider/manifest detection from payload failure.

Observations also record `ui`/`ui_signals` (text and possible block
screens) and `server_signals` (death/security/TLS/vendor counts). A weak
signal never becomes a verdict on its own.

The control matrix avoids blaming repack for a crash caused only by the
signature change, installer or apktool rebuild. In addition to the
`resigned` control, apktool variants get a `rebuilt` control (decoded
and rebuilt with no change). The result separates `original`, `resigned`,
`rebuilt` and each variant, with `attribution` (`signature`, `content`,
`signature/content`, `tooling`, `environment`, `inconclusive` or `none`).

```bash
python main.py --package com.example.app \
    --tamper-method repack --tamper-allow-reinstall \
    --tamper-variant asset --tamper-variant dex \
    --only anti_tampering

# with Frida Gadget payload (download first with tools/setup_repack.sh)
python main.py --package com.example.app \
    --tamper-method repack --tamper-allow-reinstall \
    --tamper-variant gadget --tamper-gadget ~/.raspilot/gadgets/libgadget-arm64.so \
    --window 20 --only anti_tampering
```

Temporary artifacts and kept APKs live under `reports/repack/`. For large
apps apktool may need more heap; adjust `RASPILOT_APKTOOL_XMX` (default
`6G`). The `gadget` variant checks `gadget.loaded` via `/proc/<pid>/maps`
and `gadget.connected` through the Frida endpoint; it only reports
bypass when both are true. When connected, the JSON includes
`gadget.objection_command` with a ready-to-use Objection command.

To interact with Gadget after installation:

```bash
adb forward tcp:27043 tcp:27043
frida-ps -H 127.0.0.1:27043
# objection (example; tool must be installed on the host)
objection -N -h 127.0.0.1 -p 27043 -g Gadget explore
```

The Gadget binary must match the device ABI and, ideally, the host Frida
version. Use `./tools/setup_repack.sh` to download the right one. On
large apps Gadget loading can take more than 10 s; use `--window 20` or
more.

For a script payload:

```bash
python main.py --package com.example.app \
    --tamper-method repack --tamper-allow-reinstall \
    --tamper-variant gadget --tamper-gadget-mode script \
    --tamper-gadget-script ./probe.js \
    --window 20 --only anti_tampering
```

The provider copies the script to the app's private files directory and
Gadget runs it. A marker in `files/raspilot-gadget-ok` confirms execution;
the report exposes `gadget.script_ran`. The marker check uses `run-as`
(debuggable app) or root.

> Uninstall removes app data; there is no automatic backup. Use a
> disposable device/AVD. Without the original key it is not possible to
> test modified content under the same signer: the test covers signer
> change plus content change. With `--tamper-key`, control and variant
> use the same signer, isolating content integrity. In a future MCP tool,
> repack must require explicit two-step confirmation before uninstalling/
> reinstalling anything.

## Instrumentation module (hooking APK) — optional

Everything in this section is **optional**: without a hooking framework on
the device RASPilot uses the `frida` method and behaves as before.

### Why

The Frida bypass injects an **agent** into the app process. For an app with
anti-hook protection that agent is what kills the audit: the app finds the
`frida-agent` in the memory map or in a stack trace before any anti-hook
check happens.

A **hooking module (APK)** swaps the instrument: instead of an injected
agent, the device itself loads the hooking framework into the app process —
exactly the environment the protection looks for. The module neutralises the
app's queries and the auditor observes the result **without** leaving a
trace of external injection. It is also what allows the anti-emulator and
anti-root checks to run without instrumentation: the app sees an
emulator/root environment while running normally.

The module has four configurable layers: `hook` (anti-hook), `root`
(anti-root), `tamper` (integrity/signature) and `emu` (anti-emulator). Anti-root uses `RootShield` to
observe/neutralise RootBeer, `File`, `Runtime.exec`, `SystemProperties`
and `PackageManager`.

### How it works

1. **Build** — `instrumentation/build.sh` compiles the module with the
   Android SDK's `aapt2`/`d8`/`apksigner` (no Gradle, no network). Sources
   live in `instrumentation/xposed/`.
2. **Install** — `adb install -r` of the APK.
3. **Enable and scope** — the module is enabled and its scope is set to the
   **target package only** (`--package`), through the framework's cli
   (`modules enable`, `scope set`).
4. **Configure** — the phase mode (`observe`, `bypass`, `probe`, `mask`) is
   written to a system property read by the module when the process starts:
   switching phases does not require reinstalling the APK.
5. **Run** — the app is started normally (no Frida) and the evidence emitted
   by the module is read from logcat (`RASPilotModule: EVT|...`).
6. **Restore** — the original scope is restored, the module is disabled and
   the APK is removed from the device.

### Requirements

- a device with **root** and a hooking framework installed (LSPosed,
  Vector, EdXposed) whose configuration cli is available
- Android SDK (`build-tools`, `platform`) and a JDK on the host — or a
  pre-built APK with `--module-apk`

The build toolchain is installed without system privileges:

```bash
./instrumentation/setup_toolchain.sh
```

Detailed requirements live in `instrumentation/requirements.txt`.

```bash
export ANDROID_HOME="$HOME/Android"
export JAVA_HOME="$HOME/Android/jdk"

# default: uses the module when a framework is available
python main.py --package com.example.app

# force the module (fails when no framework is present)
python main.py --package com.example.app --hook-method module

# use an already compiled APK
python main.py --package com.example.app --module-apk ./module.apk

# the repository pre-built APK already includes RootShield
ls instrumentation/build/raspilot-module.apk
```

> `instrumentation/build/raspilot-module.apk` is generated locally (the
> `build/` directory is gitignored) and already contains the available layers.
> **RASPilot's automatic build also always compiles `RootShield`**: there
> is no root flag in the main CLI. In `build.sh`, `--root` only sets the
> default mode baked into the APK; the runtime enables
> `root=observe`/`root=bypass` per phase. You only need to care if
> `--module-apk` points to an old APK built before `RootShield`.

### Coverage and limitations

The module acts on the app's **Java layer**: `Build`, `SystemProperties`,
`TelephonyManager`, `Settings.Secure`, `File.exists`, RootBeer and
`PackageManager`. Checks written in native code (reading
`/proc/self/maps`, string searches) are **not** covered by the module —
the report records that
limitation in `coverage` and lists the framework artifacts that stay visible
in the target process.

---

## Emulated environment (AVD) — optional

Everything in this section is **optional**: without the `--avd` flag
RASPilot behaves exactly as before and **does not depend on the Android
SDK**.

### Why

The anti-emulator check measures the bypass in two ways: the *probe* makes
the app see an emulator and the *mask* hides the decisive artifacts. On a
physical device that is a simulation — the emulator is only what the app
perceives.

On a **real AVD** the artifacts actually exist: the app receives the
values of a physical device while the machine is an emulator. That is the
ground truth of the bypass — and the only way to properly measure an app
that blocks instrumentation (anti-Frida), because emulator protection is
evaluated before hook protection.

### Environment setup

**1. Install the Android SDK** (cmdline-tools) and export the root:

```bash
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"
```

**2. Download the system image and create the AVD:**

```bash
sdkmanager "system-images;android-33;google_apis;x86_64"
echo no | avdmanager create avd --name raspilot_avd \
    --package "system-images;android-33;google_apis;x86_64" \
    --device "pixel_6"
```

**3. Describe the environment** in `~/.raspilot/avd.json` (or point
elsewhere with `--avd-config` / `$RASPILOT_AVD_CONFIG`):

```json
{
  "sdk_root": "/home/user/Android/Sdk",
  "avd_name": "raspilot_avd",
  "system_image": "system-images;android-33;google_apis;x86_64",
  "device_profile": "pixel_6",
  "port": 5554,
  "headless": true,
  "wipe_data": false,
  "boot_timeout": 300,
  "extra_args": ["-no-snapshot-save", "-gpu", "swiftshader_indirect"]
}
```

| Key | Default | Purpose |
|---|---|---|
| `sdk_root` | (`$ANDROID_SDK_ROOT`) | Android SDK root |
| `avd_name` | — (required) | AVD to launch |
| `system_image` | `system-images;android-33;google_apis;x86_64` | system image (instructions only) |
| `device_profile` | `pixel_6` | hardware profile (instructions only) |
| `port` | `5554` | emulator console/adb port |
| `headless` | `true` | launch without window and audio |
| `wipe_data` | `false` | restart the AVD with clean data |
| `boot_timeout` | `300` | maximum wait for boot (s) |
| `extra_args` | `[]` | extra `emulator` arguments |

**4. Validate and run:**

```bash
# shows what is missing, without auditing
python main.py --package com.example.app --avd-check

# boots the AVD, audits inside it and shuts the emulator down afterwards
python main.py --package com.example.app --avd
```

`--avd` boots the emulator (or reuses one that is already running), waits
for `sys.boot_completed`, hands the serial (`emulator-5554`) to the
`DeviceManager` and shuts down **only** the emulator it started itself.

| Flag | Effect |
|---|---|
| `--avd` | audit against the configured AVD |
| `--avd-config PATH` | configuration file (default `~/.raspilot/avd.json`) |
| `--avd-name NAME` | override `avd_name` from the configuration |
| `--avd-check` | validate the environment and show what is missing |

> **Limitations.** An AVD does not reproduce hardware-backed protections
> (TEE, attested provisioning, hardware keystore) nor the profile of a
> real handset. An AVD run complements the audit on a physical device — it
> does not replace it. The `frida-server` is downloaded for the emulator
> ABI (`x86_64`), and apps that require Play Integrity may not install.

> **Root in the emulator.** `google_apis` images are `userdebug`: the
> `adb` shell is already root, which is what lets the `frida-server`
> spawn apps that are not debuggable. Plain `default`/`aosp` images
> without root limit the audit to debuggable apps.

---

## Repository structure

```
raspilot/
├── main.py                     # CLI + auditing pipeline
├── requirements-static.txt     # Optional dependency: Droid ASC (Python 3.10+)
├── avd_manager.py              # Optional emulated environment (AVD)
├── device_manager.py           # ADB (USB/Wi-Fi) + frida-server + logcat/baseline
├── logcat_analyzer.py          # Death/security/TLS logcat correlation
├── reporter.py                 # JSON/HTML reports (Jinja2)
├── execution_log.py            # Per-check attempt, finding and verdict trace
├── tools/
│   └── setup_repack.sh         # Validates host and downloads Frida Gadget
├── instrumentation/            # Instrumentation module (hooking APK)
│   ├── manager.py              # Setup, framework scoping and evidence
│   ├── build.sh                # APK build (aapt2/d8/apksigner, no Gradle)
│   ├── setup_toolchain.sh      # Installs Android SDK + JDK in ~/Android
│   ├── requirements.txt        # Build toolchain requirements
│   └── xposed/                 # Module sources (anti-hook + root + emulator)
├── checks/
│   ├── anti_root.py            # Multi-vector root detection
│   ├── anti_frida.py           # Frida presence/detection
│   ├── anti_tampering.py       # Static integrity + in-memory probe
│   ├── tamper_repack.py        # Destructive repack with controls + restore
│   ├── anti_emulator.py        # Anti-emulator detection + bypass
│   ├── anti_hooking.py         # Anti-hooking detection + bypass
│   ├── combined.py             # Single-session observation/bypass
│   ├── stealth.py              # Native bootstrap before resume
│   ├── apk_utils.py            # Shared APK helpers + APK cache
│   ├── taxonomy.py             # Per-vector artifacts + finding owner
│   ├── static/                 # Static profile (signatures + Droid ASC)
│   │   ├── engine.py           # ASC subprocess, timeout and cache
│   │   ├── queries.py          # Signatures and high-signal queries
│   │   └── profile.py          # Profile, confidence and bypass coverage
│   └── ssl_pinning.py          # SSL pinning detection + bypass
├── scripts/
│   ├── ssl_bypass.js           # Universal SSL pinning bypass (Frida)
│   ├── anti_frida_bypass.js    # Frida detection bypass (Frida)
│   ├── tamper_probe.js         # In-memory signature tamper probe
│   ├── anti_hooking_bypass.js  # Hooking detection bypass (Frida)
│   ├── root_detection.js       # App root-check observation
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

Repack has its own tests (`tests/test_tamper_repack.py`): variants,
control matrix, attribution, payload failure, focus/usability and
restore. The instrumentation module has its own tests
(`tests/test_instrumentation.py` for the manager, `tests/test_instrumentation_checks.py` for the check
integration): configuration, evidence parsing from logcat, scope
application and restoration on the framework, and the module-based
bypass/probe phases of the hooking and emulator checks.

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
| `raspilot_check_anti_tampering(device_id, package_name) -> dict` | `AntiTamperingCheck(dm).run_all(...)` |
| `raspilot_test_repack(device_id, package_name, variants, gadget=None) -> dict` | `RepackTester(...).run()` — requires explicit confirmation before reinstalling |
| `raspilot_check_anti_emulator(device_id, package_name) -> dict` | `AntiEmulatorCheck(dm).run_all(package)` |
| `raspilot_check_anti_hooking(device_id, package_name) -> dict` | `AntiHookingCheck(dm).run_all(package)` |
| `raspilot_bypass_ssl_pinning(device_id, package_name) -> dict` | `SSLPinningCheck(dm).run_all(package)` |
| `raspilot_get_report() -> dict` | `Reporter.generate_json()` |

The JSON emitted by RASPilot already follows a stable schema
(`metadata` / `summary` / `execution_log` / `details`) designed for direct
LLM reading. `metadata.schema_version` (currently **5**) detects
incompatible changes and `metadata.run` records the execution context
(CLI arguments, Frida version, port, sha256 hashes of the injection
scripts, target pid and
baseline result) so the run can be reproduced.

For MCP, the pipeline is already prepared with staged analysis and clean
output: `--stage static|detect|bypass`, `--only`, `--apk` and
`--json-only`. Each MCP tool can map to a stage/check and return a
`dict` with `summary` + report path, leaving the full JSON/HTML as a
*resource*. Cross-call state/session belongs to the next phase.

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
| `hooking framework unavailable` | No framework with a configuration cli on the device | Use `--hook-method frida --emulator-method frida` |
| `Estático: droidasc não instalado` | Optional semantic analysis unavailable | `pip install -r requirements-static.txt` (Python 3.10+) or use `--static-engine builtin` |
| `Estático: timeout após Ns` | Large APK or slow host | Increase `--static-timeout`; the check continues with partial results |
| `module build failed` | Android SDK or JDK missing on the host | Install `build-tools` + `platform` in `$ANDROID_HOME` and a JDK, or use `--module-apk` |
| `apktool not found` | Repack without apktool on PATH | Install apktool 3.x and run `./tools/setup_repack.sh` |
| `Frida Gadget not found` | `gadget` variant without the ABI binary | `./tools/setup_repack.sh --abi <abi>` or use `--tamper-gadget` |
| `gadget.loaded=false` / `gadget.connected=false` | Gadget did not load or endpoint did not answer | Increase `--window` (20+), check ABI/version and use `--tamper-gadget` |
| Repack left the app without data | Uninstall/reinstall is destructive | Restore the original APK; app data has no automatic backup. Use a disposable AVD/device |
| `keystore não encontrado` | Invalid `--tamper-key` path | Check the path, alias and passwords for the original keystore |
| `modo script exige --tamper-gadget-script` | Script mode without JS | Pass `--tamper-gadget-script` or use `--tamper-gadget-mode listen` |

---

## Known limitations

**Repack is destructive and not exhaustive.** Without `--tamper-key`, the
test measures signer change + content change; with the original key it
measures content integrity under the same signer. Server-side attestation/Play
Integrity may block the app without a local crash. Uninstall erases app
data. The `gadget` variant depends on ABI, Frida version, a free port and
load time; the report separates `payload`/`tooling` from app detection.

**Static analysis is surface, not behaviour.** The APK profile finds
references to checks and points out coverage gaps, but it does not prove
that the method ran. Native code, packed/encrypted DEX and DEX loaded at
runtime are not seen by ASC; when that happens the report records the
limitation and the dynamic verdict remains the source of proof. In
`anti_root`, the module covers the Java layer and Frida covers native
paths/strings; if no check is exercised the result is `SKIP`, not `OK` or
`FALHOU`.

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

**The instrumentation module acts on the app's Java layer.**
When the bypass (or the probe) runs through the module, the app's native
queries (reading `/proc/self/maps`, string searches in native code) are not
covered: the module has no native component. The limitation is recorded in
`coverage.not_covered`, and the framework artifacts that stay visible in
the target process are listed in `framework_artifacts`.

**Classes generated by the Java layer depend on the cache directory.**
The bridge writes the temporary class to a directory of its own; its
default is not writable by the app process and the registration fails.
The app's directory is applied at the point of use — the bridge resets
the value when it initialises, and that can happen after the script has
been loaded.

## License and usage

Security auditing tool for **authorized** use only (apps and devices under
your control or within a contracted testing scope).
