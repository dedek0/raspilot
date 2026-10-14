# ✈ RASPilot

> 🇺🇸 [English version](README.en.md)

**RASPilot — Piloto Automático de Auditoria RASP para Android.**

Orquestra verificações Anti-Root, Anti-Frida, Anti-Emulador e SSL Pinning em
apps Android, gerando relatórios estruturados e prontos para consumo por
LLMs via MCP.

O RASPilot conecta-se a um dispositivo Android (USB ou Wi-Fi ADB), instala e
valida o `frida-server` automaticamente, executa um pipeline de verificações
RASP contra o app alvo e produz relatórios **JSON** e **HTML** com o status de
cada proteção (`OK` / `FALHOU` / `N/A` / `SKIP` / `ERROR`) e as evidências
coletadas.

---

## Requisitos

- Python 3.9+
- `adb` (Android Platform Tools) no `PATH`
- Dispositivo Android com **Depuração USB** ativada (físico ou emulador)
- Frida — o `frida-server` compatível é baixado automaticamente na versão
  do pacote `frida` instalado localmente

## Instalação

```bash
git clone <repo> raspilot && cd raspilot
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# dependências de teste (opcional)
pip install -r requirements-dev.txt
```

Verificação rápida:

```bash
python main.py --version
adb devices   # deve listar seu dispositivo como "device"
```

## Uso

```bash
# USB — primeiro dispositivo disponível
python main.py --package com.example.app

# Wi-Fi ADB
python main.py --package com.example.app --wifi 192.168.0.10:5555

# Dispositivo específico + verbose + saída customizada
python main.py --package com.example.app \
    --device-id emulator-5554 \
    --output-dir ./meus_relatorios \
    --verbose

# Janela de observação maior (segundos) nos checks dinâmicos
python main.py --package com.example.app --window 20

# Pular verificações
python main.py --package com.example.app --skip anti_emulator ssl_pinning
```

### Argumentos

| Argumento | Obrigatório | Descrição |
|---|---|---|
| `--package` | sim | Package name do app alvo (ex: `com.example.app`) |
| `--device-id` | não | Serial ADB (ex: `emulator-5554`) |
| `--wifi IP:PORTA` | não | Endereço para `adb connect` |
| `--output-dir` | não | Diretório dos relatórios (default `reports/`) |
| `--window SEG` | não | Janela de observação em segundos nos checks dinâmicos (default `12`) |
| `--verbose` | não | Logging em nível DEBUG |
| `--skip CHECK...` | não | Checks a pular (`anti_root`, `anti_frida`, `anti_emulator`, `ssl_pinning`) |

### Saída

- Terminal: tabela colorida **"RASPilot — Relatório de Auditoria RASP"**
- `reports/<package>_<timestamp>.json` — documento estruturado (metadata,
  summary, details) para consumo por LLMs/MCP
- `reports/<package>_<timestamp>.html` — relatório visual com badges de status
  e evidências

Semântica de status:

| Status | Significado |
|---|---|
| `OK` | Ambiente/proteção OK (ex: dispositivo físico, SSL pinning resistiu ao bypass, app detectou e bloqueou o Frida) |
| `FALHOU` | Ameaça presente ou bypass venceu (ex: root/emulador no ambiente, pinning contornado, app não detectou o Frida) |
| `N/A` | Não aplicável (ex: sem SSL pinning — bypass não faz sentido) |
| `SKIP` | Verificação pulada via `--skip` |
| `ERROR` | A verificação não pôde executar (o pipeline continua) |

> **Importante:** o RASPilot **não modifica permanentemente** o dispositivo.
> Ao final de cada execução ele encerra o `frida-server`, remove
> `/data/local/tmp/frida-server` e force-stop no app alvo.

---

## Verificações

### 1. Anti-Root (`checks/anti_root.py`)

Múltiplos vetores independentes consolidados em `is_rooted` + `confidence`:

- Binários `su` em 7 paths canônicos
- Magisk (package, `/data/adb/magisk`, `/sbin/.magisk`, `which magisk`)
- APatch e KernelSU (`me.bmax.apatch`, `me.weishu.kernelsu`, `/data/adb/ap`,
  `/data/adb/ksu`, `apd`, `ksud`)
- Propriedades de build (`ro.debuggable`, `ro.secure`, `service.adb.root`,
  `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`)
- Apps gerenciadores de root (Magisk, SuperSU, KingRoot, APatch, KernelSU...)
- `/system` montado `rw`
- Busybox

Confiança: `high` (≥2 vetores), `medium` (1), `low` (0).

### 2. Anti-Frida (`checks/anti_frida.py`)

- Processos (`ps -A | grep frida`)
- Portas 27042/27043 (`netstat`/`ss`/`/proc/net/tcp`)
- Módulos Frida carregados no processo alvo (via Frida)
- Threads `gum-js-loop`, `gmain`, `pool-frida` (`/proc/<pid>/task`)
- Observação de detecção de Frida **pelo app** (hooks de observação em
  `File.exists`, `Runtime.exec`, `ProcessBuilder`, `strstr`/`strcmp`,
  `connect` nas portas Frida e `open`/`access`/`stat`/`faccessat` em paths
  Frida)
- Durante a janela de observação o processo é monitorado: se o app se
  encerrar (reação típica de RASP ao detectar ameaça), isso vira evidência
  e o veredito passa a `vulnerable=False`

`vulnerable=True` ⇒ o app **não** detectou o Frida (falha de RASP).
O bypass correspondente vive em `scripts/anti_frida_bypass.js`.

### 3. Anti-Emulador (`checks/anti_emulator.py`)

Combina propriedades QEMU, arquivos de kernel, arquitetura de CPU
(x86 sem Chromebook), contagem de sensores, MAC de Bluetooth placeholder e
detecção específica de Genymotion/LDPlayer/BlueStacks/Nox/Waydroid.
Classifica `emulator_type` (`qemu_avd`, `genymotion`, `ldplayer`,
`bluestacks`, `nox`, `waydroid`) com confiança.

### 4. SSL Pinning (`checks/ssl_pinning.py`)

- **Detecção estática**: baixa o APK (`pm path` + `adb pull`) e procura
  assinaturas de OkHttp `CertificatePinner`, TrustKit,
  NetworkSecurityConfig, Flutter e Conscrypt/nativo (Manifest binário,
  DEX, libs nativas).
- **Bypass dinâmico**: injeta `scripts/ssl_bypass.js` (universal) cobrindo
  TrustManager, HostnameVerifier, OkHttp 3/4, NSC, Conscrypt, Apache
  HttpClient, WebView, BoringSSL/OpenSSL e Flutter. Bypass só é considerado
  bem-sucedido com **evidência real** (host interceptado ou log de
  `check()` contornado). O processo é monitorado durante a janela — se o
  app se encerrar, isso é registrado no resultado.

---

## Estrutura do repositório

```
raspilot/
├── main.py                     # CLI + pipeline de auditoria
├── device_manager.py           # ADB (USB/Wi-Fi) + ciclo de vida do frida-server
├── reporter.py                 # Relatórios JSON/HTML (Jinja2)
├── checks/
│   ├── anti_root.py            # Detecção de root multi-vetor
│   ├── anti_frida.py           # Presença/detecção de Frida
│   ├── anti_emulator.py        # Classificação de emuladores
│   └── ssl_pinning.py          # Detecção + bypass de SSL pinning
├── scripts/
│   ├── ssl_bypass.js           # Bypass universal de SSL pinning (Frida)
│   ├── anti_frida_bypass.js    # Bypass de detecção de Frida (Frida)
│   └── anti_root_bypass.js     # Bypass de detecção de root (Frida)
├── templates/report.html.j2    # Template do relatório HTML
├── reports/                    # Saída dos relatórios
└── tests/                      # Suíte pytest (100% mockada, sem dispositivo)
```

## Testes

```bash
pip install -r requirements-dev.txt
pytest -v
```

A suíte cobre: parsing de output do ADB (mock de `subprocess.run`),
consolidação (`run_all`) de cada check com dados mockados, geração do
relatório JSON contra um snapshot de schema, detecção de pinning em APKs
sintéticos e o pipeline completo de ponta a ponta (com `DeviceManager`
mockado). Nenhum dispositivo físico é necessário para os testes.

---

## Integração MCP (próxima fase — planejada)

Os `run_all()` de cada check são funções puras: recebem o `DeviceManager`
injetado e retornam `dict`, sem efeitos colaterais globais — prontos para
serem envolvidos como ferramentas MCP com `FastMCP`:

| Ferramenta MCP planejada | Mapeamento interno |
|---|---|
| `raspilot_iniciar_avaliacao(package_name, device_id=None) -> dict` | `DeviceManager.connect_adb()` + `setup_frida_server()` + pipeline |
| `raspilot_verificar_anti_root(device_id) -> dict` | `AntiRootCheck(dm).run_all()` |
| `raspilot_verificar_anti_frida(device_id) -> dict` | `AntiFridaCheck(dm).run_all(session, pid)` |
| `raspilot_verificar_anti_emulator(device_id) -> dict` | `AntiEmulatorCheck(dm).run_all()` |
| `raspilot_bypass_ssl_pinning(device_id, package_name) -> dict` | `SSLPinningCheck(dm).run_all(package)` |
| `raspilot_obter_relatorio() -> dict` | `Reporter.generate_json()` |

O JSON emitido pelo RASPilot já segue um schema estável
(`metadata` / `summary` / `details`) pensado para leitura direta por LLMs.

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| `adb` não encontrado | Platform Tools fora do PATH | Instale e adicione `adb` ao PATH |
| `Dispositivo AUNAUTHORIZED` | Depuração USB não confirmada | Aceite o prompt no aparelho |
| `frida-server não respondeu` | Versão local ≠ servidor | `pip install -U frida frida-tools` e rode de novo |
| `Dispositivo não ficou pronto em 15s` | Offline/USB com problema | Confira cabo/`adb kill-server` |
| App spawnado mas checks vazios | App protegido contra debugger | Use `--verbose` e inspecione `details` no JSON |
| Verificação curta demais para apps lentos | Splash longa ou RASP tardio | Aumente com `--window 20` (ou mais) |

## Licença e uso

Ferramenta de auditoria de segurança para uso **autorizado** apenas
(aplicativos e dispositivos sob seu controle ou com escopo de teste
contratado).
