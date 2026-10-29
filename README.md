# ✈ RASPilot

> 🇺🇸 [English version](README.en.md)

**Piloto automático de auditoria RASP para Android.** O RASPilot conecta
em um device via ADB, executa verificações anti-root, anti-Frida,
anti-hooking, anti-tampering, anti-emulador, anti-proxy/VPN e SSL
pinning, e gera relatórios JSON/HTML. Também expõe tudo como servidor
**MCP** para Claude Code, OpenCode, Codex e outros harnesses.

- [Guia rápido](#uso-rápido) · [Sessões](#sessões-e-etapas) ·
  [MCP](#servidor-mcp) · [Problemas](#solução-de-problemas) ·
  [Referência completa](REFERENCE.md)

## Requisitos

- Python **3.9+** (recomendado 3.11+)
- `adb` no `PATH` e device autorizado (`adb devices` deve mostrar `device`)
- `frida`/`frida-tools` no host; no device, root para o `frida-server`
- **Opcional:** Android SDK + JDK para compilar o módulo de instrumentação
- **Opcional:** `apktool`/`zipalign`/`apksigner` para o repack
- **Opcional:** Droid ASC para análise estática semântica (Python 3.10+)

## Instalação

```bash
git clone https://github.com/dedek0/raspilot
cd raspilot

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# opcional: análise estática semântica
pip install -r requirements-static.txt

# opcional: servidor MCP
pip install -r requirements-mcp.txt
```

Confira o device:

```bash
adb devices
```

## Uso rápido

```bash
# Análise estática do APK
python main.py --package com.example.app --stage static

# Detecção (sem bypass) — a saída mostra o ID da sessão
python main.py --package com.example.app --stage detect

# Bypass na mesma sessão
python main.py --session <SESSION_ID> --stage bypass

# Relatório a partir do estado salvo (não precisa de device)
python main.py --session <SESSION_ID> --stage report
```

O fluxo completo em uma chamada:

```bash
python main.py --package com.example.app --stage full
```

Exemplos úteis:

```bash
# device específico / Wi-Fi ADB
python main.py --package com.example.app --device-id emulator-5554
python main.py --package com.example.app --wifi 192.168.0.10:5555

# só um check / pular checks
python main.py --package com.example.app --only anti_proxy
python main.py --package com.example.app --skip anti_emulator ssl_pinning

# usar o módulo no device (quando houver framework de hooking)
python main.py --package com.example.app \
  --hook-method module --proxy-method module --emulator-method module

# APK local (sem device) para o estático
python main.py --stage static --apk ./app.apk
```

### Flags principais

| Flag | Para que serve |
|---|---|
| `--package` | Package do app alvo |
| `--device-id` / `--wifi` | Serial ADB ou endereço Wi-Fi |
| `--stage` | `static`, `detect`, `bypass`, `full` (default) ou `report` |
| `--session` | Retoma uma sessão existente |
| `--state-dir` | Onde ficam as sessões (default `~/.raspilot/sessions`) |
| `--list-sessions` / `--show-session` | Lista ou mostra o estado de uma sessão |
| `--only` / `--skip` | Executa ou pula checks específicos |
| `--window` | Janela de observação dos checks dinâmicos (default 15s) |
| `--output-dir` | Diretório dos relatórios (default `reports/`) |
| `--json-only` | Gera só JSON, sem HTML |
| `--apk` | APK local (evita `adb pull`) |
| `--hook-method` / `--proxy-method` / `--emulator-method` | `auto`, `frida` ou `module` |
| `--module-apk` | Usa um APK do módulo já compilado |
| `--tamper-method repack` | Teste destrutivo de repack |
| `--tamper-allow-reinstall` | Confirma que os dados podem ser apagados |

A tabela completa, com timeout e opções do repack, está em
[REFERENCE.md](REFERENCE.md#argumentos).

## Sessões e etapas

Cada execução cria uma sessão em `~/.raspilot/sessions/<id>/`:

```text
session.json   estado completo
static.json    perfil estático do APK
report.json    relatório JSON
summary.json   resumo por check
report.html    relatório visual
checks/        resultado bruto por check
artifacts/     APKs do repack, quando mantidos
```

Comandos:

```bash
python main.py --list-sessions
python main.py --show-session <SESSION_ID>
python main.py --session <SESSION_ID> --stage report
```

`detect` mede sem contornar; `bypass` exige `detect` na mesma sessão;
`full` faz o pipeline completo; `report` só regenera os arquivos.
Sessões em execução têm lock por device — duas execuções no mesmo
aparelho falham rápido.

## Servidor MCP

O servidor usa **stdio** por padrão — o transporte aceito por Claude
Code, OpenCode, Codex e qualquer harness MCP.

```bash
pip install -r requirements-mcp.txt
python mcp_server.py
```

Configurações prontas estão em [`examples/mcp/`](examples/mcp/).
Exemplos resumidos:

**Claude Code** (`.mcp.json`):

```json
{
  "mcpServers": {
    "raspilot": {
      "command": "/caminho/para/.venv/bin/python",
      "args": ["/caminho/para/mcp_server.py"],
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
      "command": ["/caminho/para/.venv/bin/python", "/caminho/para/mcp_server.py"],
      "enabled": true,
      "environment": {"RASPILOT_DEVICE": "SERIAL"}
    }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.raspilot]
command = "/caminho/para/.venv/bin/python"
args = ["/caminho/para/mcp_server.py"]
env = { RASPILOT_DEVICE = "SERIAL" }
```

Variáveis úteis:

| Variável | Uso |
|---|---|
| `RASPILOT_DEVICE` | Serial padrão quando a tool não recebe `device_id` |
| `RASPILOT_STATE_DIR` | Diretório das sessões |
| `RASPILOT_OUTPUT_DIR` | Diretório dos relatórios |
| `RASPILOT_TIMEOUT` | Timeout padrão das tools, em segundos |
| `RASPILOT_MCP_TOKEN` | Bearer token para transporte HTTP |
| `RASPILOT_LOG_LEVEL` | Nível de log (logs vão para stderr) |

### Ferramentas

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
- `raspilot_test_repack` (destrutivo, duas etapas)

Fluxo típico no harness:

```text
1. raspilot_start_assessment(package_name="com.example.app", device_id="SERIAL", stage="full")
2. raspilot_wait(session_id="...")
3. raspilot_get_report(session_id="...", format="json")
```

Recursos: `raspilot://sessions`,
`raspilot://sessions/{id}/session.json`, `summary.json`, `report.json`,
`report.html`, `static.json` e `checks/{check}.json`.

**HTTP opcional:**

```bash
python mcp_server.py --transport streamable-http --host 127.0.0.1 --port 8000
```

Bind em host não-loopback exige `--auth-token`/`RASPILOT_MCP_TOKEN`.

## Checks

| Check | O que verifica |
|---|---|
| `anti_root` | root, RootBeer, binários/propriedades típicas |
| `anti_frida` | artefatos de Frida e reação do app |
| `anti_hooking` | frameworks de hook e detecção de instrumentação |
| `anti_tampering` | assinatura/integridade do APK (repack é destrutivo) |
| `anti_emulator` | sinais de emulador |
| `anti_proxy` | consulta a proxy/VPN e bypass |
| `ssl_pinning` | certificate pinning e bypass |

Cada check tem dois vereditos: **detecção** e **bypass**. `SKIP` significa
que a condição não foi exercitada — não é “OK”. A semântica completa está
em [REFERENCE.md](REFERENCE.md#dois-vereditos-por-check).

## Módulo de instrumentação

Quando há um framework de hooking no device, o RASPilot pode usar um
módulo Xposed genérico em vez de injetar Frida:

```bash
./instrumentation/build.sh --hook bypass --root bypass --tamper off \
  --emu mask --proxy bypass --out ./module.apk

python main.py --package com.example.app --module-apk ./module.apk \
  --hook-method module --proxy-method module --emulator-method module
```

Detalhes, camadas e requisitos de build: [instrumentation/README.md](instrumentation/README.md).

## Repack (destrutivo)

O teste de repack desinstala e reinstala o app — **os dados são
apagados**. Use um device/AVD descartável:

```bash
python main.py --package com.example.app \
  --tamper-method repack --tamper-allow-reinstall \
  --tamper-variant dex --only anti_tampering
```

Prepare o host com:

```bash
./tools/setup_repack.sh
```

## Relatórios

- JSON/HTML em `reports/` (ou `--output-dir`)
- Cópia estável dentro da sessão (`report.json`, `summary.json`, `report.html`)
- `summary` traz status, detecção e bypass por check
- `metadata.session_id` identifica a sessão e `metadata.schema_version`
  versiona o JSON

Use `--json-only` para automação. O schema completo e os códigos de
erro/skip/cancel estão em [REFERENCE.md](REFERENCE.md#saída).

## Solução de problemas

| Sintoma | Solução |
|---|---|
| `adb não encontrado` | Instale platform-tools e coloque no `PATH` |
| `UNAUTHORIZED` | Aceite a depuração USB no aparelho |
| `frida-server não respondeu` | `pip install -U frida frida-tools` e rode de novo |
| `Estático: timeout` | Aumente `--static-timeout` ou use `--static-engine builtin` |
| `build do módulo falhou` | Instale SDK/JDK ou use `--module-apk` |
| `apktool não encontrado` | Instale apktool 3.x e rode `./tools/setup_repack.sh` |
| MCP não lista tools | Confirme `pip install -r requirements-mcp.txt` e o comando do harness |
| MCP “device_required” | Passe `device_id` ou defina `RASPILOT_DEVICE` |

## Limitações

- O repack é destrutivo e não cobre attestation server-side/Play Integrity.
- A análise estática mostra superfície, não comportamento.
- A camada Java depende da anexação do agente; se o app bloquear, os
  checks ficam `SKIP` com o motivo.
- Cobertura nativa é parcial (libc de baixo volume, sem `strcmp`/`memcmp`).
- O logcat é evidência de apoio, não veredito.

## Desenvolvimento

```bash
pip install -r requirements-dev.txt
pytest -q
```

Para detalhes de arquitetura, semântica de verdicts, schema do JSON,
limitações e histórico de implementação, consulte
[REFERENCE.md](REFERENCE.md).
