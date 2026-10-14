# RASPilot v0.1 — Fase 1

**RASPilot — Piloto Automático de Auditoria RASP para Android.**

Orquestra verificações Anti-Root, Anti-Frida, Anti-Emulador e SSL Pinning em
apps Android, gerando relatórios estruturados e prontos para consumo por
LLMs via MCP.

> Status: **Fase 1 (Bootstrap + DeviceManager)** implementada.
> Fases 2–7 (checks, bypass SSL, relatório, testes) seguem incrementalmente.

## Instalação

```bash
# Requisitos de sistema
# - Python 3.9+
# - Android Platform Tools (`adb`) no PATH
pip install -r requirements.txt
```

## Uso (Fase 1)

```bash
# USB (primeiro dispositivo encontrado)
python main.py --package com.example.app

# Wi-Fi ADB
python main.py --package com.example.app --wifi 192.168.0.10:5555

# Dispositivo específico + verbose
python main.py --package com.example.app --device-id emulator-5554 --verbose
```

Na Fase 1 o CLI conecta via ADB, imprime as informações do dispositivo e
instala/valida o `frida-server` (download da release compatível com a versão
local do pacote `frida` + ABI do aparelho, push para `/data/local/tmp/`,
start em background e validação com `frida-ps -U`).

## Teste manual documentado (Fase 1)

Execute em cada cenário e confira o resultado esperado:

| Cenário | Comando | Resultado esperado |
|---|---|---|
| USB, dispositivo pronto | `python main.py --package com.example.app` | `✓ Dispositivo conectado` + `✓ frida-server instalado` (exit 0) |
| Wi-Fi | `python main.py --package com.example.app --wifi IP:5555` | igual acima após `adb connect IP:5555` |
| Sem dispositivo | `python main.py --package com.example.app` | `✗ Erro: Dispositivo não ficou pronto em 15s` (exit 1) |
| Depuração não autorizada | desative "Depuração USB" no aparelho | `✗ Erro: ... AUNAUTHORIZED ...` (exit 1) |
| Frida validado | após o run, no host | `frida-ps -U` lista processos |
| Root shell detectado | device rooteado | info do dispositivo mostra `is_rooted_shell: True` |
| `--skip` inválido | `python main.py --package x --skip foo` | erro de argparse listando checks conhecidos |

## Estrutura (plano final)

```
raspilot/
├── main.py                  # CLI (Fase 1 + pipeline completo na Fase 6)
├── device_manager.py        # ADB + Frida server (Fase 1)
├── reporter.py              # Relatórios JSON/HTML (Fase 6)
├── checks/                  # anti_root, anti_frida, anti_emulator, ssl_pinning
├── scripts/                 # JS injetados via Frida
├── templates/report.html.j2
└── reports/                 # saída dos relatórios
```
