# RASPilot MCP — configuração universal

O servidor usa **stdio** por padrão, o transporte comum a Claude Code,
OpenCode, Codex e outros harnesses MCP. Substitua `/ABSOLUTE/PATH` pelo
caminho do repositório e `SERIAL_DO_APARELHO` pelo serial do `adb`.

Comando genérico:

```bash
/ABSOLUTE/PATH/.venv/bin/python /ABSOLUTE/PATH/mcp_server.py
```

Variáveis:

| Variável | Uso |
|---|---|
| `RASPILOT_DEVICE` | serial padrão quando a tool não informa `device_id` |
| `RASPILOT_STATE_DIR` | diretório das sessões (default `~/.raspilot/sessions`) |
| `RASPILOT_OUTPUT_DIR` | diretório dos relatórios da CLI (default `reports/`) |
| `RASPILOT_TIMEOUT` | timeout padrão das tools bloqueantes, em segundos |
| `RASPILOT_MCP_TOKEN` | bearer token para transporte HTTP |
| `RASPILOT_LOG_LEVEL` | nível de log; logs vão para stderr |

## Claude Code

Copie `claude-code.json` para `.mcp.json` na raiz do projeto (ou use
`claude mcp add`). O comando equivalente:

```bash
claude mcp add raspilot -- /ABSOLUTE/PATH/.venv/bin/python /ABSOLUTE/PATH/mcp_server.py
```

## OpenCode

Mescle o bloco `mcp` de `opencode.json` no `opencode.json` do projeto ou
em `~/.config/opencode/opencode.json`.

## Codex

Mescle `codex.toml` em `~/.codex/config.toml`.

## HTTP opcional

```bash
/ABSOLUTE/PATH/.venv/bin/python /ABSOLUTE/PATH/mcp_server.py \
  --transport streamable-http --host 127.0.0.1 --port 8000
```

Em host não-loopback o servidor exige `--auth-token`/`RASPILOT_MCP_TOKEN`.
Prefira manter HTTP atrás de um reverse proxy com TLS.

## Ferramentas

- `raspilot_iniciar_avaliacao`
- `raspilot_status`
- `raspilot_aguardar`
- `raspilot_cancelar`
- `raspilot_listar_sessoes`
- `raspilot_obter_relatorio`
- `raspilot_obter_resumo`
- `raspilot_listar_recursos`
- `raspilot_executar_check`
- `raspilot_verificar_anti_root`
- `raspilot_verificar_anti_frida`
- `raspilot_verificar_anti_tampering`
- `raspilot_verificar_anti_emulator`
- `raspilot_verificar_anti_hooking`
- `raspilot_verificar_proxy_vpn`
- `raspilot_bypass_ssl_pinning`
- `raspilot_testar_repack` (destrutivo, duas etapas)

Recursos: `raspilot://sessions`,
`raspilot://sessions/{id}/session.json`, `summary.json`, `report.json`,
`report.html`, `static.json` e `checks/{check}.json`.
