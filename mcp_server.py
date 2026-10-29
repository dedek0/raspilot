#!/usr/bin/env python3
"""RASPilot — servidor MCP universal (stdio por padrão).

A camada de ferramentas vive em :mod:`mcp_api`; este arquivo é um
adaptador fino para o SDK oficial ``mcp`` (``MCPServer``). O transporte
padrão é **stdio**, aceito por Claude Code, OpenCode, Codex e qualquer
harness compatível com MCP. SSE/Streamable HTTP existem para uso local
ou atrás de um reverse proxy com autenticação.

Exemplos::

    python mcp_server.py
    python mcp_server.py --transport streamable-http --host 127.0.0.1 --port 8000

Variáveis de ambiente úteis: ``RASPILOT_DEVICE`` (device padrão),
``RASPILOT_STATE_DIR``, ``RASPILOT_OUTPUT_DIR`` e ``RASPILOT_TIMEOUT``.

Nada é escrito em stdout no modo stdio: logs vão para stderr. O stdout
é reservado ao protocolo.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from mcp_api import RaspilotTools, ToolError
from device_manager import TOOL_VERSION
from service import KNOWN_CHECKS
from sessions import SessionStore

LOGGER = logging.getLogger("raspilot.mcp")

SERVER_NAME = "raspilot"
SERVER_TITLE = "RASPilot — Android RASP audit"
DEFAULT_TIMEOUT = float(os.environ.get("RASPILOT_TIMEOUT", "1800"))
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Exige ``Authorization: Bearer <token>`` no transporte HTTP."""

    def __init__(self, app, token: str) -> None:
        super().__init__(app)
        self.token = token

    async def dispatch(self, request, call_next):
        expected = f"Bearer {self.token}"
        if request.headers.get("authorization") != expected:
            return JSONResponse(
                {"error": "unauthorized", "code": "unauthorized"},
                status_code=401,
            )
        return await call_next(request)


def _ok(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return {"ok": True, **payload}
    return {"ok": True, "result": payload}


def _error(exc: BaseException) -> Dict[str, Any]:
    if isinstance(exc, ToolError):
        return exc.to_dict()
    return {
        "ok": False,
        "code": "internal_error",
        "message": str(exc),
        "details": {},
    }


def _call(func, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    try:
        return _ok(func(*args, **kwargs))
    except BaseException as exc:  # noqa: BLE001 - fronteira da ferramenta
        LOGGER.debug("Ferramenta falhou", exc_info=True)
        return _error(exc)


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _read(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"recurso inexistente: {path.name}")
    return path.read_text(encoding="utf-8")


def _session_path(store: SessionStore, session_id: str, *parts: str) -> Path:
    state = store.load(session_id)
    base = Path(state.directory).resolve()
    path = base.joinpath(*parts).resolve()
    if path != base and base not in path.parents:
        raise ValueError("caminho de recurso inválido")
    return path


def _valid_check(check: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", check or ""):
        raise ValueError("check inválido")
    if check not in KNOWN_CHECKS:
        raise ValueError(f"check desconhecido: {check}")
    return check


def create_server(tools: Optional[RaspilotTools] = None) -> MCPServer:
    """Monta o servidor MCP sobre a fachada ``RaspilotTools``."""
    toolset = tools or RaspilotTools(
        store=SessionStore(),
        run_timeout=DEFAULT_TIMEOUT,
    )
    server = MCPServer(
        name=SERVER_NAME,
        title=SERVER_TITLE,
        version=TOOL_VERSION,
        instructions=(
            "RASPilot audits Android apps for RASP protections. Start with "
            "raspilot_start_assessment (session_id-based workflow), then "
            "poll raspilot_status or call raspilot_wait. Reports and "
            "checks are exposed as raspilot:// resources. Destructive repack "
            "requires two calls (request confirmation, then present the token). "
            "All audit tools operate on session_id, never on an ad-hoc run."
        ),
        log_level="INFO",
    )

    # -- ciclo de vida -------------------------------------------------
    @server.tool(
        name="raspilot_start_assessment",
        description=(
            "Create a session and start an assessment asynchronously. "
            "Returns {session_id, status:'running'} immediately. Requires an "
            "explicit device_id or RASPILOT_DEVICE. stage: static|detect|full."
        ),
    )
    def start_assessment(
        package_name: str,
        device_id: Optional[str] = None,
        stage: str = "full",
        mode: Optional[str] = None,
        only: Optional[List[str]] = None,
        skip: Optional[List[str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        return _call(
            toolset.iniciar_avaliacao,
            package_name,
            device_id=device_id,
            stage=stage,
            mode=mode,
            only=only,
            skip=skip,
            timeout=timeout,
        )

    @server.tool(
        name="raspilot_status",
        description="Read a session's consolidated status. Never runs checks.",
    )
    def status(session_id: str) -> Dict[str, Any]:
        return _call(toolset.status, session_id)

    @server.tool(
        name="raspilot_wait",
        description="Wait until a session leaves pending/running (or time out).",
    )
    def wait_session(
        session_id: str,
        timeout: Optional[float] = None,
        poll: float = 0.5,
    ) -> Dict[str, Any]:
        return _call(
            toolset.aguardar, session_id, timeout=timeout, poll=poll
        )

    @server.tool(
        name="raspilot_cancel",
        description="Request cancellation between checks (idempotent).",
    )
    def cancel(session_id: str) -> Dict[str, Any]:
        return _call(toolset.cancelar, session_id)

    @server.tool(
        name="raspilot_list_sessions",
        description="List sessions, newest first, with pending action hints.",
    )
    def list_sessions() -> Dict[str, Any]:
        return _call(toolset.listar_sessoes)

    # -- relatórios ----------------------------------------------------
    @server.tool(
        name="raspilot_get_report",
        description=(
            "Return a saved report: format=json|summary|html|paths. "
            "Never runs the pipeline; use report stage/service first."
        ),
    )
    def get_report(
        session_id: str,
        format: str = "json",
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        return _call(
            toolset.obter_relatorio,
            session_id,
            format=format,
            timeout=timeout,
        )

    @server.tool(
        name="raspilot_get_summary",
        description="Shortcut for the session's summary.json.",
    )
    def get_summary(session_id: str) -> Dict[str, Any]:
        return _call(toolset.obter_resumo, session_id)

    @server.tool(
        name="raspilot_list_resources",
        description="List the stable raspilot:// resource URIs for a session.",
    )
    def list_resources(session_id: str) -> Dict[str, Any]:
        return _call(toolset.listar_recursos, session_id)

    # -- checks individuais --------------------------------------------
    @server.tool(
        name="raspilot_run_check",
        description=(
            "Run one check on an existing session without overwriting the "
            "other checks. check must be one of the known RASP checks."
        ),
    )
    def run_check(
        session_id: str,
        check: str,
        mode: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        return _call(
            toolset.executar_check,
            session_id,
            check,
            mode=mode,
            timeout=timeout,
        )

    @server.tool(name="raspilot_check_anti_root")
    def check_anti_root(
        session_id: str, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        return _call(
            toolset.verificar_anti_root, session_id, timeout=timeout
        )

    @server.tool(name="raspilot_check_anti_frida")
    def check_anti_frida(
        session_id: str, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        return _call(
            toolset.verificar_anti_frida, session_id, timeout=timeout
        )

    @server.tool(name="raspilot_check_anti_tampering")
    def check_anti_tampering(
        session_id: str, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        return _call(
            toolset.verificar_anti_tampering, session_id, timeout=timeout
        )

    @server.tool(name="raspilot_check_anti_emulator")
    def check_anti_emulator(
        session_id: str, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        return _call(
            toolset.verificar_anti_emulator, session_id, timeout=timeout
        )

    @server.tool(name="raspilot_check_anti_hooking")
    def check_anti_hooking(
        session_id: str, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        return _call(
            toolset.verificar_anti_hooking, session_id, timeout=timeout
        )

    @server.tool(name="raspilot_check_proxy_vpn")
    def check_proxy_vpn(
        session_id: str, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        return _call(
            toolset.verificar_proxy_vpn, session_id, timeout=timeout
        )

    @server.tool(name="raspilot_bypass_ssl_pinning")
    def bypass_ssl_pinning(
        session_id: str, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        return _call(
            toolset.bypass_ssl_pinning, session_id, timeout=timeout
        )

    # -- repack destrutivo --------------------------------------------
    @server.tool(
        name="raspilot_test_repack",
        description=(
            "Destructive repack in two steps. Without confirmation, returns "
            "a single-use token. With confirmation, executes once."
        ),
    )
    def test_repack(
        session_id: str,
        variants: Optional[List[str]] = None,
        gadget: Optional[str] = None,
        confirmation: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        return _call(
            toolset.testar_repack,
            session_id,
            variants=variants,
            gadget=gadget,
            confirmation=confirmation,
            timeout=timeout,
        )

    # -- recursos ------------------------------------------------------
    @server.resource(
        "raspilot://sessions",
        name="sessions",
        description="Session index (newest first).",
        mime_type="application/json",
    )
    def sessions_resource() -> str:
        return _json(toolset.listar_sessoes())

    @server.resource(
        "raspilot://sessions/{session_id}/session.json",
        name="session_json",
        description="Full session state.",
        mime_type="application/json",
    )
    def session_resource(session_id: str) -> str:
        return _read(_session_path(toolset.store, session_id, "session.json"))

    @server.resource(
        "raspilot://sessions/{session_id}/summary.json",
        name="summary_json",
        description="Report summary only.",
        mime_type="application/json",
    )
    def summary_resource(session_id: str) -> str:
        return _read(_session_path(toolset.store, session_id, "summary.json"))

    @server.resource(
        "raspilot://sessions/{session_id}/report.json",
        name="report_json",
        description="Full JSON report.",
        mime_type="application/json",
    )
    def report_resource(session_id: str) -> str:
        return _read(_session_path(toolset.store, session_id, "report.json"))

    @server.resource(
        "raspilot://sessions/{session_id}/report.html",
        name="report_html",
        description="HTML report.",
        mime_type="text/html",
    )
    def report_html_resource(session_id: str) -> str:
        return _read(_session_path(toolset.store, session_id, "report.html"))

    @server.resource(
        "raspilot://sessions/{session_id}/static.json",
        name="static_json",
        description="Static APK profile.",
        mime_type="application/json",
    )
    def static_resource(session_id: str) -> str:
        return _read(_session_path(toolset.store, session_id, "static.json"))

    @server.resource(
        "raspilot://sessions/{session_id}/checks/{check}.json",
        name="check_json",
        description="Raw result of one check.",
        mime_type="application/json",
    )
    def check_resource(session_id: str, check: str) -> str:
        check = _valid_check(check)
        return _read(
            _session_path(
                toolset.store, session_id, "checks", f"{check}.json"
            )
        )

    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RASPilot MCP server (stdio by default)."
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="MCP transport (default: stdio).",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="HTTP bind host (loopback default)."
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="HTTP bind port."
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="Session state directory (default: RASPILOT_STATE_DIR).",
    )
    parser.add_argument(
        "--device",
        default=None,
        help="Default device serial (default: RASPILOT_DEVICE).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Default timeout for blocking tools, in seconds.",
    )
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("RASPILOT_MCP_TOKEN"),
        help=(
            "Bearer token for HTTP transports. Required when binding to a "
            "non-loopback host."
        ),
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("RASPILOT_LOG_LEVEL", "INFO"),
        help="Log level (logs go to stderr).",
    )
    parser.add_argument(
        "--version", action="store_true", help="Print version and exit."
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(TOOL_VERSION)
        return 0
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        stream=sys.stderr,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    )
    store = SessionStore(args.state_dir)
    tools = RaspilotTools(
        store=store,
        device_id=args.device,
        run_timeout=args.timeout,
    )
    server = create_server(tools)
    if args.transport == "stdio":
        server.run("stdio")
        return 0
    if args.host not in LOOPBACK_HOSTS and not args.auth_token:
        parser.error(
            "transporte HTTP em host não-loopback exige --auth-token "
            "(ou RASPILOT_MCP_TOKEN)"
        )
    if args.transport == "streamable-http":
        app = server.streamable_http_app(
            host=args.host,
            streamable_http_path="/mcp",
        )
    else:
        app = server.sse_app(host=args.host)
    if args.auth_token:
        app.add_middleware(
            BearerAuthMiddleware, token=args.auth_token
        )
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=str(args.log_level).lower(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
