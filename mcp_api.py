"""RASPilot — contrato das ferramentas session-aware (pré-MCP).

Este módulo **não** fala MCP. Ele é a fronteira que o servidor MCP vai
adaptar: valida entradas, aplica timeout/cancelamento, traduz exceções
para códigos estáveis e devolve dicionários serializáveis.

Regras do contrato:

* toda ferramenta de auditoria opera sobre ``session_id``; ``device_id``
  só aparece na criação da sessão;
* ``iniciar_avaliacao`` retorna imediatamente com ``status="running"``
  e o cliente acompanha ``status``/``aguardar``;
* ``status`` nunca executa checks: lê ``session.json`` e os artefatos;
* toda ferramenta aceita ``timeout`` (segundos) quando pode bloquear;
* o repack é destrutivo e exige duas chamadas: uma sem confirmação
  devolve o token; a outra apresenta o token e executa;
* erros têm ``code`` estável (``session_not_found``, ``session_busy``,
  ``timeout``, ``confirmation_required`` etc.).

O endpoint HTTP (se um dia existir) deve usar o mesmo contrato.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from service import KNOWN_CHECKS, RaspilotService, RunConfig
from sessions import (
    ERROR_CODES,
    SessionBusy,
    SessionConfirmationError,
    SessionError,
    SessionNotFound,
    SessionState,
    SessionStore,
    SessionTimeout,
)

DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 6 * 3600.0
VALID_STAGES = ("static", "detect", "bypass", "full")
VALID_REPORT_FORMATS = ("json", "summary", "html", "paths")

# Códigos próprios da camada de ferramentas (somam-se aos de sessions).
TOOL_ERROR_CODES = (
    "tool_error",
    "invalid_argument",
    "device_required",
    "timeout",
    "internal_error",
)


class ToolError(Exception):
    """Erro de ferramenta com código estável e detalhes opcionais."""

    code = "tool_error"

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        super().__init__(message)
        if code:
            self.code = code
        self.details = dict(details or {})

    def to_dict(self) -> dict:
        return {
            "ok": False,
            "code": self.code,
            "message": str(self),
            "details": self.details,
        }


class ToolNotFound(ToolError):
    code = "session_not_found"


class ToolBusy(ToolError):
    code = "session_busy"


class ToolTimeout(ToolError):
    code = "timeout"


class ToolInvalidState(ToolError):
    code = "invalid_session_state"


class ToolConfirmationRequired(ToolError):
    code = "confirmation_required"


class ToolDeviceRequired(ToolError):
    code = "device_required"


def _to_tool_error(exc: BaseException) -> ToolError:
    """Converte exceções internas em :class:`ToolError`."""
    if isinstance(exc, ToolError):
        return exc
    if isinstance(exc, SessionBusy):
        return ToolBusy(str(exc))
    if isinstance(exc, SessionNotFound):
        return ToolNotFound(str(exc))
    if isinstance(exc, SessionTimeout):
        return ToolTimeout(str(exc))
    if isinstance(exc, SessionConfirmationError):
        return ToolConfirmationRequired(str(exc), code=exc.code)
    if isinstance(exc, SessionError):
        mapped = ToolInvalidState(str(exc))
        mapped.code = getattr(exc, "code", "session_error")
        return mapped
    return ToolError(str(exc), code="internal_error")


def safe_call(func: Callable[..., dict], *args: Any, **kwargs: Any) -> dict:
    """Executa uma ferramenta convertendo erro em payload estruturado."""
    try:
        return func(*args, **kwargs)
    except BaseException as exc:  # noqa: BLE001 - fronteira da ferramenta
        return _to_tool_error(exc).to_dict()


def _clamp_timeout(value: Optional[float], default: float) -> float:
    if value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ToolError("timeout deve ser numérico", code="invalid_argument")
    if number < 0:
        raise ToolError("timeout não pode ser negativo", code="invalid_argument")
    return min(number, MAX_TIMEOUT)


def _require_session_id(session_id: Optional[str]) -> str:
    if not session_id or not str(session_id).strip():
        raise ToolError("session_id é obrigatório", code="invalid_argument")
    return str(session_id)


class RaspilotTools:
    """Fachada session-aware usada pelo futuro servidor MCP.

    Args:
        store: ``SessionStore`` compartilhado; por padrão usa o state dir.
        service_factory: injeção para testes. Recebe
            ``(config, store, resume)`` e devolve um serviço compatível
            com :class:`RaspilotService`.
        device_id: device padrão quando a chamada não informa um.
        run_timeout: teto padrão para ferramentas bloqueantes.
    """

    def __init__(
        self,
        store: Optional[SessionStore] = None,
        service_factory: Optional[Callable[[RunConfig, SessionStore, bool], Any]] = None,
        device_id: Optional[str] = None,
        run_timeout: float = 1800.0,
    ) -> None:
        self.store = store or SessionStore()
        self.service_factory = service_factory
        self.default_device = device_id or os.environ.get("RASPILOT_DEVICE")
        self.run_timeout = run_timeout
        self._executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="raspilot-tool"
        )

    def close(self) -> None:
        """Libera o executor usado pelas ferramentas bloqueantes."""
        self._executor.shutdown(wait=False)

    def __enter__(self) -> "RaspilotTools":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- infraestrutura -------------------------------------------------
    def _service(self, config: RunConfig, resume: bool) -> Any:
        if self.service_factory is not None:
            return self.service_factory(config, self.store, resume)
        if resume:
            return RaspilotService.resume(config, store=self.store)
        return RaspilotService.create(config, store=self.store)

    def _resolve_device(self, device_id: Optional[str]) -> str:
        serial = device_id or self.default_device
        if not serial:
            raise ToolDeviceRequired(
                "informe device_id (ou defina RASPILOT_DEVICE); "
                "seleção implícita é proibida no contrato MCP"
            )
        return str(serial)

    @staticmethod
    def _require_known_checks(names: Optional[Iterable[str]]) -> Optional[List[str]]:
        if names is None:
            return None
        values = [str(item) for item in names]
        unknown = [item for item in values if item not in KNOWN_CHECKS]
        if unknown:
            raise ToolError(
                "checks desconhecidos: " + ", ".join(unknown),
                code="invalid_argument",
                details={"known": list(KNOWN_CHECKS)},
            )
        return values

    def _state(self, session_id: str) -> SessionState:
        try:
            return self.store.load(_require_session_id(session_id))
        except SessionNotFound as exc:
            raise ToolNotFound(str(exc)) from exc
        except SessionError as exc:
            raise _to_tool_error(exc) from exc

    # -- ferramentas ----------------------------------------------------
    def iniciar_avaliacao(
        self,
        package_name: str,
        device_id: Optional[str] = None,
        stage: str = "full",
        mode: Optional[str] = None,
        only: Optional[Iterable[str]] = None,
        skip: Optional[Iterable[str]] = None,
        timeout: Optional[float] = None,
    ) -> dict:
        """Cria a sessão e dispara a avaliação em background.

        O retorno é imediato (``status="running"``). O timeout aqui é
        apenas o teto aceito pelo contrato; não bloqueia a criação.
        """
        if not package_name or not str(package_name).strip():
            raise ToolError("package_name é obrigatório", code="invalid_argument")
        if stage not in VALID_STAGES:
            raise ToolError(
                f"stage inválido: {stage!r}",
                code="invalid_argument",
                details={"valid": list(VALID_STAGES)},
            )
        if stage == "bypass":
            raise ToolError(
                "bypass exige detecção prévia na mesma sessão; "
                "use stage='detect' e depois retome, ou stage='full'",
                code="invalid_argument",
            )
        _clamp_timeout(timeout, DEFAULT_TIMEOUT)
        serial = self._resolve_device(device_id)
        config = RunConfig(
            package=str(package_name),
            device_id=serial,
            stage=stage,
            mode=mode or ("detect" if stage == "detect" else "bypass"),
            only=self._require_known_checks(only),
            skip=self._require_known_checks(skip) or [],
            output_dir=os.environ.get("RASPILOT_OUTPUT_DIR", "reports/"),
            state_dir=str(self.store.root),
        )
        service = self._service(config, resume=False)
        try:
            service.run_async()
        except BaseException as exc:  # noqa: BLE001 - fronteira da ferramenta
            raise _to_tool_error(exc) from exc
        return {
            "session_id": service.state.session_id,
            "status": "running",
            "stage": stage,
            "package": config.package,
            "device": serial,
            "resources": service.resources(),
        }

    def status(self, session_id: str) -> dict:
        """Status consolidado da sessão (não bloqueia)."""
        return self.store.status_payload(self._state(session_id))

    def aguardar(
        self,
        session_id: str,
        timeout: Optional[float] = None,
        poll: float = 0.5,
    ) -> dict:
        """Aguarda a sessão terminar e devolve o status final."""
        session_id = _require_session_id(session_id)
        limit = _clamp_timeout(
            timeout,
            self.run_timeout,
        )
        self._state(session_id)
        from sessions import wait_for_status

        try:
            state = wait_for_status(self.store, session_id, limit, poll)
        except SessionTimeout as exc:
            raise ToolTimeout(str(exc)) from exc
        return self.store.status_payload(state)

    def cancelar(self, session_id: str) -> dict:
        """Solicita cancelamento entre checks (idempotente)."""
        session_id = _require_session_id(session_id)
        try:
            return RaspilotService.cancel_session(session_id, store=self.store)
        except SessionError as exc:
            raise _to_tool_error(exc) from exc

    def listar_sessoes(self) -> dict:
        """Lista sessões mais recentes primeiro."""
        states = self.store.list()
        return {
            "sessions": [
                {
                    "session_id": item.session_id,
                    "package": item.package,
                    "stage": item.stage,
                    "status": item.status,
                    "device": (item.device or {}).get("serial"),
                    "updated_at": item.updated_at,
                    "pending_action": (
                        (item.pending_action or {}).get("action")
                    ),
                }
                for item in states
            ],
            "total": len(states),
        }

    def obter_relatorio(
        self,
        session_id: str,
        format: str = "json",
        timeout: Optional[float] = None,
    ) -> dict:
        """Devolve o relatório salvo (JSON, summary, HTML ou caminhos).

        Não executa o pipeline: se o relatório não existe, o cliente
        precisa rodar ``--stage report``/``generate_report`` antes.
        """
        _clamp_timeout(timeout, DEFAULT_TIMEOUT)
        session_id = _require_session_id(session_id)
        if format not in VALID_REPORT_FORMATS:
            raise ToolError(
                f"format inválido: {format!r}",
                code="invalid_argument",
                details={"valid": list(VALID_REPORT_FORMATS)},
            )
        state = self._state(session_id)
        reports = dict(state.reports or {})
        if format == "paths":
            return {
                "session_id": session_id,
                "status": state.status,
                "reports": reports,
                "resources": self.store.resources(state),
            }
        key = {
            "json": "report_json",
            "summary": "summary_json",
            "html": "report_html",
        }[format]
        path = reports.get(key)
        if not path or not Path(path).is_file():
            raise ToolInvalidState(
                f"relatório {format!r} ainda não foi gerado para a sessão",
                details={"session_id": session_id, "expected": key},
            )
        payload: Dict[str, Any] = {
            "session_id": session_id,
            "status": state.status,
            "format": format,
            "path": path,
        }
        if format == "html":
            payload["html"] = Path(path).read_text(encoding="utf-8")
        else:
            with open(path, encoding="utf-8") as handle:
                payload["document"] = json.load(handle)
        return payload

    def obter_resumo(self, session_id: str) -> dict:
        """Atalho para ``summary.json`` (quando disponível)."""
        return self.obter_relatorio(session_id, format="summary")

    def listar_recursos(self, session_id: str) -> dict:
        """Lista as URIs ``raspilot://`` estáveis da sessão."""
        state = self._state(session_id)
        return {
            "session_id": state.session_id,
            "resources": self.store.resources(state),
        }

    def testar_repack(
        self,
        session_id: str,
        variants: Optional[Iterable[str]] = None,
        gadget: Optional[str] = None,
        confirmation: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> dict:
        """Repack destrutivo em duas etapas.

        Sem ``confirmation``: persiste a ação pendente e devolve o token.
        Com ``confirmation``: consome o token (uso único) e executa o
        teste, respeitando ``timeout``.
        """
        session_id = _require_session_id(session_id)
        state = self._state(session_id)
        service = self._service(
            self._config_from_state(state), resume=True
        )
        if not confirmation:
            try:
                return service.request_repack(
                    variants=variants, gadget=gadget
                )
            except BaseException as exc:  # noqa: BLE001 - fronteira
                raise _to_tool_error(exc) from exc
        limit = _clamp_timeout(timeout, self.run_timeout)
        future = self._executor.submit(
            service.run_repack, confirmation, variants, gadget
        )
        try:
            future.result(timeout=limit)
        except FutureTimeout as exc:
            # A execução continua; o cliente acompanha por status/cancelar.
            raise ToolTimeout(
                f"repack da sessão {session_id} não terminou em {limit:g}s; "
                "acompanhe com status ou cancele com cancelar"
            ) from exc
        except BaseException as exc:  # noqa: BLE001 - fronteira da ferramenta
            raise _to_tool_error(exc) from exc
        return self.store.status_payload(service.state)

    def _config_from_state(self, state: SessionState) -> RunConfig:
        config_data = dict(state.config or {})
        config_data.setdefault("package", state.package)
        config_data.setdefault("state_dir", str(self.store.root))
        config_data["session_id"] = state.session_id
        if state.device and state.device.get("serial"):
            config_data.setdefault("device_id", state.device["serial"])
        known = set(RunConfig.__dataclass_fields__)
        return RunConfig(
            **{key: value for key, value in config_data.items() if key in known}
        )


__all__ = [
    "ERROR_CODES",
    "TOOL_ERROR_CODES",
    "RaspilotTools",
    "ToolBusy",
    "ToolConfirmationRequired",
    "ToolDeviceRequired",
    "ToolError",
    "ToolInvalidState",
    "ToolNotFound",
    "ToolTimeout",
    "safe_call",
]
