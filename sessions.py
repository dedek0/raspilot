"""RASPilot — sessões persistentes.

Uma sessão é a unidade retomável de auditoria: guarda pacote, device,
identidade do APK, perfil estático, resultados por check, erros/skips,
progresso e caminhos dos relatórios em
``<state_dir>/<session_id>/``.

Layout::

    <state_dir>/<session_id>/
        session.json      estado completo (escrita atômica)
        static.json       perfil estático puro
        report.json       último documento de relatório
        summary.json      apenas o summary do relatório
        report.html       relatório HTML
        checks/<check>.json
        artifacts/        APKs do repack, quando mantidos
        logs/             espaço reservado para logs da sessão

Concorrência: cada device tem um lock em ``<state_dir>/.locks/``. O
objetivo é impedir duas execuções simultâneas no mesmo aparelho, já que
frida-server/logcat/spawn são recursos exclusivos.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

import paths

try:  # POSIX (Linux/macOS)
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger("raspilot.sessions")

SESSION_SCHEMA = 2
DEFAULT_KEEP = 15

# Um ``running`` sem PID vivo é órfão. Quando não há PID (sessão antiga),
# o heartbeat é a única evidência: passado esse teto, também é órfão.
RUNNING_STALE_SECONDS = 900.0
ACTION_TTL_SECONDS = 900.0

# Status possíveis de uma sessão. ``interrupted`` é atribuído quando o
# processo dono do ``running`` morreu (queda/restart) e ninguém fechou a
# sessão; não é o mesmo que ``cancelled`` (pedido explícito).
SESSION_STATUSES = (
    "pending",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "interrupted",
)

# Códigos estáveis expostos aos clientes (CLI/MCP). O código é estável;
# a mensagem não é contrato.
ERROR_CODES = (
    "session_error",
    "session_not_found",
    "session_busy",
    "invalid_session_state",
    "confirmation_required",
    "confirmation_expired",
    "confirmation_mismatch",
    "invalid_confirmation",
    "device_required",
    "device_mismatch",
    "check_error",
    "connect_error",
    "pipeline_error",
    "cancelled",
    "timeout",
    "interrupted",
)

# Ordem das etapas analíticas. Relatório não é etapa: é uma ação sobre
# o estado já existente.
STAGE_ORDER = {
    "created": 0,
    "static": 1,
    "detect": 2,
    "bypass": 3,
    "full": 4,
}


class SessionError(Exception):
    """Erro de sessão (estado inválido, incompatível ou inexistente)."""

    code = "session_error"


class SessionNotFound(SessionError):
    """Sessão inexistente."""

    code = "session_not_found"


class SessionBusy(SessionError):
    """Já existe uma execução em andamento no mesmo device."""

    code = "session_busy"


class SessionTimeout(SessionError):
    """A sessão não saiu de ``running``/``pending`` dentro do timeout."""

    code = "timeout"


class SessionConfirmationError(SessionError):
    """Confirmação de ação destrutiva ausente, inválida ou expirada."""

    code = "confirmation_required"

    def __init__(self, message: str, code: Optional[str] = None) -> None:
        super().__init__(message)
        if code:
            self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Converte um timestamp ISO em ``datetime`` UTC (ou ``None``)."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_seconds(value: Optional[str]) -> Optional[float]:
    parsed = _parse_iso(value)
    if parsed is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())


def _pid_alive(pid: Any) -> bool:
    """``True`` se o PID existe (ou não pode ser checado por permissão)."""
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, ValueError):
        return False
    return True


def _public_action(pending: Optional[dict], reveal_token: bool = False) -> Optional[dict]:
    """Versão pública de ``pending_action`` (sem vazar o token por padrão)."""
    if not pending:
        return None
    public = {
        key: pending[key]
        for key in (
            "action",
            "created_at",
            "expires_at",
            "session_id",
            "device",
            "payload",
        )
        if key in pending
    }
    if reveal_token:
        public["confirmation_token"] = pending.get("token")
    return public


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value or "").strip("_") or "app"


def _atomic_write(path: Path, data: str) -> None:
    """Grava ``data`` em ``path`` via arquivo temporário + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(
        f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}"
    )
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            if tmp.exists():
                tmp.unlink()


def _read_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


@dataclass
class SessionState:
    """Estado serializável de uma auditoria."""

    session_id: str
    package: str
    directory: str
    created_at: str
    updated_at: str
    schema_version: int = SESSION_SCHEMA
    device: Optional[dict] = None
    apk: Optional[dict] = None
    config: dict = field(default_factory=dict)
    stage: str = "created"
    status: str = "pending"
    mode: str = "bypass"
    static: Optional[dict] = None
    results: Dict[str, dict] = field(default_factory=dict)
    timings: Dict[str, float] = field(default_factory=dict)
    skips: Dict[str, str] = field(default_factory=dict)
    errors: List[dict] = field(default_factory=list)
    invalidations: List[dict] = field(default_factory=list)
    reports: Dict[str, str] = field(default_factory=dict)
    progress: dict = field(default_factory=dict)
    run_context: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    last_action: str = ""
    cancel_requested: bool = False
    pending_action: Optional[dict] = None

    def touch(self) -> None:
        """Atualiza ``updated_at``."""
        self.updated_at = _now()

    def advance(self, stage: str) -> None:
        """Avança a etapa sem nunca regredir."""
        if STAGE_ORDER.get(stage, 0) >= STAGE_ORDER.get(self.stage, 0):
            self.stage = stage

    def is_active(self) -> bool:
        """``True`` enquanto a sessão pode receber novas etapas/consultas."""
        return self.status in ("pending", "running")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict, directory: str = "") -> "SessionState":
        known = {item.name for item in cls.__dataclass_fields__.values()}
        state = cls(
            **{key: value for key, value in data.items() if key in known}
        )
        if directory:
            state.directory = directory
        return state


class SessionStore:
    """Leitura/escrita de sessões em disco."""

    def __init__(self, root: Optional[str] = None, keep: Optional[int] = None) -> None:
        self.root = paths.state_dir(root)
        self.keep = int(
            keep
            or os.environ.get("RASPILOT_SESSIONS_KEEP")
            or DEFAULT_KEEP
        )

    # -- caminhos ------------------------------------------------------
    def session_dir(self, session_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", session_id or ""):
            raise SessionNotFound(f"session_id inválido: {session_id!r}")
        return self.root / session_id

    def path(self, state: SessionState, *parts: str) -> Path:
        return self.session_dir(state.session_id).joinpath(*parts)

    # -- criação/carga --------------------------------------------------
    def create(
        self,
        package: str,
        config: Any = None,
        device: Optional[dict] = None,
        apk: Optional[dict] = None,
    ) -> SessionState:
        """Cria uma sessão vazia com ID estável e único."""
        now = _now()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        session_id = (
            f"{stamp}_{_slug(package)}_{uuid.uuid4().hex[:6]}"
        )
        directory = self.session_dir(session_id)
        directory.mkdir(parents=True, exist_ok=False)
        for sub in ("checks", "artifacts", "logs"):
            (directory / sub).mkdir(exist_ok=True)
        config_dict = (
            asdict(config) if hasattr(config, "__dataclass_fields__") else dict(config or {})
        )
        state = SessionState(
            session_id=session_id,
            package=package,
            directory=str(directory.resolve()),
            created_at=now,
            updated_at=now,
            device=device,
            apk=apk,
            config=config_dict,
            metadata={
                "tool_name": "RASPilot",
                "tool_version": _tool_version(),
            },
        )
        self.save(state)
        self.prune()
        return state

    def load(self, session_id: str, reconcile: bool = True) -> SessionState:
        """Carrega ``session.json`` de uma sessão existente.

        Args:
            session_id: ID da sessão.
            reconcile: Quando ``True`` (padrão), uma sessão ``running``
                cujo processo dono morreu é marcada como ``interrupted``.
                A checagem usa o PID gravado no heartbeat; sessões antigas
                (sem PID) usam o tempo desde ``updated_at``.
        """
        directory = self.session_dir(session_id)
        path = directory / "session.json"
        if not path.is_file():
            raise SessionNotFound(f"sessão não encontrada: {session_id}")
        try:
            data = _read_json(path)
        except (OSError, ValueError) as exc:
            raise SessionError(
                f"session.json inválido em {session_id}: {exc}"
            ) from exc
        version = int(data.get("schema_version") or 0)
        if version > SESSION_SCHEMA:
            raise SessionError(
                f"sessão {session_id} usa schema {version}; "
                f"esta versão suporta até {SESSION_SCHEMA}"
            )
        state = SessionState.from_dict(data, directory=str(directory.resolve()))
        if reconcile:
            self.reconcile(state)
        return state

    def reconcile(
        self, state: SessionState, stale_after: float = RUNNING_STALE_SECONDS
    ) -> bool:
        """Fecha sessões ``running`` órfãs após queda do processo dono.

        Returns:
            ``True`` quando o estado foi corrigido e regravado.
        """
        if state.status != "running":
            return False
        progress = state.progress or {}
        owner = progress.get("pid")
        heartbeat = progress.get("heartbeat_at") or state.updated_at
        age = _age_seconds(heartbeat)
        if owner is not None:
            orphaned = not _pid_alive(owner)
            reason = (
                f"o processo {owner} que executava a sessão não existe mais"
            )
        else:
            orphaned = age is not None and age > stale_after
            reason = (
                "sessão em execução sem heartbeat recente "
                f"({age if age is not None else '?'}s)"
            )
        if not orphaned:
            return False
        state.status = "interrupted"
        state.progress = dict(progress)
        state.progress.update({
            "interrupted": True,
            "finished_at": _now(),
            "current_check": None,
            "updated_at": _now(),
        })
        state.errors.append({
            "check": "pipeline",
            "error": f"execução interrompida: {reason}",
            "code": "interrupted",
            "timestamp": _now(),
        })
        self.save(state)
        logger.warning(
            "Sessão %s marcada como interrupted (%s)",
            state.session_id,
            reason,
        )
        return True

    def list(self) -> List[SessionState]:
        """Lista sessões, mais recentes primeiro."""
        if not self.root.is_dir():
            return []
        states: List[SessionState] = []
        for child in self.root.iterdir():
            if not child.is_dir() or child.name.startswith("."):
                continue
            try:
                states.append(self.load(child.name))
            except SessionError:
                logger.debug("Sessão ignorada: %s", child, exc_info=True)
        states.sort(key=lambda item: item.updated_at, reverse=True)
        return states

    # -- persistência ---------------------------------------------------
    def save(self, state: SessionState) -> None:
        """Grava ``session.json`` de forma atômica."""
        state.touch()
        path = self.path(state, "session.json")
        _atomic_write(
            path,
            json.dumps(state.to_dict(), ensure_ascii=False, indent=2) + "\n",
        )

    def write_json(self, state: SessionState, name: str, payload: Any) -> Path:
        """Grava um JSON auxiliar dentro da sessão."""
        path = self.path(state, name)
        _atomic_write(
            path,
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        )
        return path

    def write_text(self, state: SessionState, name: str, payload: str) -> Path:
        """Grava um texto auxiliar dentro da sessão."""
        path = self.path(state, name)
        _atomic_write(path, payload)
        return path

    # -- ações destrutivas (confirmação em duas etapas) -----------------
    def request_action(
        self,
        state: SessionState,
        action: str,
        payload: Optional[dict] = None,
        ttl: float = ACTION_TTL_SECONDS,
        device: Optional[str] = None,
    ) -> dict:
        """Registra uma ação pendente na própria sessão.

        O token é único, fica ligado ao ``session_id`` e ao device do
        momento do pedido e só pode ser consumido uma vez. Nada é
        executado nesta etapa: a chamada seguinte deve apresentar o
        token (``confirm_action``).
        """
        created = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(24)
        serial = device or (state.device or {}).get("serial") or ""
        state.pending_action = {
            "action": action,
            "token": token,
            "created_at": created.isoformat(),
            "expires_at": (created + timedelta(seconds=ttl)).isoformat(),
            "session_id": state.session_id,
            "device": serial,
            "payload": dict(payload or {}),
        }
        self.save(state)
        return dict(state.pending_action)

    def clear_action(self, state: SessionState) -> None:
        """Remove qualquer ação pendente da sessão."""
        if state.pending_action is not None:
            state.pending_action = None
            self.save(state)

    def confirm_action(
        self,
        state: SessionState,
        token: str,
        action: Optional[str] = None,
        device: Optional[str] = None,
    ) -> dict:
        """Consome uma ação pendente e devolve o payload confirmado.

        Raises:
            SessionConfirmationError: sem ação pendente, token inválido,
                ação diferente, device diferente ou confirmação expirada.
        """
        pending = state.pending_action
        if not pending:
            raise SessionConfirmationError(
                "nenhuma ação pendente para esta sessão; "
                "solicite a confirmação primeiro",
                code="confirmation_required",
            )
        if action and pending.get("action") != action:
            raise SessionConfirmationError(
                f"a ação pendente é {pending.get('action')!r}, não {action!r}",
                code="confirmation_mismatch",
            )
        if pending.get("session_id") != state.session_id:
            raise SessionConfirmationError(
                "a confirmação pertence a outra sessão",
                code="confirmation_mismatch",
            )
        if not secrets.compare_digest(
            str(pending.get("token") or ""), str(token or "")
        ):
            raise SessionConfirmationError(
                "token de confirmação inválido",
                code="invalid_confirmation",
            )
        saved_device = pending.get("device")
        if device and saved_device and saved_device != "unknown" and (
            saved_device != device
        ):
            raise SessionConfirmationError(
                f"a confirmação foi emitida para o device {saved_device}, "
                f"não para {device}",
                code="confirmation_mismatch",
            )
        expires = _parse_iso(pending.get("expires_at"))
        if expires is not None and datetime.now(timezone.utc) > expires:
            state.pending_action = None
            self.save(state)
            raise SessionConfirmationError(
                "confirmação expirada; solicite uma nova",
                code="confirmation_expired",
            )
        confirmed = dict(pending.get("payload") or {})
        state.pending_action = None
        self.save(state)
        return confirmed

    # -- leitura agregada (CLI/MCP) -------------------------------------
    def status_payload(self, state: SessionState) -> dict:
        """Payload estável de ``status`` para CLI, testes e MCP.

        Não executa checks: lê ``session.json`` e os artefatos já
        gravados. Inclui caminhos de relatório, recursos e códigos de
        erro/skip/cancelamento.
        """
        checks: Dict[str, dict] = {}
        for name, result in (state.results or {}).items():
            payload = result if isinstance(result, dict) else {}
            if payload.get("skipped"):
                outcome = "skipped"
            elif payload.get("error"):
                outcome = "error"
            else:
                outcome = "ok"
            checks[name] = {
                "outcome": outcome,
                "skip_reason": payload.get("skip_reason"),
                "error": payload.get("error"),
            }
        for name, reason in (state.skips or {}).items():
            checks.setdefault(
                name,
                {"outcome": "skipped", "skip_reason": reason, "error": None},
            )
        errors = [
            {
                "check": item.get("check"),
                "error": item.get("error"),
                "code": item.get("code") or "check_error",
                "timestamp": item.get("timestamp"),
            }
            for item in (state.errors or [])
        ]
        if state.status == "cancelled":
            error_code = "cancelled"
        elif state.status == "interrupted":
            error_code = "interrupted"
        elif errors:
            error_code = errors[-1]["code"]
        elif state.status == "failed":
            error_code = "pipeline_error"
        else:
            error_code = None
        reports = dict(state.reports or {})
        resources = self.resources(state)
        device = state.device or {}
        payload = {
            "session_id": state.session_id,
            "package": state.package,
            "stage": state.stage,
            "status": state.status,
            "mode": state.mode,
            "device": {
                key: device.get(key)
                for key in ("serial", "model", "android_version", "abi")
                if device.get(key) is not None
            },
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "cancel_requested": bool(state.cancel_requested),
            "error_code": error_code,
            "progress": dict(state.progress or {}),
            "checks": checks,
            "skips": dict(state.skips or {}),
            "errors": errors,
            "reports": reports,
            "report_json": reports.get("report_json"),
            "report_html": reports.get("report_html"),
            "summary_json": reports.get("summary_json"),
            "resources": resources,
            "pending_action": _public_action(state.pending_action),
        }
        summary_path = reports.get("summary_json")
        if summary_path:
            with contextlib.suppress(OSError, ValueError):
                summary = _read_json(Path(summary_path))
                payload["summary"] = summary
                for name, item in summary.items():
                    if name in checks and isinstance(item, dict):
                        checks[name]["status"] = item.get("status")
        return payload

    def pending_action_payload(
        self, state: SessionState, reveal_token: bool = False
    ) -> Optional[dict]:
        """Ação pendente em formato público (token só quando pedido)."""
        return _public_action(state.pending_action, reveal_token)

    # -- retenção -------------------------------------------------------
    def prune(
        self,
        keep: Optional[int] = None,
        exclude: Iterable[str] = (),
    ) -> List[str]:
        """Remove as sessões mais antigas, mantendo as ``keep`` recentes.

        Sessões em execução (``status == "running"``) nunca são removidas.

        Returns:
            IDs removidos.
        """
        limit = int(keep or self.keep)
        excluded = set(exclude or ())
        states = [item for item in self.list() if item.session_id not in excluded]
        removed: List[str] = []
        for state in states[limit:]:
            if state.status == "running":
                continue
            shutil.rmtree(state.directory, ignore_errors=True)
            removed.append(state.session_id)
        if removed:
            logger.info("Retenção: %d sessão(ões) removida(s)", len(removed))
        return removed

    # -- lock por device ------------------------------------------------
    @contextlib.contextmanager
    def lock(self, key: str, timeout: float = 0.0) -> Iterator[None]:
        """Adquire um lock exclusivo por device.

        Args:
            key: Chave lógica (``device:<serial>``).
            timeout: Espera máxima em segundos (0 = falha imediata).

        Raises:
            SessionBusy: quando outra execução detém o lock.
        """
        if fcntl is None:  # pragma: no cover - Windows
            yield
            return
        locks = self.root / ".locks"
        locks.mkdir(parents=True, exist_ok=True)
        path = locks / f"{_slug(key)}.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + max(0.0, timeout)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        holder = ""
                        with contextlib.suppress(OSError):
                            holder = os.pread(fd, 500, 0).decode(
                                "utf-8", "replace"
                            ).strip()
                        raise SessionBusy(
                            f"já existe uma execução em andamento ({key}). "
                            f"{holder or 'lock ocupado'}"
                        )
                    time.sleep(0.2)
            info = json.dumps(
                {"pid": os.getpid(), "key": key, "since": _now()}
            )
            os.ftruncate(fd, 0)
            os.pwrite(fd, info.encode("utf-8"), 0)
            yield
        finally:
            with contextlib.suppress(OSError):
                os.ftruncate(fd, 0)
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # -- recursos MCP ----------------------------------------------------
    def resources(self, state: SessionState) -> Dict[str, str]:
        """Catálogo de URIs estáveis da sessão.

        As URIs são as planejadas para o MCP; os valores são caminhos
        absolutos. Recursos ainda inexistentes simplesmente não existem
        no disco, mas a URI é estável desde a criação da sessão.
        """
        base = f"raspilot://sessions/{state.session_id}"
        resources = {
            "raspilot://sessions": str(self.root),
            f"{base}/session.json": str(self.path(state, "session.json")),
            f"{base}/summary.json": str(self.path(state, "summary.json")),
            f"{base}/report.json": str(self.path(state, "report.json")),
            f"{base}/report.html": str(self.path(state, "report.html")),
            f"{base}/static.json": str(self.path(state, "static.json")),
        }
        for check in sorted(state.results):
            resources[f"{base}/checks/{check}.json"] = str(
                self.path(state, "checks", f"{check}.json")
            )
        return resources


def wait_for_status(
    store: SessionStore,
    session_id: str,
    timeout: float = 0.0,
    poll: float = 0.5,
) -> SessionState:
    """Aguarda a sessão sair de ``pending``/``running``.

    A leitura é feita do disco, então funciona entre processos (CLI,
    servidor MCP e executor). Não segura lock e não interfere na
    execução; serve para o timeout por ferramenta.

    Raises:
        SessionTimeout: quando o prazo termina com a sessão ainda ativa.
    """
    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        state = store.load(session_id)
        if not state.is_active():
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SessionTimeout(
                f"sessão {session_id} continua em {state.status!r} "
                f"após {timeout:g}s"
            )
        time.sleep(min(max(0.01, poll), remaining))


def _tool_version() -> str:
    try:
        from device_manager import TOOL_VERSION

        return TOOL_VERSION
    except Exception:  # pragma: no cover
        return "unknown"
