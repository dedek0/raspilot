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
import shutil
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

import paths

try:  # POSIX (Linux/macOS)
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger("raspilot.sessions")

SESSION_SCHEMA = 1
DEFAULT_KEEP = 15

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


class SessionNotFound(SessionError):
    """Sessão inexistente."""


class SessionBusy(SessionError):
    """Já existe uma execução em andamento no mesmo device."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    def touch(self) -> None:
        """Atualiza ``updated_at``."""
        self.updated_at = _now()

    def advance(self, stage: str) -> None:
        """Avança a etapa sem nunca regredir."""
        if STAGE_ORDER.get(stage, 0) >= STAGE_ORDER.get(self.stage, 0):
            self.stage = stage

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

    def load(self, session_id: str) -> SessionState:
        """Carrega ``session.json`` de uma sessão existente."""
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
        return SessionState.from_dict(data, directory=str(directory.resolve()))

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


def _tool_version() -> str:
    try:
        from device_manager import TOOL_VERSION

        return TOOL_VERSION
    except Exception:  # pragma: no cover
        return "unknown"
