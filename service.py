"""RASPilot — camada de serviço headless.

O CLI (`main.py`) é apenas a camada de apresentação: parser, tabelas e
``rich``. Toda a orquestração — conectar ADB, subir o frida-server,
executar os checks, montar o relatório e limpar o dispositivo — vive
aqui, sem escrever em stdout. Isso permite reutilizar o mesmo fluxo no
CLI e, na fase seguinte, no servidor MCP (stdio exige stdout limpo).

Uso típico::

    service = RaspilotService(RunConfig(package="com.example.app"))
    result = service.run()
    print(result.json_path)

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from avd_manager import AvdConfig, AvdManager
from checks.anti_emulator import AntiEmulatorCheck
from checks.anti_frida import AntiFridaCheck
from checks.anti_hooking import AntiHookingCheck
from checks.anti_proxy import AntiProxyCheck
from checks.anti_root import AntiRootCheck
from checks.anti_tampering import AntiTamperingCheck
from checks.apk_utils import pull_apk
from checks.combined import run_combined_bypass, run_combined_observation
from checks.ssl_pinning import SSLPinningCheck
from checks.static import build_static_profile
from checks.static.engine import apk_digest
from device_manager import DeviceManager
from instrumentation import XposedManager
from reporter import Reporter
from script_loader import safe_detach, set_js_runtime
from sessions import (
    SessionBusy,
    SessionConfirmationError,
    SessionError,
    SessionState,
    SessionStore,
    SessionTimeout,
    wait_for_status,
)

logger = logging.getLogger("raspilot.service")

# Checks conhecidos — usado para validar --skip/--only.
KNOWN_CHECKS = (
    "anti_root", "anti_frida", "anti_tampering", "anti_emulator",
    "anti_hooking", "anti_proxy", "ssl_pinning",
)

# Executor compartilhado para execuções assíncronas (MCP/CLI). O lock
# por device em SessionStore serializa o que precisa ser serializado.
_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="raspilot-run")

# Registro em processo das sessões em execução. O lock em disco cobre
# outros processos; este mapa permite cancelar/consultar sem redescobrir
# o serviço e evita duas execuções no mesmo session_id neste processo.
_RUNNING_LOCK = threading.Lock()
_RUNNING_SERVICES: Dict[str, "RaspilotService"] = {}


class RunCancelled(Exception):
    """Execução cancelada entre dois checks."""

    code = "cancelled"


class RunTimeout(SessionTimeout):
    """A ferramenta esgotou o tempo de espera pela execução."""

    code = "timeout"


class SessionStateError(SessionError):
    """Estado de sessão incompatível com a etapa pedida."""

    code = "invalid_session_state"


# ----------------------------------------------------------------------
# Configuração
# ----------------------------------------------------------------------
@dataclass
class RunConfig:
    """Configuração serializável de uma execução.

    Os campos espelham as flags do CLI. O construtor
    :meth:`from_args` converte um ``argparse.Namespace``; o MCP e os
    testes podem montar a configuração diretamente, sem simular a CLI.
    """

    package: str
    device_id: Optional[str] = None
    wifi: Optional[str] = None
    output_dir: str = "reports/"
    stage: str = "full"
    only: Optional[List[str]] = None
    skip: List[str] = field(default_factory=list)
    apk: Optional[str] = None
    json_only: bool = False
    window: int = 15
    baseline_window: int = 5
    no_baseline: bool = False
    mode: str = "bypass"
    no_java: bool = False
    hook_method: str = "auto"
    emulator_method: str = "auto"
    proxy_method: str = "auto"
    module_apk: Optional[str] = None
    static_engine: str = "auto"
    static_timeout: float = 60.0
    java_timeout: float = 30.0
    js_runtime: str = "qjs"
    verbose: bool = False
    # Repack / anti-tampering.
    tamper_method: str = "auto"
    tamper_allow_reinstall: bool = False
    tamper_variants: List[str] = field(
        default_factory=lambda: ["asset", "dex"]
    )
    tamper_installer: Optional[str] = None
    tamper_no_restore: bool = False
    tamper_keep_artifacts: bool = False
    tamper_timeout: int = 600
    tamper_gadget: Optional[str] = None
    tamper_gadget_port: int = 27043
    tamper_gadget_mode: str = "listen"
    tamper_gadget_script: Optional[str] = None
    tamper_key: Optional[str] = None
    tamper_key_alias: str = "raspilot"
    tamper_key_pass: str = "android"
    tamper_store_pass: str = "android"
    # AVD.
    avd: bool = False
    avd_config: Optional[str] = None
    avd_name: Optional[str] = None
    # Sessão (fase 3).
    state_dir: Optional[str] = None
    session_id: Optional[str] = None

    @classmethod
    def from_args(cls, args: Any) -> "RunConfig":
        """Converte um ``argparse.Namespace`` do CLI em ``RunConfig``.

        Args:
            args: Namespace produzido por ``main.parse_args``.

        Returns:
            Configuração equivalente.
        """
        return cls(
            package=args.package,
            device_id=args.device_id,
            wifi=args.wifi,
            output_dir=args.output_dir,
            stage=getattr(args, "stage", "full"),
            only=list(getattr(args, "only", None) or []) or None,
            skip=list(args.skip or []),
            apk=getattr(args, "apk", None),
            json_only=bool(getattr(args, "json_only", False)),
            window=args.window,
            baseline_window=args.baseline_window,
            no_baseline=bool(getattr(args, "no_baseline", False)),
            mode=args.mode,
            no_java=bool(args.no_java),
            hook_method=getattr(args, "hook_method", "auto"),
            emulator_method=getattr(args, "emulator_method", "auto"),
            proxy_method=getattr(args, "proxy_method", "auto"),
            module_apk=getattr(args, "module_apk", None),
            static_engine=getattr(args, "static_engine", "auto"),
            static_timeout=getattr(args, "static_timeout", 60.0),
            java_timeout=getattr(args, "java_timeout", 30.0),
            js_runtime=getattr(args, "js_runtime", "qjs"),
            verbose=bool(getattr(args, "verbose", False)),
            tamper_method=getattr(args, "tamper_method", "auto"),
            tamper_allow_reinstall=bool(
                getattr(args, "tamper_allow_reinstall", False)
            ),
            tamper_variants=list(
                getattr(args, "tamper_variant", None) or ["asset", "dex"]
            ),
            tamper_installer=getattr(args, "tamper_installer", None),
            tamper_no_restore=bool(getattr(args, "tamper_no_restore", False)),
            tamper_keep_artifacts=bool(
                getattr(args, "tamper_keep_artifacts", False)
            ),
            tamper_timeout=int(getattr(args, "tamper_timeout", 600)),
            tamper_gadget=getattr(args, "tamper_gadget", None),
            tamper_gadget_port=int(
                getattr(args, "tamper_gadget_port", 27043)
            ),
            tamper_gadget_mode=getattr(args, "tamper_gadget_mode", "listen"),
            tamper_gadget_script=getattr(args, "tamper_gadget_script", None),
            tamper_key=getattr(args, "tamper_key", None),
            tamper_key_alias=getattr(args, "tamper_key_alias", "raspilot"),
            tamper_key_pass=getattr(args, "tamper_key_pass", "android"),
            tamper_store_pass=getattr(args, "tamper_store_pass", "android"),
            avd=bool(getattr(args, "avd", False)),
            avd_config=getattr(args, "avd_config", None),
            avd_name=getattr(args, "avd_name", None),
            state_dir=getattr(args, "state_dir", None),
            session_id=(
                getattr(args, "session", None)
                or getattr(args, "session_id", None)
            ),
        )

    def run_context_args(self) -> dict:
        """Representação do ``cli_args`` gravada no relatório.

        Mantém as mesmas chaves do schema já publicado para não quebrar
        consumidores que leem ``metadata.run.cli_args``.
        """
        return {
            "mode": self.mode,
            "no_java": bool(self.no_java),
            "window": self.window,
            "baseline_window": self.baseline_window,
            "java_timeout": self.java_timeout,
            "js_runtime": self.js_runtime,
            "skip": list(self.skip or []),
            "device_id": self.device_id,
            "wifi": self.wifi,
            "hook_method": self.hook_method,
            "emulator_method": self.emulator_method,
            "proxy_method": self.proxy_method,
            "module_apk": self.module_apk,
            "static_engine": self.static_engine,
            "static_timeout": self.static_timeout,
            "tamper_method": self.tamper_method,
            "tamper_variants": list(self.tamper_variants or []),
            "tamper_allow_reinstall": self.tamper_allow_reinstall,
            "tamper_installer": self.tamper_installer,
            "tamper_no_restore": self.tamper_no_restore,
            "tamper_keep_artifacts": self.tamper_keep_artifacts,
            "tamper_timeout": int(self.tamper_timeout),
            "tamper_gadget": self.tamper_gadget,
            "tamper_gadget_port": int(self.tamper_gadget_port),
            "tamper_gadget_mode": self.tamper_gadget_mode,
            "tamper_gadget_script": self.tamper_gadget_script,
            "tamper_key": self.tamper_key,
            "tamper_key_alias": self.tamper_key_alias,
            "stage": self.stage,
            "only": list(self.only or []),
            "apk": self.apk,
            "json_only": bool(self.json_only),
            "avd": {
                "enabled": bool(self.avd),
                "config_path": self.avd_config,
                "avd_name": self.avd_name,
            },
        }


# ----------------------------------------------------------------------
# Progresso (CLI usa rich; MCP/testes usam o sink nulo)
# ----------------------------------------------------------------------
class ProgressSink:
    """Sink de progresso que não escreve nada.

    O CLI substitui por uma implementação com ``rich``. O serviço nunca
    imprime diretamente, para que o mesmo código rode em stdio/MCP.
    """

    def status(self, message: str):
        """Context manager de status (spinner no CLI)."""
        return contextlib.nullcontext()

    def info(self, message: str) -> None:
        """Mensagem informativa."""

    def success(self, message: str) -> None:
        """Mensagem de sucesso."""

    def warning(self, message: str) -> None:
        """Mensagem de aviso."""

    def check_done(self, check_name: str, result: dict) -> None:
        """Check concluído."""

    def check_skipped(self, check_name: str, reason: str) -> None:
        """Check pulado."""


# ----------------------------------------------------------------------
# Resultados
# ----------------------------------------------------------------------
@dataclass
class StaticResult:
    """Resultado do estágio estático."""

    profile: dict
    device_info: dict = field(default_factory=dict)


@dataclass
class RunResult:
    """Resultado de uma execução dinâmica."""

    reporter: Reporter
    device_info: dict
    static_profile: Optional[dict]
    json_path: str = ""
    html_path: str = ""
    timings: Dict[str, float] = field(default_factory=dict)
    errors: List[dict] = field(default_factory=list)


# ----------------------------------------------------------------------
# Serviço
# ----------------------------------------------------------------------
class RaspilotService:
    """Orquestra uma auditoria sem depender da CLI.

    Args:
        config: Configuração da execução.
        device: ``DeviceManager`` opcional (injetado em testes ou por
            uma sessão já conectada).
        reporter: ``Reporter`` opcional (para retomar resultados).
        progress: Sink de progresso; o padrão não escreve nada.
    """

    def __init__(
        self,
        config: RunConfig,
        device: Optional[DeviceManager] = None,
        reporter: Optional[Reporter] = None,
        progress: Optional[ProgressSink] = None,
        store: Optional[SessionStore] = None,
        state: Optional[SessionState] = None,
    ) -> None:
        self.config = config
        self.dm = device
        self.reporter = reporter
        self.progress = progress or ProgressSink()
        self.store = store
        self.state = state
        self.static_profile: Optional[dict] = None
        self.device_info: Dict[str, Any] = {}
        self.timings: Dict[str, float] = {}
        self.errors: List[dict] = []
        self.skip: Set[str] = set()
        self.session = None
        self.pid: Optional[int] = None
        self._xposed = None
        self._avd: Optional[AvdManager] = None
        self._owns_device = device is None
        self._cancel = threading.Event()
        self._future: Optional[Future] = None
        if state is not None:
            self.static_profile = state.static

    # -- fábricas -------------------------------------------------------
    @classmethod
    def create(
        cls,
        config: RunConfig,
        store: Optional[SessionStore] = None,
        progress: Optional[ProgressSink] = None,
        device: Optional[DeviceManager] = None,
    ) -> "RaspilotService":
        """Cria uma nova sessão e devolve o serviço associado."""
        store = store or SessionStore(config.state_dir)
        state = store.create(config.package, config)
        config.session_id = state.session_id
        return cls(
            config,
            device=device,
            progress=progress,
            store=store,
            state=state,
        )

    @classmethod
    def resume(
        cls,
        config: RunConfig,
        store: Optional[SessionStore] = None,
        progress: Optional[ProgressSink] = None,
        device: Optional[DeviceManager] = None,
    ) -> "RaspilotService":
        """Carrega uma sessão existente e devolve o serviço associado.

        A configuração usa o pacote da sessão (o ``--package`` pode ser
        omitido) e, se o device não foi informado, reutiliza o serial
        salvo — o que também impede retomar no aparelho errado.
        """
        if not config.session_id:
            raise SessionStateError("--session é obrigatório para retomar")
        store = store or SessionStore(config.state_dir)
        state = store.load(config.session_id)
        if config.package and config.package != state.package:
            raise SessionStateError(
                f"sessão {state.session_id} pertence a {state.package}, "
                f"não a {config.package}"
            )
        config.package = state.package
        serial = (state.device or {}).get("serial")
        if not config.device_id and serial and serial != "unknown":
            config.device_id = serial
        return cls(
            config,
            device=device,
            progress=progress,
            store=store,
            state=state,
        )

    def request_cancel(self) -> None:
        """Solicita cancelamento entre dois checks.

        O flag é gravado em ``session.json`` e também no evento local.
        Uma sessão que ainda não começou é cancelada imediatamente; uma
        que já está rodando para no próximo limite entre checks.
        """
        self._cancel.set()
        if self.state is None or self.store is None:
            return
        self.state.cancel_requested = True
        self.state.progress = dict(self.state.progress or {})
        self.state.progress["cancel_requested_at"] = self._now()
        self.state.progress["updated_at"] = self._now()
        self.store.save(self.state)
        future = self._future
        if future is not None and future.cancel():
            self.state.status = "cancelled"
            self.state.progress["finished_at"] = self._now()
            self.state.progress["current_check"] = None
            self.store.save(self.state)

    @classmethod
    def cancel_session(
        cls, session_id: str, store: Optional[SessionStore] = None
    ) -> dict:
        """Cancela uma sessão, esteja ela local ou em outro processo.

        Chamadas repetidas são idempotentes para sessões já encerradas.
        """
        store = store or SessionStore()
        with _RUNNING_LOCK:
            service = _RUNNING_SERVICES.get(session_id)
        if service is not None:
            service.request_cancel()
            return store.status_payload(service.state)
        state = store.load(session_id)
        if state.status in ("pending", "running"):
            state.cancel_requested = True
            state.progress = dict(state.progress or {})
            state.progress["cancel_requested_at"] = cls._now()
            state.progress["updated_at"] = cls._now()
            store.save(state)
        return store.status_payload(state)

    def run_async(self) -> Future:
        """Executa :meth:`run` no executor compartilhado.

        O estado é marcado como ``running`` antes do submit e o
        ``run_async`` retorna imediatamente. Um cliente MCP acompanha
        ``session.json``/``progress`` (ou chama :meth:`wait`); um segundo
        ``run_async`` para a mesma sessão falha com :class:`SessionBusy`.
        """
        session_id = self.state.session_id if self.state is not None else None
        if session_id:
            with _RUNNING_LOCK:
                if session_id in _RUNNING_SERVICES:
                    raise SessionBusy(
                        f"a sessão {session_id} já está em execução"
                    )
                _RUNNING_SERVICES[session_id] = self
        self._mark_running(self.config.stage)
        try:
            future = _EXECUTOR.submit(self.run)
        except Exception:
            if session_id:
                with _RUNNING_LOCK:
                    _RUNNING_SERVICES.pop(session_id, None)
            raise
        self._future = future
        if session_id:
            future.add_done_callback(
                lambda _future, sid=session_id: self._end_async(sid)
            )
        return future

    def _end_async(self, session_id: str) -> None:
        with _RUNNING_LOCK:
            _RUNNING_SERVICES.pop(session_id, None)

    def wait(self, timeout: float = 0.0, poll: float = 0.5) -> dict:
        """Aguarda a execução local e devolve o status consolidado.

        Raises:
            RunTimeout: quando ``timeout > 0`` e a execução não terminou.
        """
        if self.state is None:
            raise SessionStateError("status exige uma sessão carregada")
        future = self._future
        if future is not None:
            try:
                future.result(timeout=None if timeout <= 0 else timeout)
            except FutureTimeout as exc:
                raise RunTimeout(
                    f"sessão {self.state.session_id} não terminou em "
                    f"{timeout:g}s"
                ) from exc
            except Exception:
                # A falha já está registrada em session.json/errors.
                logger.debug("Execução assíncrona terminou com erro", exc_info=True)
        elif timeout > 0 and self.store is not None:
            wait_for_status(self.store, self.state.session_id, timeout, poll)
        return self.status()

    def _mark_running(self, stage: str, total: Optional[int] = None) -> None:
        """Grava ``running`` com PID/heartbeat antes de qualquer check."""
        if self.state is None or self.store is None:
            return
        now = self._now()
        self.state.status = "running"
        self.state.progress = {
            "stage": stage,
            "pid": os.getpid(),
            "started_at": now,
            "heartbeat_at": now,
            "updated_at": now,
            "current_check": None,
        }
        if total is not None:
            self.state.progress["total"] = total
        self.store.save(self.state)

    def _cancel_requested_on_disk(self) -> bool:
        """Lê ``cancel_requested`` do disco (cancelamento entre processos)."""
        if self.state is None or self.store is None:
            return False
        try:
            state = self.store.load(self.state.session_id)
        except SessionError:
            return False
        if state.cancel_requested:
            self.state.cancel_requested = True
            return True
        return False

    # -- utilidades ----------------------------------------------------
    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _effective_skip(self) -> Set[str]:
        """Aplica ``--stage`` e ``--only`` como o CLI históricamente faz."""
        config = self.config
        if config.stage == "detect":
            config.mode = "detect"
        elif config.stage == "bypass" and config.mode == "detect":
            # ``bypass`` não pode ser uma detecção disfarçada.
            config.mode = "bypass"
        only = [item for item in (config.only or []) if item in KNOWN_CHECKS]
        skip = set(config.skip or [])
        if only:
            skip |= set(KNOWN_CHECKS) - set(only)
        self.skip = skip
        return skip

    def _run_step(
        self,
        check_name: str,
        step,
        skipped: bool = False,
        skip_reason: str = "",
    ) -> Optional[dict]:
        """Executa um check com isolamento de falhas e coleta de métricas."""
        if skipped:
            result: dict = {"skipped": True}
            if skip_reason:
                result["skip_reason"] = skip_reason
            self.reporter.collect(check_name, result)
            if self.state is not None:
                self.state.skips[check_name] = skip_reason or "check pulado"
                self._persist_progress(check_name, done=True)
            self.progress.check_skipped(
                check_name, skip_reason or "check pulado"
            )
            return None

        if self._cancel.is_set() or self._cancel_requested_on_disk():
            raise RunCancelled("execução cancelada antes de " + check_name)
        if self.state is not None:
            self._persist_progress(check_name, done=False)

        started = time.monotonic()
        try:
            with self.progress.status(f"Executando {check_name}"):
                result = step()
        except RunCancelled:
            raise
        except Exception as exc:  # isolamento total entre fases
            elapsed = time.monotonic() - started
            self.timings[check_name] = elapsed
            logger.warning(
                "Check %s falhou: %s", check_name, exc, exc_info=True
            )
            self.errors.append({
                "check": check_name,
                "error": str(exc),
                "code": "check_error",
                "timestamp": self._now(),
            })
            self.reporter.collect(check_name, {"error": str(exc)})
            if self.state is not None:
                self._persist_progress(check_name, done=True)
            self.progress.warning(f"{check_name}: ERROR ({exc})")
            return None

        self.timings[check_name] = time.monotonic() - started
        self.reporter.collect(check_name, result)
        if self.state is not None:
            self._persist_progress(check_name, done=True)
        self.progress.check_done(check_name, result)
        return result

    def _persist_progress(self, check_name: str, done: bool) -> None:
        """Atualiza ``session.json`` e o heartbeat após/antes de cada check."""
        if self.state is None or self.store is None:
            return
        now = self._now()
        progress = self.state.progress
        progress["current_check"] = None if done else check_name
        progress["updated_at"] = now
        progress["heartbeat_at"] = now
        progress["pid"] = os.getpid()
        if done:
            progress["completed"] = int(progress.get("completed") or 0) + 1
        self.store.save(self.state)

    def _activate_avd(self) -> Optional[AvdManager]:
        """Sobe o AVD configurado, se ``config.avd`` estiver ligado."""
        if not self.config.avd:
            return None
        config = AvdConfig.load(self.config.avd_config)
        if self.config.avd_name:
            config.avd_name = self.config.avd_name
        manager = AvdManager(config)
        with self.progress.status(f"Iniciando AVD {config.avd_name}"):
            serial = manager.start()
        self._avd = manager
        self.progress.success(f"AVD online: {serial}")
        self.config.device_id = serial
        return manager

    def _connect(self) -> DeviceManager:
        """Cria/conecta o ``DeviceManager`` uma única vez."""
        if self.dm is not None:
            return self.dm
        self._activate_avd()
        dm = DeviceManager(
            device_id=self.config.device_id,
            wifi_target=self.config.wifi,
            verbose=self.config.verbose,
        )
        try:
            dm.connect_adb()
        except Exception:
            if self._avd is not None:
                self._avd.stop()
                self._avd = None
            raise
        self.dm = dm
        return dm

    def _build_run_context(self) -> dict:
        """Monta ``metadata.run`` (reprodução da execução)."""
        try:
            import frida

            frida_version = frida.__version__
        except Exception:
            frida_version = None
        baseline = getattr(self.dm, "baseline", None)
        return {
            "cli_args": self.config.run_context_args(),
            "frida_client_version": frida_version,
            "frida_port": getattr(self.dm, "frida_port", None),
            "script_sha256": _script_hashes(),
            "baseline": baseline if isinstance(baseline, dict) else None,
            "logcat_capture": {
                "available": bool(getattr(self.dm, "_logcat_available", False)),
            },
        }

    def _ensure_static_profile(self) -> Optional[dict]:
        """Constrói o perfil estático uma vez, sem derrubar o pipeline."""
        if self.static_profile is not None:
            return self.static_profile
        if self.config.static_engine == "off":
            return None
        with self.progress.status("Analisando o APK (estático)"):
            try:
                profile = build_static_profile(
                    self.dm,
                    self.config.package,
                    apk_path=self.config.apk,
                    engine=self.config.static_engine,
                    timeout=self.config.static_timeout,
                )
            except Exception as exc:  # o ASC não pode derrubar o pipeline
                logger.warning("Análise estática falhou", exc_info=True)
                self.progress.warning(f"Estático indisponível: {exc}")
                return None
        self.static_profile = profile
        if profile and profile.get("available"):
            summary = profile.get("summary") or {}
            present = summary.get("vectors_present") or []
            engine = summary.get("engine") or "?"
            self.progress.success(
                f"Estático ({engine}): {len(present)} vetor(es) com indícios"
                + (f" — {', '.join(present)}" if present else "")
            )
        elif profile:
            reason = (profile.get("summary") or {}).get("error") or "indisponível"
            self.progress.warning(f"Estático: {reason}")
        return profile

    # -- estágio estático ---------------------------------------------
    def run_static(self) -> StaticResult:
        """Executa somente o perfil estático (sem Frida/spawn).

        Se ``config.apk`` não for informado, conecta ao dispositivo para
        puxar o APK. Retorna o perfil sem gravar arquivo — a persistência
        é responsabilidade do CLI/sessão.
        """
        if self.state is not None and self.store is not None:
            self._mark_running("static")
        try:
            if not self.config.apk:
                self._connect()
                self.device_info = self.dm.get_device_info()
                self.progress.success("Dispositivo conectado para obter o APK")
            profile = build_static_profile(
                self.dm,
                self.config.package,
                apk_path=self.config.apk,
                engine=self.config.static_engine,
                timeout=self.config.static_timeout,
            )
        except Exception as exc:
            if self.state is not None and self.store is not None:
                self.state.errors.append({
                    "check": "static",
                    "error": str(exc),
                    "timestamp": self._now(),
                })
                self.state.status = "failed"
                self.store.save(self.state)
            raise
        self.static_profile = profile
        if self.state is not None and self.store is not None:
            state = self.state
            previous = (state.apk or {}).get("sha256")
            current = (profile.get("apk") or {}).get("sha256")
            if previous and current and previous != current and state.results:
                state.invalidations.append({
                    "reason": "o perfil estático foi refeito para outro APK",
                    "timestamp": self._now(),
                })
                state.results = {}
                state.timings = {}
                state.skips = {}
                state.stage = "static"
            if self.device_info:
                state.device = dict(self.device_info)
            state.static = profile
            state.apk = profile.get("apk")
            state.stage = "static" if state.stage in ("created", "static") else state.stage
            state.status = "succeeded"
            state.last_action = "static"
            state.progress = {
                "stage": "static",
                "finished_at": self._now(),
                "updated_at": self._now(),
            }
            static_path = self.store.write_json(state, "static.json", profile)
            state.reports["static_json"] = str(static_path)
            self.store.save(state)
            self.store.prune()
        return StaticResult(profile=profile, device_info=dict(self.device_info))

    # -- execução dinâmica --------------------------------------------
    def run(self) -> Any:
        """Executa a etapa pedida em ``config.stage``.

        ``static`` retorna :class:`StaticResult`; as demais etapas
        retornam :class:`RunResult`.
        """
        if self.config.stage == "static":
            return self.run_static()
        if self.config.stage == "report":
            return self.generate_report()
        return self.run_dynamic()

    # -- etapas explícitas (CLI e MCP) ----------------------------------
    def run_detection(self) -> RunResult:
        """Executa só a detecção (sem bypass) na sessão."""
        self.config.stage = "detect"
        self.config.mode = "detect"
        return self.run_dynamic(mode="detect")

    def run_bypass(self) -> RunResult:
        """Executa detecção+bypass; exige detecção prévia na sessão."""
        self.config.stage = "bypass"
        self.config.mode = "bypass"
        return self.run_dynamic(mode="bypass")

    def run_full(self) -> RunResult:
        """Executa o pipeline completo."""
        self.config.stage = "full"
        return self.run_dynamic()

    def save_state(self) -> None:
        """Persiste o estado atual (útil entre chamadas MCP)."""
        if self.state is not None and self.store is not None:
            self.store.save(self.state)

    def list_reports(self) -> Dict[str, str]:
        """Caminhos dos relatórios/artefatos da sessão."""
        if self.state is None:
            return {}
        return dict(self.state.reports)

    def resources(self) -> Dict[str, str]:
        """Catálogo de recursos da sessão (URIs → caminhos)."""
        if self.state is None or self.store is None:
            return {}
        return self.store.resources(self.state)

    def status(self) -> dict:
        """Status consolidado da sessão (sem executar checks)."""
        if self.state is None:
            raise SessionStateError("status exige uma sessão carregada")
        if self.store is None:
            raise SessionStateError("status exige um SessionStore")
        return self.store.status_payload(self.state)

    # -- repack destrutivo (confirmação em duas etapas) -----------------
    def _device_serial(self) -> str:
        saved = (self.state.device or {}) if self.state is not None else {}
        return str(self.config.device_id or saved.get("serial") or "")

    def request_repack(
        self,
        variants: Optional[Iterable[str]] = None,
        gadget: Optional[str] = None,
        ttl: float = 900.0,
    ) -> dict:
        """Etapa 1 do repack: persiste uma ação pendente na sessão.

        Não desinstala nada. Devolve o token de confirmação e o prazo;
        a etapa 2 (:meth:`run_repack`) consome o token uma única vez.
        """
        if self.state is None or self.store is None:
            raise SessionStateError(
                "o repack exige uma sessão (RaspilotService.create/resume)"
            )
        serial = self._device_serial()
        if not serial:
            error = SessionStateError(
                "selecione o device antes de pedir confirmação de repack"
            )
            error.code = "device_required"
            raise error
        payload = {
            "variants": list(
                variants or self.config.tamper_variants or ["asset", "dex"]
            ),
            "gadget": gadget,
            "destructive": True,
            "wipes_app_data": True,
        }
        self.store.request_action(
            self.state, "repack", payload, ttl=ttl, device=serial
        )
        pending = self.store.pending_action_payload(
            self.state, reveal_token=True
        ) or {}
        return {
            "session_id": self.state.session_id,
            "status": "confirmation_required",
            "destructive": True,
            "package": self.state.package,
            "device": serial,
            "confirmation_token": pending.get("confirmation_token"),
            "expires_at": pending.get("expires_at"),
            "variants": payload["variants"],
            "gadget": gadget,
        }

    def run_repack(
        self,
        confirmation: str,
        variants: Optional[Iterable[str]] = None,
        gadget: Optional[str] = None,
    ) -> dict:
        """Etapa 2 do repack: valida o token e executa o teste destrutivo.

        O token é de uso único, pertence a esta sessão e ao device atual.
        Sem token válido nada é desinstalado.
        """
        if self.state is None or self.store is None:
            raise SessionStateError(
                "o repack exige uma sessão (RaspilotService.create/resume)"
            )
        serial = self._device_serial()
        payload = self.store.confirm_action(
            self.state,
            confirmation,
            action="repack",
            device=serial,
        )
        chosen = list(
            variants
            or payload.get("variants")
            or self.config.tamper_variants
            or ["asset", "dex"]
        )
        gadget_value = gadget or payload.get("gadget")
        self.config.tamper_method = "repack"
        self.config.tamper_allow_reinstall = True
        self.config.tamper_variants = chosen
        if gadget_value:
            self.config.tamper_gadget = str(gadget_value)
        return self._run_repack(chosen, gadget_value)

    def _run_repack(
        self, variants: Iterable[str], gadget: Optional[str]
    ) -> dict:
        from checks.tamper_repack import RepackTester

        config = self.config
        self.timings = {}
        self.errors = []
        self._mark_running("repack")
        try:
            self._connect()
            self.device_info = self.dm.get_device_info()
            self._validate_device()
            serial = self.device_info.get("serial") or "default"
            with self._device_lock(serial):
                self._prepare_reporter()
                self.reporter.static_profile = self.static_profile
                self._annotate_static_context()
                if self.state is not None:
                    self.reporter.run_context["session_id"] = (
                        self.state.session_id
                    )
                probe = RepackTester(
                    self.dm,
                    config.package,
                    apk_path=config.apk,
                    output_dir=self._artifacts_dir(),
                    window=config.window,
                    variants=tuple(variants),
                    installer=config.tamper_installer,
                    allow_reinstall=True,
                    restore=not config.tamper_no_restore,
                    keep_artifacts=config.tamper_keep_artifacts,
                    timeout=config.tamper_timeout,
                    gadget_path=(
                        str(gadget) if gadget else config.tamper_gadget
                    ),
                    gadget_port=config.tamper_gadget_port,
                    gadget_mode=config.tamper_gadget_mode,
                    gadget_script=config.tamper_gadget_script,
                    key_path=config.tamper_key,
                    key_alias=config.tamper_key_alias,
                    key_pass=config.tamper_key_pass,
                    store_pass=config.tamper_store_pass,
                ).run()
                self.reporter.collect(
                    "anti_tampering",
                    {
                        "method": "repack",
                        "static_detected": False,
                        **probe,
                    },
                )
                result = RunResult(
                    reporter=self.reporter,
                    device_info=dict(self.device_info),
                    static_profile=self.static_profile,
                )
                self._persist_session(
                    result, target=self.state.stage, action="repack"
                )
                return {
                    "session_id": self.state.session_id,
                    "status": self.state.status,
                    "package": config.package,
                    "device": serial,
                    "probe": probe,
                    "reports": dict(self.state.reports),
                }
        except Exception as exc:
            self.errors.append({
                "check": "anti_tampering",
                "error": str(exc),
                "code": "check_error",
                "timestamp": self._now(),
            })
            self._mark_finished("failed")
            raise
        finally:
            self._cleanup()

    def run_dynamic(
        self,
        mode: Optional[str] = None,
        skip: Optional[Iterable[str]] = None,
        static_profile: Optional[dict] = None,
    ) -> RunResult:
        """Executa o pipeline dinâmico (detect/bypass/full).

        Args:
            mode: Sobrescreve ``config.mode`` (ex: ``detect``).
            skip: Conjunto de checks a pular. Se omitido, aplica
                ``--only``/``--skip`` da configuração.
            static_profile: Perfil já carregado (retomada de sessão).

        Returns:
            Resultado com relatório salvo e métricas por check.
        """
        config = self.config
        if mode is not None:
            config.mode = mode
        if skip is not None:
            self.skip = set(skip)
        elif not self.skip:
            self._effective_skip()

        self._validate_stage()

        set_js_runtime(config.js_runtime)
        self.timings = {}
        self.errors = []
        if static_profile is not None:
            self.static_profile = static_profile

        if self.state is not None:
            self.state.cancel_requested = False
            self.state.mode = config.mode
            self._mark_running(
                config.stage,
                total=len(set(KNOWN_CHECKS) - self.skip),
            )
            self.state.progress.update({
                "completed": 0,
                "current_check": None,
            })
            if self.store is not None:
                self.store.save(self.state)

        try:
            self._connect()
            self.device_info = self.dm.get_device_info()
            self._validate_device()
        except Exception as exc:
            self.errors.append({
                "check": "connect",
                "error": str(exc),
                "code": "connect_error",
                "timestamp": self._now(),
            })
            self._mark_finished("failed")
            raise
        self.progress.success(
            "Dispositivo conectado: "
            f"{self.device_info.get('model')} "
            f"({self.device_info.get('serial')})"
        )

        serial = self.device_info.get("serial") or "default"
        with self._device_lock(serial):
            try:
                self.dm.setup_frida_server()
                self.progress.success(
                    "frida-server instalado, iniciado e validado"
                )

                if self.dm.start_logcat_capture():
                    logger.info("Captura de logcat ativa")
                else:
                    self.progress.warning(
                        "Captura de logcat indisponível (seguindo sem ela)"
                    )

                self._ensure_static_current()
                self._prepare_reporter()
                self.reporter.static_profile = self.static_profile
                self._annotate_static_context()
                if self.state is not None:
                    self.reporter.run_context["session_id"] = (
                        self.state.session_id
                    )
                self._xposed = self._prepare_instrumentation()

                if self._cancel.is_set() or self._cancel_requested_on_disk():
                    raise RunCancelled("execução cancelada")
                self._run_checks()

                json_path, html_path = self.reporter.save(
                    write_html=not config.json_only
                )
                result = RunResult(
                    reporter=self.reporter,
                    device_info=dict(self.device_info),
                    static_profile=self.static_profile,
                    json_path=json_path,
                    html_path=html_path,
                    timings=dict(self.timings),
                    errors=list(self.errors),
                )
                self._persist_session(result)
                return result
            except RunCancelled:
                self._mark_finished("cancelled")
                raise
            except Exception as exc:
                self.errors.append({
                    "check": "pipeline",
                    "error": str(exc),
                    "code": "pipeline_error",
                    "timestamp": self._now(),
                })
                self._mark_finished("failed")
                raise
            finally:
                self._cleanup()

    # -- validação e retomada ------------------------------------------
    @contextlib.contextmanager
    def _device_lock(self, serial: str):
        """Lock por device; sem store, executa sem lock (testes puros)."""
        if self.store is None:
            yield
            return
        try:
            with self.store.lock(f"device:{serial}"):
                yield
        except SessionBusy as exc:
            if self.state is not None and self.state.status == "running":
                self.errors.append({
                    "check": "lock",
                    "error": str(exc),
                    "code": "session_busy",
                    "timestamp": self._now(),
                })
                self._mark_finished("failed")
            raise

    def _validate_stage(self) -> None:
        """Aplica a regra bypass ⇐ detect e evita regressão de etapa."""
        stage = self.config.stage
        state = self.state
        if state is None:
            return
        if stage == "bypass" and state.stage not in (
            "detect", "bypass", "full",
        ):
            raise SessionStateError(
                "bypass exige uma detecção concluída na mesma sessão. "
                "Execute primeiro --stage detect (ou use --stage full)."
            )
        if stage == "detect" and state.stage in ("bypass", "full"):
            raise SessionStateError(
                "a sessão já possui bypass; rode --stage report para "
                "regenerar o relatório ou crie uma nova sessão"
            )
        if state.cancel_requested:
            raise SessionStateError(
                "a sessão foi cancelada; crie uma nova sessão"
            )

    def _validate_device(self) -> None:
        """Impede retomar uma sessão em outro aparelho."""
        state = self.state
        if state is None or not state.device:
            return
        saved = state.device.get("serial")
        current = self.device_info.get("serial")
        if saved and saved != "unknown" and current and current != saved:
            raise SessionStateError(
                f"sessão criada no device {saved}, mas o device atual é "
                f"{current}. Use o mesmo aparelho ou crie uma nova sessão."
            )

    def _ensure_static_current(self) -> None:
        """Reutiliza o perfil salvo; refaz se o APK mudou."""
        if self.config.static_engine == "off":
            return
        if self.static_profile is None:
            self._ensure_static_profile()
            return
        if self._static_matches_device():
            return
        reason = "o APK instalado mudou desde o perfil estático salvo"
        logger.warning("Perfil estático obsoleto: %s", reason)
        self.progress.warning(f"Perfil estático obsoleto: {reason}")
        if self.state is not None:
            self.state.invalidations.append({
                "reason": reason,
                "timestamp": self._now(),
            })
            # Resultados dinâmicos anteriores não valem para o APK novo.
            self.state.results = {}
            self.state.timings = {}
            self.state.skips = {}
            self.state.stage = "static"
        self.static_profile = None
        self._ensure_static_profile()

    def _static_matches_device(self) -> bool:
        """Compara o digest do APK atual com o perfil salvo.

        Se o APK não puder ser obtido (ex: pull indisponível), assume que
        o perfil continua válido — a validação é uma proteção extra, não
        um pré-requisito para a execução.
        """
        profile = self.static_profile or {}
        expected = (profile.get("apk") or {}).get("sha256")
        if not expected:
            return False
        try:
            if self.config.apk:
                paths = [self.config.apk]
            else:
                with tempfile.TemporaryDirectory(
                    prefix="raspilot_resume_"
                ) as tmp:
                    paths = pull_apk(self.dm, self.config.package, tmp)
            if not paths:
                return True
            return apk_digest(paths) == expected
        except OSError:
            return True

    def _prepare_reporter(self) -> None:
        """Cria o Reporter e semeia resultados anteriores da sessão."""
        if self.reporter is None:
            self.reporter = Reporter(
                device_info=self.device_info,
                package_name=self.config.package,
                output_dir=self.config.output_dir,
                run_context=self._build_run_context(),
            )
        else:
            self.reporter.device_info = dict(self.device_info)
            self.reporter.run_context.update(self._build_run_context())
        if self.state is not None:
            for name, result in (self.state.results or {}).items():
                self.reporter.collect(name, result)

    def _mark_finished(self, status: str) -> None:
        """Registra o desfecho da execução no estado da sessão."""
        if self.state is None or self.store is None:
            return
        now = self._now()
        self.state.status = status
        self.state.errors.extend(self.errors)
        self.state.progress = dict(self.state.progress or {})
        self.state.progress["finished_at"] = now
        self.state.progress["heartbeat_at"] = now
        self.state.progress["current_check"] = None
        if status == "cancelled":
            self.state.progress["code"] = "cancelled"
        self.state.updated_at = now
        self.store.save(self.state)
        if status == "succeeded":
            self.store.prune()

    def _persist_session(
        self,
        result: RunResult,
        target: Optional[str] = None,
        action: Optional[str] = None,
    ) -> None:
        """Grava relatório, summary, checks e estado da sessão."""
        state = self.state
        store = self.store
        if state is None or store is None:
            return

        doc = result.reporter.generate_json()
        state.device = dict(self.device_info)
        state.static = self.static_profile
        state.apk = (self.static_profile or {}).get("apk")
        state.results = dict(result.reporter.results)
        state.timings = dict(self.timings)
        state.skips = {
            name: (payload.get("skip_reason") or "check pulado")
            for name, payload in state.results.items()
            if payload.get("skipped")
        }
        state.run_context = dict(result.reporter.run_context)
        state.last_action = action or self.config.stage
        if target is None:
            if self.config.mode == "detect":
                target = "detect"
            elif self.config.stage == "full":
                target = "full"
            else:
                target = "bypass"
        state.advance(target)
        state.status = "succeeded" if state.results else "failed"
        state.progress.update({
            "stage": target,
            "finished_at": self._now(),
            "updated_at": self._now(),
            "current_check": None,
            "completed": len(state.results),
            "total": len(state.results),
        })

        report_json = store.write_json(state, "report.json", doc)
        summary_json = store.write_json(state, "summary.json", doc["summary"])
        state.reports = {
            "report_json": str(report_json),
            "summary_json": str(summary_json),
            "last_run_json": result.json_path,
        }
        if result.html_path:
            html = result.reporter.generate_html()
            report_html = store.write_text(state, "report.html", html)
            state.reports["report_html"] = str(report_html)
            state.reports["last_run_html"] = result.html_path
        for check, payload in state.results.items():
            store.write_json(state, f"checks/{check}.json", payload)
        if self.static_profile is not None:
            static_json = store.write_json(
                state, "static.json", self.static_profile
            )
            state.reports["static_json"] = str(static_json)

        self._mark_finished(state.status)

    # -- relatório sem device -------------------------------------------
    def generate_report(self, write_html: bool = True) -> RunResult:
        """Regenera o relatório a partir do estado salvo, sem device."""
        if self.state is None:
            raise SessionStateError(
                "generate_report exige uma sessão carregada"
            )
        state = self.state
        run_context = dict(state.run_context or {})
        run_context.setdefault("session_id", state.session_id)
        reporter = Reporter(
            device_info=state.device or {},
            package_name=state.package,
            output_dir=state.directory,
            run_context=run_context,
            timestamp=_existing_report_timestamp(store=self.store, state=state)
            or _parse_iso(state.created_at),
            static_profile=state.static,
        )
        for check, payload in state.results.items():
            reporter.collect(check, payload)

        doc = reporter.generate_json()
        if self.store is None:
            self.store = SessionStore(os.path.dirname(state.directory))
        store = self.store
        report_json = store.write_json(state, "report.json", doc)
        summary_json = store.write_json(state, "summary.json", doc["summary"])
        reports = {
            "report_json": str(report_json),
            "summary_json": str(summary_json),
        }
        html_path = ""
        if write_html:
            html = reporter.generate_html()
            reports["report_html"] = str(
                store.write_text(state, "report.html", html)
            )
            html_path = reports["report_html"]
        for check, payload in state.results.items():
            store.write_json(state, f"checks/{check}.json", payload)
        if state.static is not None:
            reports["static_json"] = str(
                store.write_json(state, "static.json", state.static)
            )
        state.reports = reports
        state.last_action = "report"
        state.status = "succeeded" if state.results else state.status
        state.progress["reported_at"] = self._now()
        store.save(state)
        return RunResult(
            reporter=reporter,
            device_info=dict(state.device or {}),
            static_profile=state.static,
            json_path=reports["report_json"],
            html_path=html_path,
        )

    def _annotate_static_context(self) -> None:
        """Resume o perfil estático em ``metadata.run.static``."""
        reporter = self.reporter
        profile = self.static_profile
        if reporter is None:
            return
        if profile and profile.get("available"):
            summary = profile.get("summary") or {}
            reporter.run_context["static"] = {
                "available": True,
                "engine": summary.get("engine"),
                "version": profile.get("version"),
                "vectors_present": summary.get("vectors_present") or [],
                "rasp_sdks": summary.get("rasp_sdks") or [],
                "classes_count": profile.get("classes_count"),
                "cached": bool(profile.get("cached")),
            }
        elif profile:
            reason = (profile.get("summary") or {}).get("error") or "indisponível"
            reporter.run_context["static"] = {
                "available": False,
                "engine": profile.get("engine"),
                "error": reason,
            }

    def _prepare_instrumentation(self) -> Optional[XposedManager]:
        """Cria o módulo de instrumentação quando o método permite."""
        config = self.config
        if config.hook_method == "frida" and config.emulator_method == "frida":
            return None
        try:
            xposed = XposedManager(
                self.dm, config.package, apk_path=config.module_apk
            )
            framework = xposed.detect()
            self.reporter.run_context["xposed"] = {
                "framework": framework.get("name"),
                "version": framework.get("version"),
                "available": bool(framework.get("available")),
                "details": framework.get("details"),
            }
            if framework.get("available"):
                self.progress.success(
                    "Framework de hooking: "
                    f"{framework.get('name')} {framework.get('version') or ''}"
                )
            else:
                self.progress.warning(
                    "Framework de hooking indisponível "
                    f"({framework.get('details')}) — usando Frida"
                )
            return xposed
        except Exception as exc:
            logger.warning(
                "Módulo de instrumentação indisponível", exc_info=True
            )
            self.progress.warning(f"Módulo de instrumentação indisponível: {exc}")
            return None

    def _run_checks(self) -> None:
        """Executa os checks na ordem histórica do pipeline."""
        config = self.config
        dm = self.dm
        reporter = self.reporter
        static_profile = self.static_profile
        skip = self.skip
        xposed = self._xposed

        self._run_step(
            "anti_root",
            lambda: AntiRootCheck(
                dm,
                mode=config.mode,
                no_java=config.no_java,
                xposed=xposed,
            ).run_all(
                static_profile=static_profile,
                package_name=config.package,
                window=config.window,
            ),
            skipped="anti_root" in skip,
        )

        dynamic = any(
            check not in skip
            for check in (
                "anti_frida", "anti_hooking", "ssl_pinning", "anti_emulator",
            )
        )
        if dynamic and not config.no_baseline:
            with self.progress.status("Executando baseline sem instrumentação"):
                dm.baseline = dm.run_app_baseline(
                    config.package, window=max(1, config.baseline_window)
                )
            if dm.baseline.get("available"):
                death = (
                    (dm.baseline.get("death_cause") or {}).get("summary")
                    if dm.baseline.get("death_cause") else "não"
                )
                self.progress.success(
                    f"Baseline: pid={dm.baseline.get('pid')} "
                    f"vivo={dm.baseline.get('alive_at_end')} morte={death}"
                )
            else:
                self.progress.warning(
                    "Baseline indisponível "
                    f"({dm.baseline.get('reason', 'sem pid')})"
                )
            # O run_context é criado antes do baseline; atualiza para que
            # o relatório registre o resultado efetivo.
            reporter.run_context["baseline"] = (
                dm.baseline if isinstance(dm.baseline, dict) else None
            )

        frida_logcat_mark = dm.logcat_mark()
        frida_detection = None
        hook_detection = None

        need_combined = any(
            check not in skip for check in ("anti_frida", "anti_hooking")
        )
        if need_combined:
            with self.progress.status(f"Spawning {config.package}"):
                self.session = dm.spawn_app(config.package, resume=False)
            self.pid = dm.get_app_pid(config.package)
            self.progress.success(f"App spawnado suspenso (pid={self.pid})")
            reporter.run_context["target_pid"] = self.pid
            if self.pid is not None:
                with self.progress.status(
                    "Observando camadas em sessão única"
                ):
                    frida_detection, hook_detection = run_combined_observation(
                        dm,
                        self.session,
                        self.pid,
                        config.package,
                        config.window,
                        frida_logcat_mark,
                        dm.resume_app,
                        mode=config.mode,
                        no_java=config.no_java,
                        java_timeout=config.java_timeout,
                    )

        if "anti_frida" not in skip:
            if self.pid is not None and frida_detection is not None:
                self._run_step(
                    "anti_frida",
                    lambda: AntiFridaCheck(
                        dm, mode=config.mode, no_java=config.no_java
                    ).run_all(
                        self.session, self.pid,
                        window=config.window,
                        package_name=config.package,
                        logcat_mark=frida_logcat_mark,
                        app_detection=frida_detection,
                        static_profile=static_profile,
                    ),
                )
            else:
                reporter.collect(
                    "anti_frida", {"error": "app não pôde ser spawnado"}
                )
                self.progress.warning("anti_frida: ERROR (app não spawnado)")

        hooking_bypass = None
        ssl_bypass = None
        if (
            "anti_hooking" not in skip
            and "ssl_pinning" not in skip
            and config.mode != "detect"
            and not config.no_java
            and config.hook_method == "frida"
        ):
            with self.progress.status("Executando bypass combinado"):
                hooking_bypass, ssl_bypass = run_combined_bypass(
                    dm, config.package, config.window,
                    mode=config.mode, no_java=config.no_java,
                    java_timeout=config.java_timeout,
                )

        self._run_step(
            "anti_hooking",
            lambda: AntiHookingCheck(
                dm, mode=config.mode, no_java=config.no_java,
                method=config.hook_method, xposed=xposed,
            ).run_all(
                config.package,
                window=config.window,
                apk_path=config.apk,
                precomputed_detection=hook_detection,
                precomputed_bypass=hooking_bypass,
                static_profile=static_profile,
            ),
            skipped="anti_hooking" in skip,
        )

        self._run_step(
            "ssl_pinning",
            lambda: SSLPinningCheck(
                dm, mode=config.mode, no_java=config.no_java,
                java_timeout=config.java_timeout,
            ).run_all(
                config.package, window=config.window,
                apk_path=config.apk,
                precomputed_bypass=ssl_bypass,
                static_profile=static_profile,
            ),
            skipped="ssl_pinning" in skip,
        )

        self._run_step(
            "anti_proxy",
            lambda: AntiProxyCheck(
                dm, mode=config.mode, no_java=config.no_java,
                java_timeout=config.java_timeout,
                method=config.proxy_method, xposed=xposed,
            ).run_all(
                config.package,
                window=config.window,
                apk_path=config.apk,
                static_profile=static_profile,
            ),
            skipped="anti_proxy" in skip,
        )

        self._run_step(
            "anti_tampering",
            lambda: AntiTamperingCheck(
                dm,
                mode=config.mode,
                no_java=config.no_java,
                method=config.tamper_method,
                xposed=xposed,
                repack_variants=tuple(config.tamper_variants or ("asset", "dex")),
                allow_reinstall=config.tamper_allow_reinstall,
                installer=config.tamper_installer,
                restore=not config.tamper_no_restore,
                keep_artifacts=config.tamper_keep_artifacts,
                output_dir=self._artifacts_dir(),
                repack_timeout=config.tamper_timeout,
                gadget_path=config.tamper_gadget,
                gadget_port=config.tamper_gadget_port,
                gadget_mode=config.tamper_gadget_mode,
                gadget_script=config.tamper_gadget_script,
                key_path=config.tamper_key,
                key_alias=config.tamper_key_alias,
                key_pass=config.tamper_key_pass,
                store_pass=config.tamper_store_pass,
            ).run_all(
                static_profile=static_profile,
                package_name=config.package,
                window=config.window,
                apk_path=config.apk,
            ),
            skipped="anti_tampering" in skip,
        )

        self._run_step(
            "anti_emulator",
            lambda: AntiEmulatorCheck(
                dm, mode=config.mode, no_java=config.no_java,
                java_timeout=config.java_timeout,
                method=config.emulator_method, xposed=xposed,
            ).run_all(
                config.package,
                window=config.window,
                apk_path=config.apk,
                static_profile=static_profile,
            ),
            skipped="anti_emulator" in skip,
        )

    def _artifacts_dir(self) -> str:
        """Diretório de artefatos do repack (sessão ou output-dir)."""
        if self.state is not None:
            return os.path.join(self.state.directory, "artifacts")
        return self.config.output_dir

    def _cleanup(self) -> None:
        """Cleanup idempotente — nunca deixa resíduos no dispositivo."""
        dm = self.dm
        if dm is not None:
            try:
                dm.stop_logcat_capture()
            except Exception:
                logger.debug("Falha ao encerrar captura de logcat", exc_info=True)
            try:
                dm.resume_app()
                safe_detach(self.session)
            except Exception:
                logger.debug("Falha ao detach da sessão final", exc_info=True)
            if self._xposed is not None:
                try:
                    for action in self._xposed.finish():
                        logger.info(
                            "Cleanup do módulo (%s): ok=%s %s",
                            action.get("step"),
                            action.get("ok"),
                            action.get("detail"),
                        )
                except Exception:
                    logger.warning("Falha no cleanup do módulo", exc_info=True)
            try:
                dm.remove_frida_server()
                dm.run_shell(
                    f"am force-stop {self.config.package}", timeout=10
                )
                time.sleep(1)
                dm.run_shell(
                    f"am force-stop {self.config.package}", timeout=10
                )
            except Exception:
                logger.warning(
                    "Falha no cleanup final do dispositivo", exc_info=True
                )
        if self._avd is not None:
            try:
                self._avd.stop()
            except Exception:
                logger.warning("Falha ao encerrar o AVD", exc_info=True)
            self._avd = None


# ----------------------------------------------------------------------
# Metadados de reprodução
# ----------------------------------------------------------------------
def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Converte um timestamp ISO em ``datetime`` (None se inválido)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _existing_report_timestamp(
    store: Optional[SessionStore],
    state: SessionState,
) -> Optional[datetime]:
    """Preserva o timestamp do relatório já gravado na sessão.

    Assim ``--stage report`` reproduz o mesmo documento que a execução
    original gerou, em vez de carimbar a hora da regeneração.
    """
    if store is None:
        return None
    try:
        data = json.loads(
            store.path(state, "report.json").read_text(encoding="utf-8")
        )
        return _parse_iso(((data or {}).get("metadata") or {}).get("timestamp"))
    except (OSError, ValueError, AttributeError):
        return None


def _script_hashes() -> dict:
    """Calcula o sha256 de cada script de injeção."""
    scripts_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "scripts"
    )
    hashes: dict = {}
    try:
        names = sorted(os.listdir(scripts_dir))
    except OSError:
        return hashes
    for name in names:
        if not name.endswith(".js"):
            continue
        path = os.path.join(scripts_dir, name)
        try:
            with open(path, "rb") as fh:
                hashes[name] = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            continue
    return hashes
