"""RASPilot — Observação combinada em uma única sessão Frida.

Carrega, em um único spawn, as camadas nativas e Java dos checks
anti-Frida e anti-hooking. Isso reduz o número de spawns, evita que cada
check mantenha o app suspenso por conta própria e diminui o ruído de
detecção causado por múltiplas injeções.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from checks.anti_frida import DETECTION_SCRIPT
from checks.anti_hooking import HOOK_DETECTION_SCRIPT, WEAK_DETECTION_METHODS
from checks.stealth import PROC_FILTER_SCRIPT, load_stealth, unload_stealth
from logcat_analyzer import (
    RASP_CATEGORIES,
    analyze_since,
    classify_failure,
    format_detection_signals,
    format_evidence,
)
from script_loader import load_script, safe_detach, safe_unload

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.combined")

FRIDA_CATEGORIES = ("root", "frida", "debug", "integrity")
HOOK_CATEGORIES = ("root", "hooking", "emulator", "debug", "integrity")


def _iife(source: str) -> str:
    """Encapsula um script em IIFE para evitar colisão de globais."""
    return "(function(){\n" + source + "\n})();\n"


def _replacements(dm: "DeviceManager", java_only: bool) -> Dict[str, str]:
    """Placeholders comuns aos dois scripts."""
    value = getattr(dm, "frida_port", None)
    port = int(value) if isinstance(value, int) else 27999
    return {
        "__RASPILOT_FRIDA_PORT__": str(port),
        "__RASPILOT_FRIDA_PORT_HEX__": f"{port:04X}",
        "__RASPILOT_JAVA_ONLY__": "true" if java_only else "false",
    }


def _baseline(dm: "DeviceManager") -> Optional[dict]:
    value = getattr(dm, "baseline", None)
    return value if isinstance(value, dict) else None


def _agent_terminated(logcat: dict) -> bool:
    return bool(logcat.get("agent_terminated"))


def _agent_line(logcat: dict) -> Optional[str]:
    for item in logcat.get("security_signals", []) or []:
        if isinstance(item, dict) and item.get("category") == "frida_agent_crash":
            return f"frida_agent_crash: {item.get('line', '')}"
    return None


def _frida_detection(
    *,
    found: List[str],
    logcat: dict,
    baseline: Optional[dict],
    died_after: Optional[int],
    app_alive: bool,
    java_load_error: Optional[str],
    java_skipped: bool,
    stealth_used: bool,
    window: int,
) -> dict:
    """Consolida o resultado anti-Frida a partir dos sinais coletados."""
    for entry in format_detection_signals(logcat, FRIDA_CATEGORIES, limit=4):
        if entry not in found:
            found.append(entry)
    if _agent_terminated(logcat):
        line = _agent_line(logcat)
        if line and line not in found:
            found.append(line)

    if not app_alive and died_after is None:
        died_after = max(1, int(window))

    baseline_died = bool(
        baseline and baseline.get("available") and baseline.get("alive_at_end") is False
    )
    death_cause: Optional[dict] = None
    death_classification: Optional[str] = None
    observation_status = "ok"
    error: Optional[str] = None

    if app_alive and java_skipped and not found:
        observation_status = "native_only"
        error = (
            "hooks Java desativados (--no-java); a observação nativa não "
            "encontrou detecção de Frida"
        )
    elif app_alive and java_load_error and not found:
        observation_status = "error"
        error = (
            "hooks Java de observação não carregaram e nenhuma detecção "
            f"foi observada: {java_load_error}"
        )

    if not app_alive:
        logcat_death = logcat.get("death") or {}
        logcat_rasp = any(
            category in (logcat.get("categories") or {})
            for category in RASP_CATEGORIES
        )
        kill_traced = any(item.startswith("app_kill") for item in found)
        if kill_traced:
            death_classification = "rasp_kill"
        elif baseline_died:
            death_classification = "baseline_death"
            observation_status = "baseline_death"
            error = (
                "app encerrou no baseline sem instrumentação; não é possível "
                "isolar uma reação ao Frida"
            )
        elif logcat_rasp or _agent_terminated(logcat):
            death_classification = "rasp_reaction"
        elif logcat.get("instrumentation_kill"):
            death_classification = "start_timeout"
            observation_status = "start_timeout"
            error = (
                "app morto por ActivityManager start timeout durante o "
                "carregamento (instrumentação)"
            )
        elif logcat.get("available") and logcat_death.get("kind") in ("crash", "anr"):
            death_classification = "instrumentation_crash"
            observation_status = "crashed"
            error = (
                "app encerrou por crash/ANR sem evidência de segurança no logcat "
                "(possível crash da instrumentação)"
            )
        else:
            death_classification = "unclassified_death"

        if death_classification in ("rasp_kill", "rasp_reaction", "unclassified_death"):
            found.append(
                f"app_terminated: processo encerrou ~{died_after}s após resume "
                f"({death_classification})"
            )

    vulnerable = (
        None
        if observation_status in ("crashed", "baseline_death", "error", "native_only", "start_timeout")
        else (not found)
    )
    result = {
        "detection_methods_found": found,
        "vulnerable": vulnerable,
        "app_alive_at_end": app_alive,
        "observed": True,
        "observation_status": observation_status,
        "death_cause": death_cause,
        "death_classification": death_classification,
        "baseline": baseline,
        "logcat": logcat,
        "logcat_evidence": format_evidence(logcat),
        "java_load_error": java_load_error,
        "java_skipped": java_skipped,
        "stealth_used": stealth_used,
        "session_unsafe": bool(java_load_error),
        "details": (
            f"App detectou Frida via: {'; '.join(found)}" if found
            else "App não executou nenhuma detecção de Frida observada"
        ),
    }
    if error:
        result["error"] = error
    return result


def _hooking_detection(
    *,
    found: List[str],
    strong: List[str],
    weak: List[str],
    logcat: dict,
    baseline: Optional[dict],
    died_after: Optional[int],
    app_alive: bool,
    java_load_error: Optional[str],
    java_skipped: bool,
    stealth_used: bool,
    window: int,
) -> dict:
    """Consolida o resultado anti-hooking a partir dos sinais coletados."""

    def add_signal(method: str, detail: str) -> None:
        entry = f"{method}: {detail}"
        if entry in found:
            return
        found.append(entry)
        bucket = weak if method in WEAK_DETECTION_METHODS else strong
        bucket.append(entry)

    for entry in format_detection_signals(logcat, HOOK_CATEGORIES, limit=4):
        method, _, detail = entry.partition(": ")
        add_signal(method, detail)
    if _agent_terminated(logcat):
        for item in logcat.get("security_signals", []) or []:
            if isinstance(item, dict) and item.get("category") == "frida_agent_crash":
                add_signal("frida_agent_crash", item.get("line", ""))
                break

    if not app_alive and died_after is None:
        died_after = max(1, int(window))

    baseline_died = bool(
        baseline and baseline.get("available") and baseline.get("alive_at_end") is False
    )
    death_cause: Optional[dict] = None
    death_classification: Optional[str] = None
    observation_status = "ok"
    error: Optional[str] = None

    if app_alive and java_skipped and not strong:
        observation_status = "native_only"
        error = (
            "hooks Java desativados (--no-java); a observação nativa não "
            "encontrou checagem anti-hook"
        )
    elif app_alive and java_load_error and not strong:
        observation_status = "error"
        error = (
            "hooks Java de observação não carregaram e nenhuma checagem "
            f"anti-hook foi observada: {java_load_error}"
        )

    if not app_alive:
        logcat_death = logcat.get("death") or {}
        logcat_rasp = any(
            category in (logcat.get("categories") or {})
            for category in RASP_CATEGORIES
        )
        kill_traced = any(item.startswith("app_kill") for item in strong)
        if kill_traced:
            death_classification = "rasp_kill"
        elif baseline_died:
            death_classification = "baseline_death"
            observation_status = "baseline_death"
            error = (
                "app encerrou no baseline sem instrumentação; não é possível "
                "isolar uma reação anti-hook"
            )
        elif logcat_rasp or _agent_terminated(logcat):
            death_classification = "rasp_reaction"
        elif logcat.get("instrumentation_kill"):
            death_classification = "start_timeout"
            observation_status = "start_timeout"
            error = (
                "app morto por ActivityManager start timeout durante o "
                "carregamento (instrumentação)"
            )
        elif logcat.get("available") and logcat_death.get("kind") in ("crash", "anr"):
            death_classification = "instrumentation_crash"
            observation_status = "crashed"
            error = (
                "app encerrou por crash/ANR sem evidência de segurança no logcat "
                "(possível crash da instrumentação)"
            )
        else:
            death_classification = "unclassified_death"

        if death_classification in ("rasp_kill", "rasp_reaction", "unclassified_death"):
            add_signal(
                "app_terminated",
                f"processo encerrou ~{died_after}s após resume "
                f"({death_classification})",
            )

    detected = bool(strong)
    result = {
        "detected": detected,
        "detection_methods_found": found,
        "strong_signals": strong,
        "weak_signals": weak,
        "app_alive_at_end": app_alive,
        "observed": True,
        "observation_status": observation_status,
        "death_cause": death_cause,
        "death_classification": death_classification,
        "baseline": baseline,
        "logcat": logcat,
        "logcat_evidence": format_evidence(logcat),
        "java_load_error": java_load_error,
        "java_skipped": java_skipped,
        "stealth_used": stealth_used,
        "session_unsafe": bool(java_load_error),
        "details": (
            f"App executou checagens anti-hook: {'; '.join(strong)}"
            if strong
            else (
                "Apenas sinais fracos (leitura de maps/status), sem checagem "
                "anti-hook forte observada"
                if weak
                else "App não executou nenhuma checagem anti-hook observada"
            )
        ),
    }
    if error:
        result["error"] = error
    return result


def run_combined_observation(
    dm: "DeviceManager",
    session: object,
    pid: Optional[int],
    package_name: str,
    window: int,
    logcat_mark: Optional[int],
    on_resume: Optional[object],
    mode: str = "bypass",
    no_java: bool = False,
) -> Tuple[dict, dict]:
    """Executa a observação anti-Frida + anti-hooking em um único spawn.

    Args:
        dm: Gerenciador do dispositivo.
        session: Sessão Frida já anexada a um spawn suspenso.
        pid: PID do processo alvo.
        package_name: Package name do app.
        window: Janela de observação em segundos.
        logcat_mark: Marcador de logcat tirado antes do spawn.
        on_resume: Callback para retomar o spawn suspenso.
        mode: ``detect``, ``bypass`` ou ``stealth``.
        no_java: Se True, não carrega a bridge Java.

    Returns:
        Tupla ``(frida_detection, hooking_detection)``.
    """
    frida_found: List[str] = []
    hook_found: List[str] = []
    hook_strong: List[str] = []
    hook_weak: List[str] = []

    native_script = None
    java_script = None
    stealth_loaded: List[tuple] = []
    resumed = False
    died_after: Optional[int] = None
    java_load_error: Optional[str] = None

    def on_message(message, data):  # noqa: ANN001 - assinatura frida
        if message.get("type") == "send":
            payload = message.get("payload", {})
            ptype = payload.get("type")
            if ptype == "frida-detection":
                entry = f"{payload.get('method', '?')}: {payload.get('detail', '')}"
                if entry not in frida_found:
                    frida_found.append(entry)
                return
            if ptype == "hook-detection":
                entry = f"{payload.get('method', '?')}: {payload.get('detail', '')}"
                if entry not in hook_found:
                    hook_found.append(entry)
                    bucket = (
                        hook_weak
                        if payload.get("method") in WEAK_DETECTION_METHODS
                        else hook_strong
                    )
                    bucket.append(entry)
                return
            if ptype == "app-kill":
                entry = "app_kill: " + payload.get("message", "")
                for target in (frida_found, hook_strong):
                    if entry not in target:
                        target.append(entry)
                return
            if ptype in ("frida-detection-error", "hook-detection-error"):
                logger.debug("Hook de observação não instalou: %s", payload.get("message"))
        elif message.get("type") == "error":
            logger.debug("Erro no script combinado: %s", message.get("description"))

    try:
        if mode == "stealth":
            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=_replacements(dm, java_only=False),
                include_proc_filter=True,
            )

        native_source = _replacements(dm, java_only=False)
        native_script = load_script(
            session,
            _iife(DETECTION_SCRIPT) + _iife(HOOK_DETECTION_SCRIPT),
            on_message=on_message,
            name="raspilot-combined-native",
            replacements=native_source,
            with_java_bridge=False,
            load_timeout=5.0,
        )
        if on_resume is not None:
            on_resume()
            resumed = True

        if not no_java:
            try:
                java_script = load_script(
                    session,
                    _iife(DETECTION_SCRIPT) + _iife(HOOK_DETECTION_SCRIPT),
                    on_message=on_message,
                    name="raspilot-combined-java",
                    replacements=_replacements(dm, java_only=True),
                    with_java_bridge=True,
                    load_timeout=5.0,
                )
            except Exception as exc:
                java_load_error = str(exc)
                logger.warning("Hooks Java combinados não carregaram: %s", exc)
                safe_detach(session)

        for elapsed in range(max(1, int(window))):
            time.sleep(1)
            if pid is not None and not dm.is_app_alive(pid):
                died_after = elapsed + 1
                break
    except Exception as exc:
        java_load_error = java_load_error or str(exc)
        logger.warning("Falha na observação combinada", exc_info=True)
    finally:
        safe_unload(native_script)
        safe_unload(java_script)
        unload_stealth(stealth_loaded)
        if not resumed and on_resume is not None:
            try:
                on_resume()
            except Exception:
                logger.debug("Falha no resume de emergência", exc_info=True)
        if java_load_error:
            # Sessão degradada; não deixar para o host.
            safe_detach(session)

    if died_after is None and pid is not None:
        try:
            if not dm.is_app_alive(pid):
                died_after = max(1, int(window))
        except Exception:
            logger.debug("Falha na rechecagem de vida", exc_info=True)

    logcat = analyze_since(dm, logcat_mark, package_name, pid)
    baseline = _baseline(dm)
    app_alive = died_after is None
    if not app_alive:
        try:
            death_cause = dm.capture_death_cause(pid=pid, package=package_name)
        except Exception:
            death_cause = None
    else:
        death_cause = None

    frida = _frida_detection(
        found=frida_found,
        logcat=logcat,
        baseline=baseline,
        died_after=died_after,
        app_alive=app_alive,
        java_load_error=java_load_error,
        java_skipped=no_java,
        stealth_used=bool(stealth_loaded),
        window=window,
    )
    hooking = _hooking_detection(
        found=hook_found,
        strong=hook_strong,
        weak=hook_weak,
        logcat=logcat,
        baseline=baseline,
        died_after=died_after,
        app_alive=app_alive,
        java_load_error=java_load_error,
        java_skipped=no_java,
        stealth_used=bool(stealth_loaded),
        window=window,
    )
    # Anexa evidência de morte (uma única captura compartilhada).
    if death_cause:
        frida["death_cause"] = death_cause
        hooking["death_cause"] = death_cause
    return frida, hooking


# ----------------------------------------------------------------------
# Bypass combinado (anti-hooking + SSL pinning no mesmo spawn)
# ----------------------------------------------------------------------
from checks.anti_hooking import (  # noqa: E402 - evita ciclo no topo
    BYPASS_EVIDENCE_MARKERS,
    HOOK_BYPASS_SCRIPT,
)
from checks.ssl_pinning import (  # noqa: E402
    EVIDENCE_MARKERS,
    SSL_BYPASS_SCRIPT,
)
from logcat_analyzer import get_logcat_mark  # noqa: E402
from script_loader import load_script_file  # noqa: E402


def run_combined_bypass(
    dm: "DeviceManager",
    package_name: str,
    window: int,
    mode: str = "bypass",
    no_java: bool = False,
) -> Tuple[dict, dict]:
    """Executa os bypasses de anti-hooking e SSL em um único spawn.

    Args:
        dm: Gerenciador do dispositivo.
        package_name: Package name do app.
        window: Janela de observação em segundos.
        mode: ``bypass`` ou ``stealth``.
        no_java: Se True, apenas a camada nativa é carregada.

    Returns:
        Tupla ``(hooking_result, ssl_result)`` no formato de
        ``attempt_bypass``.
    """
    hook_logs: List[str] = []
    ssl_logs: List[str] = []
    hosts: List[str] = []
    hook_java_error: Optional[str] = None
    ssl_java_error: Optional[str] = None
    combined_error: Optional[str] = None
    stealth_loaded: List[tuple] = []
    session = None
    native_hook = None
    native_ssl = None
    proc_script = None
    java_hook = None
    java_ssl = None
    died_after: Optional[int] = None
    logcat_mark = get_logcat_mark(dm)

    def on_message(message, data):  # noqa: ANN001 - assinatura frida
        if message.get("type") == "send":
            payload = message.get("payload", {})
            ptype = payload.get("type")
            if ptype == "app-kill":
                msg = "app-kill: " + payload.get("message", "")
                for target in (hook_logs, ssl_logs):
                    if msg not in target:
                        target.append(msg)
                return
            if ptype == "raspilot-hooking-bypass":
                msg = payload.get("message", "")
                if msg and msg not in hook_logs:
                    hook_logs.append(msg)
                return
            if ptype == "ssl-bypass-host":
                host = payload.get("host", "")
                if host and host not in hosts:
                    hosts.append(host)
                return
            if ptype == "ssl-bypass":
                msg = payload.get("message", "")
                if msg and msg not in ssl_logs:
                    ssl_logs.append(msg)
                return
        elif message.get("type") == "error":
            desc = message.get("description", "")
            if desc:
                entry = f"[script-error] {desc}"
                for target in (hook_logs, ssl_logs):
                    if entry not in target:
                        target.append(entry)

    try:
        session = dm.spawn_app(package_name, resume=False)
        if mode == "stealth":
            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=_replacements(dm, java_only=False),
                include_proc_filter=True,
            )
        native_hook = load_script_file(
            session, HOOK_BYPASS_SCRIPT, on_message=on_message,
            replacements=_replacements(dm, java_only=False),
            with_java_bridge=False, load_timeout=5.0,
        )
        native_ssl = load_script_file(
            session, SSL_BYPASS_SCRIPT, on_message=on_message,
            replacements=_replacements(dm, java_only=False),
            with_java_bridge=False, load_timeout=5.0,
        )
        proc_loaded = any(path == PROC_FILTER_SCRIPT for path, _ in stealth_loaded)
        if not proc_loaded:
            proc_script = load_script_file(
                session, PROC_FILTER_SCRIPT, on_message=on_message,
                replacements=_replacements(dm, java_only=False),
                with_java_bridge=False, load_timeout=3.0,
            )
        dm.resume_app()
        pid = dm.last_spawn_pid or dm.get_app_pid(package_name)

        if not no_java:
            try:
                java_hook = load_script_file(
                    session, HOOK_BYPASS_SCRIPT, on_message=on_message,
                    replacements=_replacements(dm, java_only=True),
                    with_java_bridge=True, load_timeout=5.0,
                )
            except Exception as exc:
                hook_java_error = str(exc)
            try:
                java_ssl = load_script_file(
                    session, SSL_BYPASS_SCRIPT, on_message=on_message,
                    replacements=_replacements(dm, java_only=True),
                    with_java_bridge=True, load_timeout=5.0,
                )
            except Exception as exc:
                ssl_java_error = str(exc)
            if hook_java_error and ssl_java_error:
                safe_detach(session)

        for elapsed in range(max(1, int(window))):
            time.sleep(1)
            if pid is not None and not dm.is_app_alive(pid):
                died_after = elapsed + 1
                break
    except Exception as exc:
        logger.warning("Bypass combinado falhou", exc_info=True)
        combined_error = str(exc)
        for target in (hook_logs, ssl_logs):
            target.append(f"[script-error] {exc}")
    finally:
        for script in (native_hook, native_ssl, proc_script, java_hook, java_ssl):
            safe_unload(script)
        unload_stealth(stealth_loaded)
        if session is not None:
            safe_detach(session)

    pid = dm.last_spawn_pid if died_after is not None else None
    logcat = analyze_since(dm, logcat_mark, package_name, pid)
    baseline = _baseline(dm)
    failure = classify_failure(logcat, baseline)
    alive = died_after is None
    death_cause = None
    if not alive:
        try:
            death_cause = dm.capture_death_cause(pid=pid, package=package_name)
        except Exception:
            death_cause = None

    hook_effective = [
        log for log in hook_logs
        if any(marker in log for marker in BYPASS_EVIDENCE_MARKERS)
    ]
    ssl_effective = [
        log for log in ssl_logs
        if any(marker in log for marker in EVIDENCE_MARKERS)
    ]
    kind = str(failure.get("kind", "unknown"))
    is_rasp = bool(failure.get("is_rasp"))

    hook_success = bool(hook_effective) and alive
    hook_error: Optional[str] = None
    if alive and hook_java_error:
        hook_success = False
        hook_error = f"hooks Java do bypass não carregaram: {hook_java_error}"
    elif not alive and not is_rasp:
        hook_error = (
            "app encerrou sem reação RASP identificável durante o bypass "
            f"({kind})"
        )
    if hook_error is None and combined_error and not (not alive and is_rasp):
        hook_error = combined_error

    ssl_success = bool(hosts) and alive
    ssl_error: Optional[str] = None
    if alive and ssl_java_error and not hosts:
        ssl_success = False
        ssl_error = f"hooks Java de SSL não carregaram: {ssl_java_error}"
    elif not alive and not is_rasp:
        ssl_error = (
            "app encerrou sem reação RASP identificável durante o bypass "
            f"({kind})"
        )
    if ssl_error is None and combined_error and not (not alive and is_rasp):
        ssl_error = combined_error

    hooking = {
        "success": hook_success,
        "bypass_logs": hook_logs,
        "effective_logs": hook_effective,
        "app_alive_at_end": alive,
        "death_cause": death_cause,
        "logcat": logcat,
        "logcat_evidence": format_evidence(logcat),
        "java_load_error": hook_java_error,
        "stealth_used": bool(stealth_loaded),
        "error": hook_error,
    }
    ssl = {
        "success": ssl_success,
        "intercepted_hosts": hosts,
        "bypass_logs": ssl_logs,
        "effective_logs": ssl_effective,
        "evidence_strength": "host" if hosts else ("config_only" if ssl_effective else "none"),
        "app_alive_at_end": alive,
        "death_cause": death_cause,
        "logcat": logcat,
        "logcat_evidence": format_evidence(logcat),
        "java_load_error": ssl_java_error,
        "stealth_used": bool(stealth_loaded),
        "error": ssl_error,
    }
    return hooking, ssl
