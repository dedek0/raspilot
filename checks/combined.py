"""RASPilot — Observação combinada em uma única sessão Frida.

Carrega, em um único spawn, as camadas nativas e Java dos checks
anti-Frida e anti-hooking. Isso reduz o número de spawns, evita que cada
check mantenha o app suspenso por conta própria e diminui o ruído de
detecção causado por múltiplas injeções.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from checks.anti_frida import DETECTION_SCRIPT
from checks.anti_hooking import HOOK_DETECTION_SCRIPT, WEAK_DETECTION_METHODS
from checks.stealth import (  # noqa: E402
    PROC_FILTER_SCRIPT,
    load_stealth,
    unload_stealth,
)
from logcat_analyzer import (
    HIGH_CONFIDENCE_CATEGORIES,
    analyze_since,
    classify_failure,
    format_detection_signals,
    format_evidence,
)
from script_loader import (
    load_java_bundle_files,
    load_script,
    load_script_file,
    safe_detach,
    safe_unload,
    wait_for_java_ready,
)
from verdict_hook import (
    VERDICT_HOOK_SCRIPT,
    build_replacements as build_verdict_replacements,
)

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.combined")

# Intervalo entre as consultas feitas durante a janela de observacao.
# Exposto como constante para que os testes nao dependam de esperar
# tempo real.
OBSERVATION_POLL_INTERVAL = 1.0


# Categorias de logcat aceitas como evidência de detecção em cada check.
# "root" e "emulator" não são evidência de Frida nem de hooking: são
# checagens de ambiente, e o app as faz por conta própria.
FRIDA_CATEGORIES = ("frida", "debug")
HOOK_CATEGORIES = ("hooking", "debug")

# Tempo máximo de carga dos scripts Java. A carga da bridge é dominada
# pela inicialização do runtime Java no processo alvo e pela varredura de
# classloaders, que em apps com muitos dex leva vários segundos. Um limite
# curto descarta o script no meio da execução, removendo os hooks já
# instalados e produzindo um veredito falso.
DEFAULT_JAVA_TIMEOUT = 30.0


def _iife(source: str) -> str:
    """Encapsula um script em IIFE para evitar colisão de globais."""
    return "(function(){\n" + source + "\n})();\n"


def _replacements(
    dm: "DeviceManager",
    java_only: bool,
    package_name: str = "",
) -> Dict[str, str]:
    """Placeholders comuns aos dois scripts."""
    value = getattr(dm, "frida_port", None)
    port = int(value) if isinstance(value, int) else 27999
    return {
        "__RASPILOT_FRIDA_PORT__": str(port),
        "__RASPILOT_FRIDA_PORT_HEX__": f"{port:04X}",
        "__RASPILOT_JAVA_ONLY__": "true" if java_only else "false",
        "__RASPILOT_PACKAGE_NAME__": package_name or "",
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
    script_errors: Optional[List[str]] = None,
    neutralized_actions: Optional[List[str]] = None,
) -> dict:
    """Consolida o resultado anti-Frida a partir dos sinais coletados."""
    for entry in format_detection_signals(logcat, FRIDA_CATEGORIES, limit=4):
        if entry not in found:
            found.append(entry)
    agent_crash = _agent_terminated(logcat)

    if not app_alive and died_after is None:
        died_after = max(1, int(window))

    baseline_died = bool(
        baseline and baseline.get("available") and baseline.get("alive_at_end") is False
    )
    death_cause: Optional[dict] = None
    death_classification: Optional[str] = None
    observation_status = "ok"
    error: Optional[str] = None

    if app_alive and agent_crash:
        # O agente do Frida quebrou dentro do processo: é falha da
        # instrumentação, não reação do app. A observação é
        # inconclusiva — nunca "o app detectou o Frida".
        observation_status = "error"
        error = (
            "o agente de instrumentação terminou dentro do processo alvo; "
            "a observação é inconclusiva"
        )
    elif app_alive and java_skipped and not found:
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
            for category in HIGH_CONFIDENCE_CATEGORIES
        ) or bool(logcat.get("vendor_signals"))
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
            observation_status = "inconclusive"
            error = (
                "o processo encerrou sem que a causa pudesse ser atribuida "
                f"({death_classification}); não é possível concluir se houve "
                "reação à instrumentação"
            )

        if death_classification in ("rasp_kill", "rasp_reaction"):
            found.append(
                f"app_terminated: processo encerrou ~{died_after}s após resume "
                f"({death_classification})"
            )

    vulnerable = (
        None
        if observation_status in (
            "crashed", "baseline_death", "error", "native_only",
            "start_timeout", "inconclusive",
        )
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
        "script_errors": list(script_errors or []),
        "neutralized_actions": list(neutralized_actions or []),
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
    script_errors: Optional[List[str]] = None,
    neutralized_actions: Optional[List[str]] = None,
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
                # Falha da instrumentação: não é checagem do app.
                entry = f"frida_agent_crash: {item.get('line', '')}"
                if entry not in found:
                    found.append(entry)
                    weak.append(entry)
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
            for category in HIGH_CONFIDENCE_CATEGORIES
        ) or bool(logcat.get("vendor_signals"))
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
            observation_status = "inconclusive"
            error = (
                "o processo encerrou sem que a causa pudesse ser atribuida "
                f"({death_classification}); não é possível concluir se houve "
                "reação à instrumentação"
            )

        if death_classification in ("rasp_kill", "rasp_reaction"):
            add_signal(
                "app_terminated",
                f"processo encerrou ~{died_after}s após resume "
                f"({death_classification})",
            )

    detected = bool(strong) and observation_status != "inconclusive"
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
        "script_errors": list(script_errors or []),
        "neutralized_actions": list(neutralized_actions or []),
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
    java_timeout: float = DEFAULT_JAVA_TIMEOUT,
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
        java_timeout: Tempo máximo de carga dos scripts Java, em segundos.

    Returns:
        Tupla ``(frida_detection, hooking_detection)``.
    """
    frida_found: List[str] = []
    hook_found: List[str] = []
    hook_strong: List[str] = []
    hook_weak: List[str] = []
    script_errors: List[str] = []
    neutralized_actions: List[str] = []
    java_ready = threading.Event()

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
            if ptype == "raspilot-script-error":
                # Erro interno de um script (ex: exceção ao instalar um
                # hook Java). É um diagnóstico da instrumentação, nunca uma
                # detecção do app: por isso fica numa lista separada e
                # não alimenta o veredito de detecção.
                script_errors.append(str(payload.get("message", "")))
                logger.warning("Erro em script de observação: %s", payload.get("message"))
                return
            if ptype == "raspilot-java-bootstrap":
                logger.debug("Bootstrap Java: %s", payload.get("message"))
                return
            if ptype == "raspilot-neutralized":
                # Ação do app que foi de fato impedida (auto-destruição,
                # consulta a artefato de instrumentação). É evidência do
                # que o app tentou fazer, não uma detecção do app.
                msg = payload.get("message", "")
                if msg and msg not in neutralized_actions:
                    neutralized_actions.append(msg)
                return
            if ptype == "raspilot-java-ready":
                java_ready.set()
                return
            if ptype == "raspilot-java-unavailable":
                logger.debug("Camada Java indisponível (%s)", payload.get("label"))
                return
        elif message.get("type") == "error":
            logger.debug("Erro no script combinado: %s", message.get("description"))

    try:
        if mode == "stealth":
            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=_replacements(
                    dm, java_only=False, package_name=package_name
                ),
                include_proc_filter=True,
            )
        else:
            # A camada nativa de evasão é carregada também fora do modo
            # stealth: sem ela, o app aborta logo após o resume e a
            # janela de observação termina sem produzir sinal algum.
            #
            # No modo ``detect`` a evasão fica desligada de propósito:
            # observar a reação do app exige que a reação aconteça.
            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=_replacements(
                    dm, java_only=False, package_name=package_name
                ),
                include_proc_filter=mode != "detect",
                load_native_frida=mode != "detect",
            )

        native_source = _replacements(
                    dm, java_only=False, package_name=package_name
                )
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
            # O class loader do app só existe depois que a aplicação é
            # criada. Carregar a bridge antes disso faz a ponte esperar
            # ativamente — e a espera prende a thread de JavaScript do
            # agente, o que estoura o limite de carga do script.
            if not dm.wait_for_app_ready(package_name, pid=pid):
                logger.warning(
                    "App não ficou em foco a tempo; a camada Java pode "
                    "demorar a subir"
                )
            try:
                java_script = load_script(
                    session,
                    _iife(DETECTION_SCRIPT) + _iife(HOOK_DETECTION_SCRIPT),
                    on_message=on_message,
                    name="raspilot-combined-java",
                    replacements=_replacements(
                    dm, java_only=True, package_name=package_name
                ),
                    with_java_bridge=True,
                    load_timeout=java_timeout,
                )
            except Exception as exc:
                java_load_error = str(exc)
                logger.warning("Hooks Java combinados não carregaram: %s", exc)
                # A sessão NÃO é detachada aqui: os hooks nativos já
                # instalados continuam válidos e a observação nativa segue
                # produzindo evidência durante a janela restante.
            else:
                # A instalação dos hooks Java é adiada dentro do script:
                # a janela de observação só começa quando a camada Java
                # está de fato ativa.
                if not wait_for_java_ready(java_ready, java_timeout):
                    java_load_error = (
                        "camada Java não ficou pronta em "
                        f"{java_timeout:.0f}s"
                    )
                    logger.warning("Camada Java não ficou pronta a tempo")

        for elapsed in range(max(1, int(window))):
            time.sleep(OBSERVATION_POLL_INTERVAL)
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
        script_errors=script_errors,
        neutralized_actions=neutralized_actions,
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
        script_errors=script_errors,
        neutralized_actions=neutralized_actions,
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

# Rastreio de kill: identifica quem encerrou o processo (o app ou o
# próprio RASP). É carregado junto com os demais scripts Java porque
# depende da bridge.
KILL_TRACE_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "kill_trace.js",
)


def run_combined_bypass(
    dm: "DeviceManager",
    package_name: str,
    window: int,
    mode: str = "bypass",
    no_java: bool = False,
    java_timeout: float = DEFAULT_JAVA_TIMEOUT,
) -> Tuple[dict, dict]:
    """Executa os bypasses de anti-hooking e SSL em um único spawn.

    Args:
        dm: Gerenciador do dispositivo.
        package_name: Package name do app.
        window: Janela de observação em segundos.
        mode: ``bypass`` ou ``stealth``.
        no_java: Se True, apenas a camada nativa é carregada.
        java_timeout: Tempo máximo de carga dos scripts Java, em segundos.

    Returns:
        Tupla ``(hooking_result, ssl_result)`` no formato de
        ``attempt_bypass``.
    """
    hook_logs: List[str] = []
    hook_evidence: List[str] = []
    neutralized_actions: List[str] = []
    ssl_logs: List[str] = []
    hosts: List[str] = []
    java_ready = threading.Event()
    hook_java_error: Optional[str] = None
    ssl_java_error: Optional[str] = None
    combined_error: Optional[str] = None
    stealth_loaded: List[tuple] = []
    session = None
    native_hook = None
    native_ssl = None
    proc_script = None
    java_hook = None
    died_after: Optional[int] = None
    pid: Optional[int] = None
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
            if ptype == "bypass-evidence":
                # Evidência real: a checagem do app foi exercitada e o
                # resultado foi neutralizado. Difere do self-report do
                # hook, que apenas indica instrumentação ativa.
                msg = payload.get("message", "")
                if msg and msg not in hook_evidence:
                    hook_evidence.append(msg)
                if msg and msg not in hook_logs:
                    hook_logs.append(msg)
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
            if ptype == "raspilot-script-error":
                # Exceção real dentro de um script. Registrada como
                # diagnóstico: não é evidência de bypass, mas explica por
                # que a camada Java não ficou ativa.
                msg = f"[script-error] {payload.get('message', '')}"
                for target in (hook_logs, ssl_logs):
                    if msg not in target:
                        target.append(msg)
                return
            if ptype == "raspilot-java-ready":
                java_ready.set()
                return
            if ptype == "raspilot-neutralized":
                msg = payload.get("message", "")
                if msg and msg not in neutralized_actions:
                    neutralized_actions.append(msg)
                if msg and msg not in hook_logs:
                    hook_logs.append(msg)
                return
            if ptype == "raspilot-verdict":
                # Diagnóstico do hook de veredito (qual classe foi
                # varrida, quantos métodos foram encontrados).
                msg = payload.get("message", "")
                if msg and msg not in hook_logs:
                    hook_logs.append(msg)
                return
            if ptype == "raspilot-java-unavailable":
                msg = "[java-indisponivel] camada Java não pôde ser carregada"
                for target in (hook_logs, ssl_logs):
                    if msg not in target:
                        target.append(msg)
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
                replacements=_replacements(
                    dm, java_only=False, package_name=package_name
                ),
                include_proc_filter=True,
            )
        else:
            # A evasão anti-Frida nativa é carregada também fora do modo
            # stealth: sem ela o alvo aborta logo após o resume e o bypass
            # é avaliado sobre um processo já morto.
            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=_replacements(
                    dm, java_only=False, package_name=package_name
                ),
                include_proc_filter=True,
            )
        native_hook = load_script_file(
            session, HOOK_BYPASS_SCRIPT, on_message=on_message,
            replacements=_replacements(
                    dm, java_only=False, package_name=package_name
                ),
            with_java_bridge=False, load_timeout=5.0,
        )
        native_ssl = load_script_file(
            session, SSL_BYPASS_SCRIPT, on_message=on_message,
            replacements=_replacements(
                    dm, java_only=False, package_name=package_name
                ),
            with_java_bridge=False, load_timeout=5.0,
        )
        proc_loaded = any(path == PROC_FILTER_SCRIPT for path, _ in stealth_loaded)
        if not proc_loaded:
            proc_script = load_script_file(
                session, PROC_FILTER_SCRIPT, on_message=on_message,
                replacements=_replacements(
                    dm, java_only=False, package_name=package_name
                ),
                with_java_bridge=False, load_timeout=3.0,
            )
        dm.resume_app()
        pid = dm.last_spawn_pid or dm.get_app_pid(package_name)

        if not no_java:
            # Ver nota na observação: sem o app em foco, a ponte espera
            # pelo class loader e prende a thread do agente.
            if not dm.wait_for_app_ready(package_name, pid=pid):
                logger.warning(
                    "App não ficou em foco a tempo; a camada Java pode "
                    "demorar a subir"
                )
            # Todos os scripts Java são carregados em UM único script: a
            # bridge Java é compilada uma vez por sessão em vez de uma
            # vez por script, o que reduz o tempo de carga e evita
            # que a camada Java seja descartada por timeout.
            #
            # O hook de veredito entra no mesmo bundle: ele neutraliza a
            # comunicação de violação dos SDKs de RASP — as primitivas
            # são enganadas, mas o SDK ainda reporta a ameaça ao app.
            try:
                java_hook = load_java_bundle_files(
                    session,
                    [
                        HOOK_BYPASS_SCRIPT,
                        SSL_BYPASS_SCRIPT,
                        KILL_TRACE_SCRIPT,
                        VERDICT_HOOK_SCRIPT,
                    ],
                    on_message=on_message,
                    name="raspilot-combined-bypass-java",
                    replacements={
                        **_replacements(
                    dm, java_only=True, package_name=package_name
                ),
                        **build_verdict_replacements(),
                    },
                    load_timeout=java_timeout,
                )
            except Exception as exc:
                hook_java_error = str(exc)
                ssl_java_error = ssl_java_error or str(exc)
                logger.warning("Hooks Java do bypass não carregaram: %s", exc)
            else:
                if not wait_for_java_ready(java_ready, java_timeout):
                    hook_java_error = (
                        "camada Java do bypass não ficou pronta em "
                        f"{java_timeout:.0f}s"
                    )
                    ssl_java_error = ssl_java_error or hook_java_error
                    logger.warning("Camada Java do bypass não ficou pronta a tempo")

        for elapsed in range(max(1, int(window))):
            time.sleep(OBSERVATION_POLL_INTERVAL)
            if pid is not None and not dm.is_app_alive(pid):
                died_after = elapsed + 1
                break
    except Exception as exc:
        logger.warning("Bypass combinado falhou", exc_info=True)
        combined_error = str(exc)
        for target in (hook_logs, ssl_logs):
            target.append(f"[script-error] {exc}")
    finally:
        for script in (native_hook, native_ssl, proc_script, java_hook):
            safe_unload(script)
        unload_stealth(stealth_loaded)
        if session is not None:
            safe_detach(session)

    # O PID é mantido mesmo quando o app morreu: sem ele, a correlação com
    # o logcat passa a depender apenas do package name e a mesma linha
    # pode ser classificada de forma diferente entre a observação e o
    # bypass da mesma execução.
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

    # Só a evidência de bypass exercitado sustenta o veredito de
    # "bypass venceu": o self-report do hook prova apenas que a
    # instrumentação está ativa.
    hook_effective = list(hook_evidence) or [
        log for log in hook_logs
        if any(marker in log for marker in BYPASS_EVIDENCE_MARKERS)
        and "hookado" not in log
        and not log.endswith("carregado")
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
        "neutralized_actions": neutralized_actions,
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
        "neutralized_actions": neutralized_actions,
        "stealth_used": bool(stealth_loaded),
        "error": ssl_error,
    }
    return hooking, ssl
