"""RASPilot — Análise de logcat para correlação de evidências RASP.

O logcat é usado como fonte **independente** de evidência: ele registra
mortes, kills, crashes, exceções de TLS e mensagens de SDKs de segurança
que não passam pelos hooks do Frida. Isso ajuda a distinguir uma reação
real do RASP de um crash causado pela própria instrumentação.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Sequence

logger = logging.getLogger("raspilot.logcat")

# Kills causados pela própria ferramenta/usuário (force-stop) não devem
# ser confundidos com reação do RASP.
TOOL_KILL_PATTERNS = (
    re.compile(r"Force stopping .*", re.I),
    re.compile(r"Killing \d+:.*: stop .* due to", re.I),
    re.compile(r"am force-stop", re.I),
)

# Padrões de morte/erro fatal no logcat.
DEATH_PATTERNS = (
    re.compile(r"Fatal signal \d+ \((?P<signal>SIG[A-Z]+)\)", re.I),
    re.compile(r"Process \d+ exited due to signal (?P<signal_nr>\d+)", re.I),
    re.compile(r"has died:.*", re.I),
    re.compile(r"\bam_proc_died\b", re.I),
    re.compile(r"\bam_kill\b", re.I),
    re.compile(r"\bam_crash\b", re.I),
    re.compile(r"\bKilling \d+:", re.I),
    re.compile(r"\bstart timeout\b", re.I),
    re.compile(r"\bANR in\b", re.I),
    re.compile(r"Application Not Responding", re.I),
    re.compile(r"FATAL EXCEPTION", re.I),
)

# Categorias de evidência de segurança. A lista é intencionalmente
# conservadora: termos genéricos só contam quando a linha também cita o
# pacote/pid alvo (ver ``_line_matches_target``).
SECURITY_PATTERNS = {
    "root": re.compile(
        r"\b(magisk|supersu|superuser|apatch|kernelsu|rootbeer|"
        r"root(?:ed|ing)?|/system/(?:x?bin)/su|su binary)\b",
        re.I,
    ),
    "frida": re.compile(
        r"\b(frida|gum-js|gum-js-loop|linjector|frida-server|libfrida|"
        r"frida-agent|gadget)\b",
        re.I,
    ),
    "hooking": re.compile(
        r"\b(xposed|lsposed|edxposed|substrate|sandhook|yahfa|lsplant|"
        r"whale|dobby|riru|zygisk|hook(?:ing|ed)?|inline hook)\b",
        re.I,
    ),
    "emulator": re.compile(
        r"\b(qemu|goldfish|ranchu|genymotion|ldplayer|bluestacks|nox|"
        r"waydroid|android sdk built for|emulator)\b",
        re.I,
    ),
    "debug": re.compile(
        r"\b(ptrace|tracerpid|debugger|anti[- ]?debug|isdebuggerconnected|"
        r"jdwp|waiting for debugger)\b",
        re.I,
    ),
    "tls": re.compile(
        r"\b(certificatepinner|certificate pinning|sslhandshake|"
        r"sslpeerunverified|trust anchor|certpathvalidator|"
        r"certificateexception|ssl_verify|cert_verify|pin(?:ning)?)\b",
        re.I,
    ),
    "integrity": re.compile(
        r"\b(tamper|integrity|checksum|signature mismatch|"
        r"package.*modified|apk.*modified|rooted device)\b",
        re.I,
    ),
    "security_sdk": re.compile(
        r"\b(security|rasp|anti[- ]?(?:root|frida|hook|debug|emulator)|"
        r"threat|dangerous|blocked|detected)\b",
        re.I,
    ),
}

# Categorias que, isoladamente, indicam que o app reagiu a uma ameaça.
# TLS é tratado separadamente (é sintoma de pinning, não necessariamente
# reação do RASP).
RASP_CATEGORIES = ("root", "frida", "hooking", "emulator", "debug", "integrity")

# Limites para manter o relatório enxuto e serializável.
MAX_EVIDENCE_LINES = 40
MAX_LINE_LEN = 500


def _clip(line: str) -> str:
    """Normaliza e limita o tamanho de uma linha de log.

    Args:
        line: Linha bruta do logcat.

    Returns:
        Linha sem espaços nas pontas e truncada em :data:`MAX_LINE_LEN`.
    """
    clean = " ".join((line or "").split())
    return clean[:MAX_LINE_LEN]


def _line_matches_target(line: str, package: Optional[str], pid: Optional[int]) -> bool:
    """Verifica se a linha cita o pacote ou o pid alvo.

    Args:
        line: Linha do logcat.
        package: Package name do app (opcional).
        pid: PID do processo (opcional).

    Returns:
        True se houver menção ao alvo.
    """
    if package and package in line:
        return True
    if pid is not None and re.search(rf"\b{int(pid)}\b", line):
        return True
    return False


def _extract_signal(line: str) -> Optional[str]:
    """Extrai um nome de sinal de uma linha de morte/crash.

    Args:
        line: Linha do logcat.

    Returns:
        Nome do sinal (ex: ``SIGKILL``) ou ``None``.
    """
    for pattern in DEATH_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        named = match.groupdict().get("signal")
        if named:
            return named.upper()
        number = match.groupdict().get("signal_nr")
        if number is not None:
            return {9: "SIGKILL", 6: "SIGABRT", 11: "SIGSEGV"}.get(
                int(number), f"signal {number}"
            )
    if "SIGKILL" in line.upper():
        return "SIGKILL"
    if "SIGSEGV" in line.upper():
        return "SIGSEGV"
    if "SIGABRT" in line.upper():
        return "SIGABRT"
    return None


def _classify_death_kind(signal: Optional[str], lines: Sequence[str]) -> Optional[str]:
    """Classifica a morte em ``crash``, ``kill``, ``anr``, ``exit``.

    Args:
        signal: Sinal extraído (``SIGKILL``, ``SIGSEGV``, ...).
        lines: Linhas de evidência de morte.

    Returns:
        Categoria ou ``None`` se não houver morte.
    """
    blob = " ".join(lines).lower()
    # start timeout é kill do ActivityManager por o app demorar a iniciar
    # (ex: spawn suspenso por muito tempo) — não é reação do RASP.
    if "start timeout" in blob:
        return "start_timeout"
    if "anr in" in blob or "application not responding" in blob:
        return "anr"
    if signal == "SIGKILL":
        return "kill"
    if signal in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE"):
        return "crash"
    if "fatal exception" in blob or "am_crash" in blob:
        return "crash"
    if "am_kill" in blob or "killing " in blob or "has died" in blob:
        return "kill"
    if lines:
        return "exit"
    return None


def analyze_logcat(
    lines: Sequence[str],
    package: Optional[str] = None,
    pid: Optional[int] = None,
) -> Dict[str, object]:
    """Analisa linhas de logcat em busca de evidências RASP.

    A análise é dividida em três grupos:

    - **morte**: sinais fatais, kills do ActivityManager, ANR e crashes;
    - **segurança**: categorias (root, frida, hooking, emulador, debug,
      integridade, TLS, SDK de segurança);
    - **TLS**: erros de certificado/pinning, úteis para corroborar a
      detecção de SSL pinning.

    Termos genéricos de segurança só entram quando a linha cita o pacote
    ou o pid alvo, reduzindo falsos positivos de outros apps/serviços.

    Args:
        lines: Linhas do logcat.
        package: Package name do app alvo (opcional).
        pid: PID do processo alvo (opcional).

    Returns:
        Dict com ``available``, ``death``, ``security_signals``,
        ``tls_errors``, ``has_rasp_evidence``, ``summary`` e
        ``suggestions``.
    """
    lines = [ln for ln in (lines or []) if isinstance(ln, str) and ln.strip()]
    death_evidence: List[str] = []
    tool_kill_lines: List[str] = []
    security: List[Dict[str, str]] = []
    tls_errors: List[str] = []
    categories: Dict[str, int] = {}
    target_lines: List[str] = []

    for raw in lines:
        line = _clip(raw)
        if not line:
            continue
        matches_target = _line_matches_target(line, package, pid)
        if matches_target:
            target_lines.append(line)

        if any(p.search(line) for p in TOOL_KILL_PATTERNS):
            tool_kill_lines.append(line)
            continue

        signal = _extract_signal(line)
        if signal or any(p.search(line) for p in DEATH_PATTERNS):
            if matches_target or (pid is None and package is None):
                death_evidence.append(line)

        for category, pattern in SECURITY_PATTERNS.items():
            if not pattern.search(line):
                continue
            # Termos genéricos exigem o package na mesma linha (o pid
            # sozinho pode casar com timestamps/endereços). Termos muito
            # específicos (frida/xposed/qemu...) aceitam package ou pid.
            if category in ("security_sdk", "tls") and not (
                package and package in line
            ):
                continue
            if category not in ("security_sdk", "tls") and not matches_target:
                # Ainda assim, aceita linhas de sistema que mencionem o pid.
                if pid is None or not re.search(rf"\b{int(pid)}\b", line):
                    continue
            # Stack trace do agente Frida não é, por si só, detecção do
            # RASP: é evidência da instrumentação. Mantém separado para
            # não inflar o veredito; a morte do processo continua contando.
            if category == "frida" and (
                "runtime.cc" in line
                or "frida-agent" in line
                or "frida_agent" in line
            ):
                category = "frida_agent_crash"
            entry = {"category": category, "line": line}
            if entry not in security:
                security.append(entry)
            categories[category] = categories.get(category, 0) + 1
            if category == "tls" and line not in tls_errors:
                tls_errors.append(line)

    signal = None
    for line in death_evidence:
        found = _extract_signal(line)
        if found:
            signal = found
            break
    death_kind = _classify_death_kind(signal, death_evidence)
    death_detected = bool(death_evidence)
    instrumentation_kill = death_kind == "start_timeout"

    rasp_signals = [s for s in security if s["category"] in RASP_CATEGORIES]
    has_rasp_evidence = bool(rasp_signals) or bool(tls_errors)
    agent_terminated = bool(categories.get("frida_agent_crash"))

    if death_detected:
        detail = f"morte ({death_kind or 'desconhecida'}"
        if signal:
            detail += f", {signal}"
        detail += ")"
    elif rasp_signals:
        detail = "sinais de segurança sem morte do processo"
    elif tls_errors:
        detail = "erros de TLS/pinning sem morte do processo"
    elif lines:
        detail = "sem sinais relevantes"
    else:
        detail = "logcat indisponível"

    suggestions: List[str] = []
    if instrumentation_kill:
        suggestions.append(
            "app morto por ActivityManager start timeout (spawn suspenso por muito "
            "tempo) — reduzir scripts carregados antes do resume"
        )
    elif death_detected and rasp_signals:
        suggestions.append(
            "morte correlacionada com evidência de segurança — provável reação do RASP"
        )
    elif death_detected and death_kind in ("crash", "anr"):
        suggestions.append(
            "morte sem evidência de segurança — pode ser crash da instrumentação/app"
        )
    if tls_errors:
        suggestions.append(
            "erros de TLS no logcat corroboram SSL pinning; verificar se o bypass interceptou host real"
        )
    if signal == "SIGKILL" and not rasp_signals:
        suggestions.append(
            "SIGKILL sem mensagem de segurança pode ser kill externo (LMK/usuário/OS)"
        )

    result: Dict[str, object] = {
        "available": bool(lines),
        "lines_scanned": len(lines),
        "categories": categories,
        "death": {
            "detected": death_detected,
            "kind": death_kind,
            "signal": signal,
            "instrumentation_kill": instrumentation_kill,
            "evidence": death_evidence[-MAX_EVIDENCE_LINES:],
        },
        "security_signals": security[-MAX_EVIDENCE_LINES:],
        "tls_errors": tls_errors[-MAX_EVIDENCE_LINES:],
        "target_lines": target_lines[-MAX_EVIDENCE_LINES:],
        "tool_kill_lines": tool_kill_lines[-MAX_EVIDENCE_LINES:],
        "has_rasp_evidence": has_rasp_evidence,
        "agent_terminated": agent_terminated,
        "instrumentation_kill": instrumentation_kill,
        "summary": detail,
        "suggestions": suggestions,
    }
    logger.debug(
        "logcat: linhas=%d morte=%s sinal=%s segurança=%d tls=%d",
        len(lines), death_detected, signal, len(security), len(tls_errors),
    )
    return result


def get_logcat_mark(dm: object) -> Optional[int]:
    """Obtém um marcador de logcat do ``DeviceManager`` com tolerância.

    Args:
        dm: Instância de ``DeviceManager`` (ou fake).

    Returns:
        Índice inteiro do marcador ou ``None`` se indisponível.
    """
    marker = getattr(dm, "logcat_mark", None)
    if not callable(marker):
        return None
    try:
        value = marker()
    except Exception:
        return None
    return value if isinstance(value, int) else None


def analyze_since(
    dm: object,
    mark: Optional[int],
    package: Optional[str] = None,
    pid: Optional[int] = None,
) -> Dict[str, object]:
    """Captura e analisa o logcat desde um marcador.

    Args:
        dm: Instância de ``DeviceManager`` (ou fake).
        mark: Marcador retornado por :func:`get_logcat_mark`.
        package: Package name do app alvo.
        pid: PID do processo alvo.

    Returns:
        Resultado de :func:`analyze_logcat`; ``available=False`` quando o
        dispositivo não expõe a API de logcat.
    """
    getter = getattr(dm, "logcat_since", None)
    if not callable(getter):
        return analyze_logcat([], package=package, pid=pid)
    try:
        lines = getter(mark if mark is not None else 0)
    except Exception:
        logger.debug("Falha ao ler logcat", exc_info=True)
        lines = []
    if not isinstance(lines, list):
        lines = []
    return analyze_logcat(lines, package=package, pid=pid)


def format_detection_signals(
    analysis: Dict[str, object],
    allowed_categories: Sequence[str],
    limit: int = 4,
) -> List[str]:
    """Formata no máximo um sinal de cada categoria para o veredito.

    Evita que um stack trace com dezenas de linhas de ``frida-agent``
    infle ``detection_methods_found``. A evidência completa continua no
    campo ``logcat``.

    Args:
        analysis: Resultado de :func:`analyze_logcat`.
        allowed_categories: Categorias aceitas para aquele check.
        limit: Máximo de entradas retornadas.

    Returns:
        Lista de strings ``logcat_<categoria>: <linha>``.
    """
    allowed = set(allowed_categories)
    seen = set()
    output: List[str] = []
    for item in analysis.get("security_signals", []) or []:
        if not isinstance(item, dict):
            continue
        category = item.get("category", "security")
        if category not in allowed or category in seen:
            continue
        seen.add(category)
        output.append(f"logcat_{category}: {item.get('line', '')}")
        if len(output) >= limit:
            break
    return output


def classify_failure(
    analysis: Dict[str, object], baseline: Optional[dict] = None
) -> Dict[str, object]:
    """Classifica uma falha de observação/script usando logcat + baseline.

    Args:
        analysis: Resultado de :func:`analyze_logcat`.
        baseline: Resultado de ``DeviceManager.run_app_baseline`` (opcional).

    Returns:
        Dict com ``kind`` (``start_timeout``, ``baseline_death``,
        ``rasp_reaction``, ``instrumentation_crash``, ``unknown``),
        ``is_rasp``, ``is_instrumentation`` e ``summary``.
    """
    categories = analysis.get("categories") or {}
    rasp = any(category in (categories or {}) for category in RASP_CATEGORIES)
    death = analysis.get("death") or {}
    baseline_died = bool(
        baseline and baseline.get("available") and baseline.get("alive_at_end") is False
    )

    if analysis.get("instrumentation_kill") or death.get("kind") == "start_timeout":
        kind = "start_timeout"
    elif baseline_died:
        kind = "baseline_death"
    elif analysis.get("agent_terminated"):
        kind = "rasp_agent_terminated"
    elif rasp:
        kind = "rasp_reaction"
    elif death.get("detected") and death.get("kind") == "kill":
        # SIGKILL externo/auto-kill sem start timeout e com baseline vivo
        # é tratado como reação do alvo (os force-stops da ferramenta são
        # filtrados antes).
        kind = "rasp_reaction"
    elif death.get("detected") and death.get("kind") in ("crash", "anr"):
        kind = "instrumentation_crash"
    elif death.get("detected"):
        kind = "unknown_death"
    else:
        kind = "unknown"

    return {
        "kind": kind,
        "is_rasp": kind in ("rasp_reaction", "rasp_agent_terminated"),
        "is_instrumentation": kind in (
            "start_timeout", "baseline_death", "instrumentation_crash"
        ),
        "summary": str(analysis.get("summary", "")),
    }


def format_evidence(analysis: Dict[str, object], limit: int = 8) -> List[str]:
    """Formata as principais evidências de logcat para listas do relatório.

    Args:
        analysis: Resultado de :func:`analyze_logcat`.
        limit: Máximo de linhas retornadas.

    Returns:
        Lista de strings legíveis.
    """
    output: List[str] = []
    death = analysis.get("death") or {}
    if isinstance(death, dict) and death.get("detected"):
        signal = death.get("signal")
        kind = death.get("kind")
        output.append(f"logcat_death: {kind or 'morte'}" + (f" ({signal})" if signal else ""))
        for line in (death.get("evidence") or [])[:limit]:
            output.append(f"logcat: {line}")
    for item in (analysis.get("security_signals") or [])[:limit]:
        if isinstance(item, dict):
            output.append(f"logcat_{item.get('category', 'security')}: {item.get('line', '')}")
    for line in (analysis.get("tls_errors") or [])[:limit]:
        output.append(f"logcat_tls: {line}")
    return output[:limit]
