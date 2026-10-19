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

from rasp_vendors import all_tokens
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
    # A mensagem do ActivityManager não tem os dois-pontos:
    # "Process <pkg> (pid 1234) has died"
    re.compile(r"has died\b", re.I),
    re.compile(r"\bam_proc_died\b", re.I),
    re.compile(r"\bam_kill\b", re.I),
    re.compile(r"\bam_crash\b", re.I),
    re.compile(r"\bKilling \d+:", re.I),
    re.compile(r"\bstart timeout\b", re.I),
    re.compile(r"\bANR in\b", re.I),
    re.compile(r"Application Not Responding", re.I),
    re.compile(r"FATAL EXCEPTION", re.I),
)

# Evidência de segurança com confiança alta.
#
# Só estas linhas podem, sozinhas, sustentar a conclusão de que o app
# reagiu à instrumentação. O critério é objetivo: a linha cita um
# artefato de instrumentação, um sinal de morte rastreado, ou um
# identificador de um SDK de RASP conhecido.
#
# Termos genéricos (root, hook, detected, checksum, emulator) ficam
# fora: eles aparecem em logs comuns de aplicação e transformavam
# qualquer log do app em "o app detectou a instrumentação".
HIGH_CONFIDENCE_PATTERNS = {
    "frida": re.compile(
        r"\b(gum-js-loop|gum-js|linjector|frida-server|re\.frida\.server|"
        r"frida-agent|libfrida|libloader64_v8|libloader32_v7)\b",
        re.I,
    ),
    "hooking": re.compile(
        r"\b(de\.robv\.android\.xposed|lsposed|edxposed|liblspd|"
        r"xposedbridge|xc_methodhook|cydia.?substrate|libsubstrate|"
        r"lsplant|libsandhook|libyahfa|libwhale|libdobby|libshadowhook)\b",
        re.I,
    ),
    "debug": re.compile(
        r"\b(tracerpid:\s*[1-9]|waiting for debugger|"
        r"isdebuggerconnected\(\)\s*==\s*true)\b",
        re.I,
    ),
    "tls": re.compile(
        r"\b(certificatepinner|certificate pinning|certificatepinnerexception|"
        r"sslhandshakeexception|sslpeerunverifiedexception|"
        r"certificateverifyexception|sslpinning|pinning failed|"
        r"pin mismatch|chain validation failed|"
        r"unable to find valid certification path|hostname .* not verified|"
        r"trust anchor|trust manager)\b",
        re.I,
    ),
}

# Evidência de segurança com confiança baixa: contexto, nunca veredito.
#
# São termos que aparecem em logs de aplicação sem qualquer relação com
# instrumentação ("root cause", "lifecycle hook", "checksum mismatch",
# "emulator detected" de um SDK de emulação). Aparecem no relatório como
# contexto, mas não alteram o status de nenhum check.
LOW_CONFIDENCE_PATTERNS = {
    "root": re.compile(
        r"\b(magisk|supersu|superuser|apatch|kernelsu|rootbeer|"
        r"root(?:ed|ing)?|/system/(?:x?bin)/su|su binary)\b",
        re.I,
    ),
    "frida": re.compile(r"\b(frida|gadget)\b", re.I),
    "hooking": re.compile(
        r"\b(xposed|substrate|sandhook|yahfa|lsplant|whale|dobby|riru|zygisk|"
        r"hook(?:ing|ed)?|inline hook)\b",
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

# Identificadores de SDKs de RASP conhecidos. O log de um SDK costuma
# vir na tag do próprio SDK, sem citar o pacote do app — por isso a
# busca por tag é feita separadamente da exigência de citar o alvo.
#
# A lista vem do catálogo de vendors, para que a detecção de vendor
# tenha uma fonte só.
RASP_VENDOR_TAGS = tuple(
    list({token.lower() for token in all_tokens()})
    + [
        "playintegrity", "play integrity", "appcheck",
        "cloudflare", "turnstile", "nucleus", "apk-protector",
    ]
)

# Tags cujo log pertence à ferramenta de instrumentação do operador
# (framework de hooking instalado no device), e não ao app auditado.
OPERATOR_FRAMEWORK_TAGS = (
    "vector", "lsposed", "edxposed", "xposed", "epic", "yahfa", "sandhook",
    "riru", "zygisk", "corepatch", "lspatch",
)

# Categorias de evidência de segurança. A lista é intencionalmente
# conservadora: termos genéricos só contam quando a linha também cita o
# pacote/pid alvo (ver ``_line_matches_target``).
SECURITY_PATTERNS = {
    **{f"low:{k}": v for k, v in LOW_CONFIDENCE_PATTERNS.items()},
    **{f"high:{k}": v for k, v in HIGH_CONFIDENCE_PATTERNS.items()},
}

# Categorias que, isoladamente, indicam que o app reagiu a uma ameaça.
# TLS é tratado separadamente (é sintoma de pinning, não necessariamente
# reação do RASP).
RASP_CATEGORIES = ("root", "frida", "hooking", "emulator", "debug", "integrity")

# Categorias de confiança alta — as únicas que sustentam um veredito.
HIGH_CONFIDENCE_CATEGORIES = tuple(
    f"high:{name}" for name in HIGH_CONFIDENCE_PATTERNS
)

# Limites para manter o relatório enxuto e serializável.
MAX_EVIDENCE_LINES = 40
MAX_LINE_LEN = 500


# Verbos que transformam um termo genérico em evidência de reação.
#
# "xposed" sozinho aparece em log de qualquer app que liste frameworks
# conhecidos; "xposed detected" ou "xposed framework found" é o app
# reagindo a uma ameaça. O verbo é o que dá o peso da evidência.
DETECTION_VERB_PATTERN = re.compile(
    r"\b(detect(?:ed|ion)?|detec(?:ção|cao|ou)|found|encontrado|"
    r"identificad[oa]|block(?:ed|ing)?|bloquead[oa]|negad[oa]|"
    r"rejected|recusad[oa]|violation|viola[çc][ãa]o|tamper|"
    r"comprometid[oa]|suspicious|suspeit[oa])\b",
    re.I,
)


def _is_operator_framework_line(line: str) -> bool:
    """Indica se a linha pertence à tag de um framework de hooking.

    Ferramentas de hooking instaladas no device escrevem no logcat com a
    própria tag. Quando o alvo está no escopo delas, o log resultante
    descreve a ferramenta de instrumentação do operador, não a proteção do
    app auditado.

    Args:
        line: Linha do logcat.

    Returns:
        True se a linha pertence a um framework de hooking do operador.
    """
    low = (line or "").lower()
    for tag in OPERATOR_FRAMEWORK_TAGS:
        if re.search(rf"\b{re.escape(tag)}\b", low):
            return True
    return False


def _vendor_signals(
    lines: List[str],
    package: Optional[str] = None,
    pid: Optional[int] = None,
) -> List[str]:
    """Localiza linhas de log de SDKs de RASP conhecidos.

    O log de um SDK de RASP costuma vir na tag do próprio SDK e não cita
    o pacote do app — a associação é feita pelo pid do processo.

    A linha precisa pertencer ao alvo: sem esse filtro, qualquer linha
    do sistema que mencione o nome de um serviço (uma intent de
    framework, por exemplo) seria contada como reação do app.

    Args:
        lines: Linhas do logcat.
        package: Package name do app alvo.
        pid: PID do processo alvo.

    Returns:
        Linhas que correspondem a um SDK de RASP conhecido.
    """
    found: List[str] = []
    for raw in lines or []:
        line = _clip(raw)
        if not line:
            continue
        if not _line_matches_target(line, package, pid):
            continue
        low = line.lower()
        for vendor in RASP_VENDOR_TAGS:
            if vendor in low:
                if line not in found:
                    found.append(line)
                break
    return found


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

        is_operator_framework = _is_operator_framework_line(line)

        for category, pattern in SECURITY_PATTERNS.items():
            if not pattern.search(line):
                continue
            confidence = "high" if category.startswith("high:") else "low"
            base = category.split(":", 1)[1] if ":" in category else category
            # Termo genérico acompanhado de verbo de detecção sobe para
            # confiança alta: "xposed detected" é reação do app, "xposed"
            # sozinho é apenas um nome em um log.
            if confidence == "low" and base not in (
                "security_sdk", "integrity", "emulator", "debug",
            ) and DETECTION_VERB_PATTERN.search(line):
                confidence = "high"
            # Termos genéricos exigem o package na mesma linha (o pid
            # sozinho pode casar com timestamps/endereços). Termos muito
            # específicos (frida/xposed/qemu...) aceitam package ou pid.
            if base in ("security_sdk", "tls") and not (
                package and package in line
            ):
                continue
            if base not in ("security_sdk", "tls") and not matches_target:
                # Ainda assim, aceita linhas de sistema que mencionem o pid.
                if pid is None or not re.search(rf"\b{int(pid)}\b", line):
                    continue
            # Pilha de crash do agente Frida não é, por si só, detecção
            # do RASP: é evidência da instrumentação. Mantém separado
            # para não inflar o veredito; a morte do processo continua
            # contando. Merece a categoria própria apenas quando a
            # linha descreve um crash, e não a simples menção ao
            # artefato.
            if base == "frida" and (
                "runtime.cc" in line
                or "frida_agent" in line
                or re.search(
                    r"frida[-_]agent.*(signal|crash|abort|segv|backtrace)",
                    line, re.I,
                )
            ):
                base = "frida_agent_crash"
                confidence = "low"
            # Log de framework de hooking do operador não é evidência de
            # proteção do app auditado: é contaminação do ambiente.
            if is_operator_framework and confidence == "low":
                base = f"operator:{base}"
            entry = {"category": base, "confidence": confidence, "line": line}
            if entry not in security:
                security.append(entry)
            categories[base] = categories.get(base, 0) + 1
            if base == "tls" and confidence == "high" and line not in tls_errors:
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

    # Só a evidência de confiança alta sustenta a conclusão de que o app
    # reagiu. Termos genéricos permanecem no relatório como contexto.
    rasp_signals = [
        s for s in security
        if s["category"] in RASP_CATEGORIES and s.get("confidence") == "high"
    ]
    context_signals = [
        s for s in security if s.get("confidence") != "high"
    ]
    vendor_signals = _vendor_signals(lines, package, pid)
    has_rasp_evidence = bool(rasp_signals) or bool(tls_errors) or bool(vendor_signals)
    agent_terminated = bool(categories.get("frida_agent_crash"))

    if death_detected:
        detail = f"morte ({death_kind or 'desconhecida'}"
        if signal:
            detail += f", {signal}"
        detail += ")"
    elif rasp_signals or vendor_signals:
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
        "context_signals": context_signals[-MAX_EVIDENCE_LINES:],
        "vendor_signals": vendor_signals[-MAX_EVIDENCE_LINES:],
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
        # Somente evidência de confiança alta sustenta um veredito: termos
        # genéricos (root, hook, detected) aparecem em logs comuns e
        # transformavam qualquer log do app em reação à instrumentação.
        if item.get("confidence") != "high":
            continue
        category = item.get("category", "security")
        if category not in allowed or category in seen:
            continue
        seen.add(category)
        output.append(f"logcat_{category}: {item.get('line', '')}")
        if len(output) >= limit:
            break
    # Sinais de vendor de RASP entram como evidência direta: o log do SDK
    # é a reação do app, mesmo sem citar o pacote na mesma linha.
    for line in analysis.get("vendor_signals", []) or []:
        entry = f"logcat_vendor: {line}"
        if entry not in output:
            output.append(entry)
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
    rasp = any(
        category in (categories or {}) for category in HIGH_CONFIDENCE_CATEGORIES
    ) or bool(analysis.get("vendor_signals"))
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
