"""RASPilot — trilha de execução legível por humanos e por LLMs.

Cada check devolve um resultado estruturado; este módulo o converte em
uma sequência de etapas com a mesma semântica em todos os checks:

* ``phase`` — em que momento a ação aconteceu (contexto do dispositivo,
  análise estática, observação dinâmica, bypass ou veredito);
* ``action`` — o que o RASPilot tentou executar;
* ``outcome`` — o que encontrou (detectado, não detectado, sucesso,
  bloqueado, pulado, inconclusivo, erro ou não aplicável);
* ``details`` — explicação curta do resultado;
* ``evidence`` — os sinais concretos que sustentam o resultado;
* ``reported_status`` — o status final atribuído pelo relatório
  (``OK``/``FALHOU``/``SKIP``/``N/A``/``ERROR``).

A trilha é gerada a partir do próprio resultado do check, sem conhecer
detalhes do app auditado: o mesmo formato vale para qualquer alvo e para
qualquer proteção adicionada no futuro.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

# Limite de itens de evidência por etapa na trilha. O resultado completo
# continua disponível em ``details``; a trilha existe para leitura rápida.
MAX_EVIDENCE = 12

# Rótulos das ações de cada vetor. O nome interno do vetor continua no
# JSON; o rótulo descreve o que foi realmente tentado.
SUBCHECK_ACTIONS: Dict[str, Dict[str, str]] = {
    "anti_root": {
        "su_binaries": "Procurar binários su em caminhos canônicos",
        "magisk": "Procurar Magisk (package, diretórios e binário)",
        "root_props": "Ler propriedades de build ligadas a root/debug",
        "dangerous_apps": "Listar apps gerenciadores de root instalados",
        "rw_system": "Verificar se /system está montado como rw",
        "busybox": "Procurar busybox nos caminhos usuais",
        "alt_root_solutions": "Procurar APatch/KernelSU (paths e binários)",
    },
    "anti_frida": {
        "frida_processes": "Procurar processos do Frida (ps)",
        "frida_ports": "Procurar portas do Frida (netstat/ss//proc/net/tcp)",
        "frida_threads": "Inspecionar threads do processo alvo",
        "frida_libraries": "Enumerar módulos carregados no processo alvo",
    },
    "anti_hooking": {
        "hook_framework_packages": "Procurar frameworks de hooking instalados",
        "hook_modules_on_device": "Procurar módulos de hooking em /data/adb",
        "hook_framework_runtime": "Identificar o framework de hooking ativo",
        "hook_libraries": "Enumerar libs de hooking no processo alvo",
    },
    "anti_emulator": {
        "emulator_props": "Comparar propriedades de build com padrões de emulador",
        "emulator_files": "Procurar arquivos típicos de emulador",
        "cpu_architecture": "Classificar a ABI da CPU",
        "sensors": "Contar e classificar sensores",
        "bluetooth_mac": "Verificar o MAC de Bluetooth",
        "genymotion": "Procurar Genymotion",
        "third_party_emulators": "Procurar LDPlayer/BlueStacks/Nox/Waydroid",
    },
}

BYPASS_ACTIONS = {
    "anti_hooking": "Tentar neutralizar as checagens anti-hook do app",
    "anti_emulator": "Tentar ocultar os artefatos decisivos de emulador",
    "ssl_pinning": "Tentar contornar o SSL pinning e interceptar conexões",
}

STATIC_ACTIONS = {
    "anti_root": "Analisar o APK por referências à detecção de root",
    "anti_frida": "Analisar o APK por assinaturas anti-Frida",
    "anti_hooking": "Analisar o APK por assinaturas anti-hook",
    "anti_emulator": "Analisar o APK por assinaturas anti-emulador",
    "ssl_pinning": "Analisar o APK por assinaturas de SSL pinning",
}

DYNAMIC_ACTIONS = {
    "anti_frida": "Observar a detecção de Frida pelo app durante a janela",
    "anti_hooking": "Observar as checagens anti-hook do app durante a janela",
    "anti_emulator": "Fazer o app enxergar um emulador e observar a reação",
}

STATUS_OUTCOMES = {
    "OK": "ok",
    "FALHOU": "failed",
    "SKIP": "skipped",
    "N/A": "not_applicable",
    "ERROR": "error",
}


def _text(value: Any, limit: int = 600) -> str:
    """Converte um valor arbitrário em texto curto e de linha única.

    Args:
        value: Valor do resultado do check.
        limit: Tamanho máximo do texto.

    Returns:
        Representação legível, sem quebras de linha.
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        text = "; ".join(
            f"{key}={_text(item, 140)}" for key, item in value.items()
        )
    elif isinstance(value, (list, tuple, set)):
        text = "; ".join(_text(item, 140) for item in value)
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def _evidence(value: Any) -> List[str]:
    """Normaliza uma coleção de evidências em uma lista curta.

    Args:
        value: String, lista, tupla, conjunto ou dict de evidências.

    Returns:
        Lista de evidências não vazias, limitada a :data:`MAX_EVIDENCE`.
    """
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, dict):
        items = [f"{key}={_text(item, 160)}" for key, item in value.items()]
    elif isinstance(value, Iterable):
        items = [_text(item, 200) for item in value]
    else:
        items = [str(value)]
    items = [item for item in items if item]
    if len(items) > MAX_EVIDENCE:
        extra = len(items) - MAX_EVIDENCE
        items = items[:MAX_EVIDENCE] + [f"(+{extra} evidência(s) no resultado completo)"]
    return items


def _entry(
    phase: str,
    action: str,
    outcome: str,
    details: str = "",
    evidence: Any = None,
    reported_status: Optional[str] = None,
) -> dict:
    """Monta uma etapa da trilha de execução.

    Args:
        phase: ``context``, ``static``, ``detection``, ``bypass`` ou
            ``verdict``.
        action: O que foi tentado.
        outcome: Resultado da tentativa.
        details: Explicação curta.
        evidence: Sinais concretos que sustentam o resultado.
        reported_status: Status final do check (só no veredito).

    Returns:
        Dict serializável em JSON.
    """
    entry: Dict[str, Any] = {
        "phase": phase,
        "action": action,
        "outcome": outcome,
        "details": _text(details),
    }
    evidence_items = _evidence(evidence)
    if evidence_items:
        entry["evidence"] = evidence_items
    if reported_status:
        entry["reported_status"] = reported_status
    return entry


def _subcheck_entries(
    trace: List[dict],
    check_name: str,
    checks: Any,
    phase: str = "detection",
) -> None:
    """Adiciona uma etapa para cada vetor interno de um check.

    Args:
        trace: Trilha em construção.
        check_name: Nome do check dono dos vetores.
        checks: Dict ``{nome_do_vetor: resultado}``.
        phase: Fase atribuída aos vetores.
    """
    if not isinstance(checks, dict):
        return
    labels = SUBCHECK_ACTIONS.get(check_name, {})
    for name, result in checks.items():
        action = labels.get(name, f"Executar vetor {name}")
        if not isinstance(result, dict):
            trace.append(_entry(phase, action, "ok", _text(result)))
            continue
        if result.get("skipped"):
            outcome = "skipped"
        elif result.get("error"):
            outcome = "error"
        elif result.get("detected"):
            outcome = "detected"
        else:
            outcome = "not_detected"
        details = result.get("details") or ""
        if result.get("error"):
            details = f"{details} (erro: {result['error']})".strip()
        trace.append(
            _entry(
                phase,
                action,
                outcome,
                details,
                result.get("evidence"),
            )
        )


def _static_entry(trace: List[dict], check_name: str, detection: Any) -> None:
    """Adiciona a etapa de análise estática do APK, quando houve.

    Args:
        trace: Trilha em construção.
        check_name: Nome do check.
        detection: Resultado da detecção estática.
    """
    if not isinstance(detection, dict) or not detection:
        return
    detected = bool(
        detection.get("static_detected") or detection.get("pinning_detected")
    )
    outcome = "detected" if detected else "not_detected"
    details = detection.get("details") or ""
    if detection.get("available") is False and not detected:
        outcome = "skipped"
        details = details or "análise estática não executada"
    if detection.get("error"):
        outcome = "error"
    if detected:
        principal = detection.get("primary") or detection.get("type")
        if principal:
            details = f"principal={principal}; {details}".strip("; ")
    trace.append(
        _entry(
            "static",
            STATIC_ACTIONS.get(check_name, "Analisar o APK"),
            outcome,
            details,
            detection.get("evidence"),
        )
    )


def _dynamic_entry(trace: List[dict], check_name: str, detection: Any) -> None:
    """Adiciona a etapa de observação dinâmica do app.

    Args:
        trace: Trilha em construção.
        check_name: Nome do check.
        detection: ``app_detection`` devolvido pelo check.
    """
    if not isinstance(detection, dict) or not detection:
        return
    action = DYNAMIC_ACTIONS.get(check_name, "Observar o app em execução")
    status = detection.get("observation_status")
    error = detection.get("error")
    findings = detection.get("detection_methods_found") or []
    strong = detection.get("strong_signals") or []
    weak = detection.get("weak_signals") or []

    if check_name == "anti_frida":
        detected = bool(findings)
    else:
        detected = bool(detection.get("detected")) or bool(strong)
    if detected:
        outcome = "detected"
    elif error and status in (
        "error", "crashed", "start_timeout", "instrumentation_crash"
    ):
        outcome = "error"
    elif weak or status in (
        "native_only", "inconclusive", "baseline_death", "rasp_reaction"
    ):
        outcome = "inconclusive"
    else:
        outcome = "not_detected"

    parts: List[str] = []
    if detection.get("details"):
        parts.append(str(detection["details"]))
    if status and status != "ok":
        parts.append(f"status da observação={status}")
    if detection.get("death_classification"):
        parts.append(f"morte={detection['death_classification']}")
    if detection.get("app_alive_at_end") is False:
        parts.append("app não estava vivo ao final da janela")
    if error:
        parts.append(f"erro: {error}")

    evidence: List[Any] = []
    evidence.extend(strong or findings or weak)
    channels = detection.get("channels")
    if isinstance(channels, dict):
        decisive = channels.get("decisive") or []
        secondary = channels.get("secondary") or []
        if decisive or secondary:
            parts.append(
                f"canais: decisivos={len(decisive)}, secundários={len(secondary)}"
            )
            evidence.extend(decisive)
    evidence.extend(_evidence(detection.get("logcat_evidence")))

    trace.append(
        _entry("detection", action, outcome, "; ".join(parts), evidence)
    )


def _bypass_entry(trace: List[dict], check_name: str, result: dict) -> None:
    """Adiciona a etapa de bypass (ou o motivo de ela não ter rodado).

    Args:
        trace: Trilha em construção.
        check_name: Nome do check.
        result: Resultado completo do check.
    """
    details = result.get("bypass_details")
    reason = result.get("bypass_skipped_reason")
    method = (
        result.get("bypass_method")
        or (details or {}).get("method")
        or "frida"
    )
    action = f"{BYPASS_ACTIONS.get(check_name, 'Tentar contornar a proteção')} (método {method})"

    if not isinstance(details, dict) or not details:
        if reason:
            trace.append(_entry("bypass", action, "skipped", reason))
        return

    if details.get("blocked"):
        outcome = "blocked"
    elif details.get("inconclusive"):
        outcome = "inconclusive"
    elif details.get("success") is True:
        outcome = "success"
    elif details.get("success") is None:
        outcome = "inconclusive"
    elif details.get("error"):
        outcome = "error"
    else:
        outcome = "resisted"

    # O resultado do bypass pode ter sido rebaixado pelo check (ex.: o
    # bypass rodou, mas nenhuma checagem decisiva foi exercitada). A
    # trilha precisa mostrar o que foi REPORTADO, não só o retorno
    # bruto da camada de bypass.
    reported_bypass = result.get("bypass_successful")
    if reported_bypass is None and reason:
        outcome = "inconclusive"
    elif reported_bypass is True:
        outcome = "success"
    elif reported_bypass is False:
        if details.get("blocked"):
            outcome = "blocked"
        elif details.get("error"):
            outcome = "error"
        else:
            outcome = "resisted"

    parts: List[str] = []

    def _add_detail(value: Any) -> None:
        text = _text(value)
        if text and text not in parts:
            parts.append(text)

    if details.get("details"):
        _add_detail(details["details"])
    if details.get("error"):
        _add_detail(f"erro: {details['error']}")
    if details.get("skipped_reason"):
        _add_detail(details["skipped_reason"])
    if reason:
        _add_detail(reason)
    if not parts:
        alive = details.get("app_alive_at_end")
        if alive is not None:
            _add_detail(f"app vivo ao final: {alive}")
        else:
            _add_detail("bypass avaliado")

    evidence: List[Any] = []
    for key in (
        "effective_logs",
        "neutralized",
        "observed_checks",
        "masked_channels",
        "exposed_channels",
        "intercepted_hosts",
        "spoofed_values",
        "detection_signals",
        "bypass_logs",
    ):
        value = details.get(key)
        if value:
            evidence.extend(_evidence(value))
            if check_name == "anti_hooking" and key == "effective_logs":
                # effective_logs são a evidência forte; os demais campos
                # ficam como contexto e não precisam inflar a trilha.
                break
    trace.append(
        _entry("bypass", action, outcome, "; ".join(parts), evidence)
    )


def _verdict_text(check_name: str, result: dict) -> str:
    """Resume o veredito final de um check em uma linha.

    Args:
        check_name: Nome do check.
        result: Resultado completo do check.

    Returns:
        Texto do veredito.
    """
    if check_name == "anti_root":
        positive = result.get("positive_vectors") or []
        app_root = result.get("app_root_detection") or {}
        return (
            f"is_rooted={bool(result.get('is_rooted'))}; "
            f"confiança={result.get('confidence')}; "
            f"vetores positivos={', '.join(map(str, positive)) or 'nenhum'}; "
            f"app_detecta_root={bool(app_root.get('present'))}"
        )
    if check_name == "anti_frida":
        app_detection = result.get("app_detection") or {}
        return (
            f"vulnerable={result.get('vulnerable')}; "
            f"proteção={bool(result.get('protection_detected'))}; "
            f"observação={app_detection.get('observation_status') or 'n/a'}; "
            f"sinais={len(app_detection.get('detection_methods_found') or [])}"
        )
    if check_name == "anti_hooking":
        return (
            f"protection_detected={bool(result.get('protection_detected'))}; "
            f"bypass_successful={result.get('bypass_successful')}; "
            f"método={result.get('bypass_method') or 'n/a'}"
        )
    if check_name == "anti_emulator":
        return (
            f"protection_detected={bool(result.get('protection_detected'))}; "
            f"bypass_successful={result.get('bypass_successful')}; "
            f"probe={result.get('probe_method') or 'n/a'}; "
            f"bypass={result.get('bypass_method') or 'n/a'}"
        )
    if check_name == "ssl_pinning":
        return (
            f"pinning_detected={bool(result.get('pinning_detected'))}; "
            f"tipo={result.get('pinning_type') or 'n/a'}; "
            f"bypass_successful={result.get('bypass_successful')}"
        )
    return "veredito consolidado"


def build_execution_log(
    check_name: str,
    result: dict,
    status: str,
) -> List[dict]:
    """Converte o resultado de um check em uma trilha de execução.

    A função é tolerante a resultados parciais: um check interrompido,
    pulado ou com erro produz uma trilha curta e explícita em vez de
    omitir a etapa.

    Args:
        check_name: Nome do check no relatório.
        result: Resultado do ``run_all()`` (pode ser vazio).
        status: Status final atribuído pelo relatório.

    Returns:
        Lista de etapas prontas para JSON/HTML/terminal.
    """
    if not result:
        return [
            _entry(
                "verdict",
                "Executar o check",
                "error",
                "o check não retornou resultado",
                reported_status=status,
            )
        ]
    if result.get("skipped"):
        return [
            _entry(
                "verdict",
                "Executar o check",
                "skipped",
                "check pulado via --skip",
                reported_status=status,
            )
        ]

    # Erro fatal sem qualquer resultado específico (o pipeline só
    # recebeu a exceção do check).
    specific_keys = {
        "checks", "app_detection", "bypass_details", "static_detection",
        "device_environment", "detection", "is_rooted", "vulnerable",
        "protection_detected", "pinning_detected", "frida_present",
    }
    if result.get("error") and not (specific_keys & set(result)):
        return [
            _entry(
                "verdict",
                "Executar o check",
                "error",
                str(result["error"]),
                reported_status=status,
            )
        ]

    trace: List[dict] = []

    if check_name == "anti_root":
        _subcheck_entries(trace, check_name, result.get("checks"))
        _static_entry(trace, check_name, result.get("app_root_detection"))
    elif check_name == "anti_frida":
        _subcheck_entries(trace, check_name, result.get("checks"))
        _static_entry(trace, check_name, result.get("static_detection"))
        _dynamic_entry(trace, check_name, result.get("app_detection"))
        app_detection = result.get("app_detection") or {}
        if app_detection.get("detection_methods_found"):
            trace.append(
                _entry(
                    "detection",
                    "Correlacionar sinais de detecção do app",
                    "detected",
                    app_detection.get("details")
                    or "o app executou detecção de Frida",
                    app_detection.get("detection_methods_found"),
                )
            )
    elif check_name == "anti_hooking":
        _subcheck_entries(trace, check_name, result.get("checks"))
        _static_entry(trace, check_name, result.get("static_detection"))
        _dynamic_entry(trace, check_name, result.get("app_detection"))
        module_detection = result.get("module_detection") or {}
        if module_detection.get("detection_methods_found"):
            trace.append(
                _entry(
                    "detection",
                    "Observar as checagens anti-hook com o módulo do dispositivo",
                    "detected",
                    module_detection.get("details")
                    or "o módulo observou consultas a artefatos de hooking",
                    module_detection.get("detection_methods_found"),
                )
            )
        _bypass_entry(trace, check_name, result)
    elif check_name == "anti_emulator":
        device = result.get("device_environment") or {}
        _subcheck_entries(
            trace, check_name, device.get("checks"), phase="context"
        )
        _static_entry(trace, check_name, result.get("static_detection"))
        _dynamic_entry(trace, check_name, result.get("app_detection"))
        _bypass_entry(trace, check_name, result)
    elif check_name == "ssl_pinning":
        _static_entry(
            trace,
            check_name,
            result.get("detection") or result,
        )
        if result.get("pinning_detected"):
            _bypass_entry(trace, check_name, result)
        elif not result.get("pinning_detected"):
            trace.append(
                _entry(
                    "bypass",
                    BYPASS_ACTIONS[check_name],
                    "not_applicable",
                    "nenhum SSL pinning foi detectado no APK",
                )
            )
    else:
        trace.append(
            _entry(
                "detection",
                f"Executar o check {check_name}",
                "ok",
                _text(result),
            )
        )

    trace.append(
        _entry(
            "verdict",
            "Consolidar o veredito do check",
            STATUS_OUTCOMES.get(status, "ok"),
            _verdict_text(check_name, result),
            reported_status=status,
        )
    )
    return trace
