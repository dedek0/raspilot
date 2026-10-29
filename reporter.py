"""RASPilot — Gerador de relatórios JSON e HTML.

Consolida os resultados de cada check, aplica a semântica de status
(``OK`` = proteção funcionou / ``FALHOU`` = bypass venceu /
``ERROR`` = check não executou) e gera relatórios estruturados
prontos para consumo humano (HTML) e por LLMs (JSON/MCP).

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from device_manager import TOOL_NAME, TOOL_VERSION
from execution_log import build_execution_log

# Versão do schema do documento JSON. Incrementada quando a forma do
# relatório muda de modo incompatível, para que um consumidor possa
# detectar a mudança em vez de interpretar campos ausentes.
SCHEMA_VERSION = 5

logger = logging.getLogger("raspilot.reporter")

# Ordem de apresentação dos checks no relatório. A execução dos checks
# dinâmicos não segue essa ordem (o anti-emulador precisa de spawns
# próprios e roda por último), mas o relatório mantém a ordem estável.
REPORT_ORDER = (
    "anti_root",
    "anti_tampering",
    "anti_emulator",
    "anti_frida",
    "anti_hooking",
    "ssl_pinning",
    "anti_proxy",
)

# Diretório dos templates Jinja2 (relativo a este arquivo).
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


class Reporter:
    """Coleta resultados de checks e gera relatórios JSON/HTML.

    Exemplo de uso::

        rep = Reporter(device_info=info, package_name="com.example.app")
        rep.collect("anti_root", AntiRootCheck(dm).run_all())
        json_path, html_path = rep.save()
    """

    def __init__(
        self,
        device_info: dict,
        package_name: str,
        output_dir: str = "reports/",
        run_context: Optional[dict] = None,
        timestamp: Optional[datetime] = None,
        static_profile: Optional[dict] = None,
    ) -> None:
        """Inicializa o relatório com metadados do dispositivo e alvo.

        Args:
            device_info: Dict retornado por ``DeviceManager.get_device_info()``.
            package_name: Package name do app auditado.
            output_dir: Diretório de saída dos relatórios.
            run_context: Metadados da execução (argumentos da CLI, versão
                do Frida, hashes dos scripts, pid alvo, resultado do
                baseline). Tornam a execução reproduzível por terceiros.
            timestamp: Timestamp do relatório. Permite reconstruir um
                relatório a partir do estado salvo sem alterar a data.
            static_profile: Perfil estático completo do APK. Quando
                presente, entra no JSON como ``static_profile`` (recurso
                estável para MCP e para retomada de sessão).
        """
        self.device_info = dict(device_info or {})
        self.package_name = package_name
        self.output_dir = output_dir
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.run_context: Dict[str, Any] = dict(run_context or {})
        self.static_profile: Optional[dict] = static_profile
        self._results: Dict[str, dict] = {}

    @property
    def results(self) -> Dict[str, dict]:
        """Resultados coletados, por check (cópia rasa)."""
        return dict(self._results)

    # ------------------------------------------------------------------
    # Coleta
    # ------------------------------------------------------------------
    def collect(self, check_name: str, result: dict) -> None:
        """Registra o resultado de um check.

        Args:
            check_name: Nome do check ('anti_root', 'anti_frida',
                'anti_emulator', 'anti_hooking', 'ssl_pinning').
            result: Dict retornado pelo ``run_all()`` do check.
        """
        self._results[check_name] = result or {}
        logger.debug("Relatório: resultado coletado para %s", check_name)

    # ------------------------------------------------------------------
    # Semântica de status
    # ------------------------------------------------------------------
    @staticmethod
    def _verdict(status: str, label: str, detail: str = "", **extra: Any) -> dict:
        """Monta um veredito de detecção ou bypass."""
        verdict = {"status": status, "label": label, "detail": detail or None}
        verdict.update(extra)
        return verdict

    @classmethod
    def _dual_verdicts(
        cls, check_name: str, result: dict, status: str
    ) -> Tuple[dict, dict]:
        """Deriva os dois vereditos de um check.

        ``detection`` responde se a proteção foi observada/identificada.
        ``bypass`` responde se a evasão venceu, resistiu ou não foi
        exercitada. O ``status`` geral continua sendo a consolidação para
        compatibilidade com consumidores antigos.
        """
        if result.get("skipped"):
            return (
                cls._verdict("not_applicable", "Não aplicável", "check pulado"),
                cls._verdict("not_applicable", "Não aplicável", "check pulado"),
            )

        detection = cls._verdict("inconclusive", "Inconclusivo")
        bypass = cls._verdict("not_exercised", "Não exercitado")

        if check_name == "anti_tampering":
            detected = result.get("tamper_detected")
            bypass = result.get("bypass_successful")
            static_present = bool(result.get("static_detected"))
            if detected is True:
                detection = cls._verdict(
                    "detected", "Detectado",
                    "app reagiu à assinatura alterada em memória",
                    sources=["dynamic"],
                )
            elif bypass is True:
                detection = cls._verdict(
                    "not_detected", "Não detectado",
                    "app sobreviveu à assinatura alterada",
                    sources=["dynamic"],
                )
            elif static_present:
                detection = cls._verdict(
                    "indicated", "Indicado (estático)",
                    "há APIs de integridade no APK, sem sonda dinâmica",
                    sources=["static"],
                )
            else:
                detection = cls._verdict(
                    "inconclusive", "Inconclusivo",
                    result.get("bypass_skipped_reason")
                    or "sonda de tamper não concluiu",
                )
            if bypass is True:
                bypass_verdict = cls._verdict(
                    "bypassed", "Bypass venceu",
                    "app sobreviveu e continuou utilizável",
                    method=result.get("bypass_method"),
                )
            elif bypass is False:
                bypass_verdict = cls._verdict(
                    "resisted", "Proteção resistiu",
                    "app detectou/bloqueou a assinatura alterada",
                    method=result.get("bypass_method"),
                )
            elif static_present:
                bypass_verdict = cls._verdict(
                    "not_exercised", "Não exercitado",
                    result.get("bypass_skipped_reason")
                    or "sonda de tamper não executada",
                    method=result.get("bypass_method"),
                )
            else:
                bypass_verdict = cls._verdict(
                    "not_applicable", "Não aplicável",
                    "sem proteção ou sonda de tamper",
                )
            return detection, bypass_verdict

        if check_name == "anti_frida":
            app = result.get("app_detection") or {}
            static = result.get("static_analysis") or {}
            signals = list(app.get("detection_methods_found") or [])
            vulnerable = result.get("vulnerable")
            static_present = bool(static.get("present"))
            if signals or app.get("detected") or vulnerable is False:
                detection = cls._verdict(
                    "detected", "Detectado",
                    app.get("details") or "o app executou detecção de Frida",
                    sources=list(result.get("protection_sources") or []),
                )
            elif static_present:
                detection = cls._verdict(
                    "indicated", "Indicado (estático)",
                    "há referências anti-Frida no APK, mas sem detecção dinâmica",
                    sources=["static"],
                )
            elif vulnerable is True:
                detection = cls._verdict(
                    "not_detected", "Não detectado",
                    "o app não reagiu ao Frida na janela",
                )
            else:
                detection = cls._verdict(
                    "inconclusive", "Inconclusivo",
                    app.get("error") or "observação sem conclusão",
                )
            protection = bool(result.get("protection_detected"))
            bypass = cls._bypass_verdict(
                result, protection, result.get("bypass_skipped_reason")
            )
            return detection, bypass

        if check_name == "anti_root":
            app = result.get("app_detection") or {}
            module = result.get("module_detection") or {}
            static = result.get("static_analysis") or {}
            dynamic = bool(
                app.get("detected")
                or module.get("detected")
                or (result.get("app_root_detection") or {}).get("dynamic_detected")
            )
            sources = []
            if static.get("present"):
                sources.append("static")
            if module.get("detected"):
                sources.append("module")
            if app.get("detected"):
                sources.append("dynamic")
            if dynamic:
                detection = cls._verdict(
                    "detected", "Detectado",
                    app.get("details") or module.get("details")
                    or "o app executou checagens de root",
                    sources=sources,
                )
            elif static.get("present"):
                detection = cls._verdict(
                    "indicated", "Indicado (estático)",
                    "há referências de root no APK, sem checagem dinâmica",
                    sources=sources,
                )
            elif result.get("protection_detected") is False:
                detection = cls._verdict(
                    "not_detected", "Não detectado",
                    "nenhuma referência ou checagem de root observada",
                )
            else:
                detection = cls._verdict(
                    "inconclusive", "Inconclusivo",
                    app.get("error") or "análise de root sem conclusão",
                )
            bypass = cls._bypass_verdict(
                result, bool(result.get("protection_detected")),
                result.get("bypass_skipped_reason"),
            )
            return detection, bypass

        if check_name in ("anti_hooking", "anti_emulator", "anti_proxy"):
            app = result.get("app_detection") or {}
            static = result.get("static_detection") or {}
            static_present = bool(static.get("static_detected"))
            dynamic = bool(app.get("detected"))
            observation = str(app.get("observation_status") or "")
            query_only = bool(app.get("query_only"))
            if dynamic:
                detection = cls._verdict(
                    "detected",
                    "Detectado (consulta)" if query_only else "Detectado",
                    app.get("details") or "checagem observada em runtime",
                    sources=list(Reporter._protection_sources(result)),
                )
            elif static_present:
                detection = cls._verdict(
                    "indicated", "Indicado (estático)",
                    static.get("details") or "assinaturas no APK",
                    sources=["static"],
                )
            elif result.get("protection_detected"):
                detection = cls._verdict(
                    "indicated", "Indicado",
                    "proteção identificada por uma fonte sem detalhe dinâmico",
                    sources=list(Reporter._protection_sources(result)),
                )
            elif app.get("error") or observation in (
                "error", "crashed", "start_timeout", "native_only",
                "inconclusive", "baseline_death", "unattributed_death",
            ):
                detection = cls._verdict(
                    "inconclusive", "Inconclusivo",
                    app.get("error") or observation or "observação sem conclusão",
                )
            else:
                detection = cls._verdict(
                    "not_detected", "Não detectado",
                    "nenhuma checagem observada",
                )
            bypass = cls._bypass_verdict(
                result, bool(result.get("protection_detected")),
                result.get("bypass_skipped_reason"),
            )
            return detection, bypass

        if check_name == "ssl_pinning":
            static = result.get("static_analysis") or {}
            pinned = bool(result.get("pinning_detected"))
            suspected = bool(result.get("pinning_suspected"))
            if pinned:
                detection = cls._verdict(
                    "detected", "Detectado",
                    f"pinning do tipo {result.get('pinning_type') or 'n/a'}",
                    sources=["static"],
                )
            elif suspected:
                detection = cls._verdict(
                    "suspected", "Suspeito / não confirmado",
                    "há indícios fracos, mas o pinning não foi confirmado",
                    sources=["static"],
                )
            elif static.get("present") is False:
                detection = cls._verdict(
                    "not_detected", "Não detectado",
                    "nenhuma assinatura de pinning no APK",
                )
            else:
                detection = cls._verdict(
                    "inconclusive", "Inconclusivo",
                    result.get("error") or "análise de pinning sem conclusão",
                )
            bypass = cls._bypass_verdict(
                result, bool(pinned or suspected),
                result.get("bypass_skipped_reason"),
            )
            return detection, bypass

        return detection, bypass

    @classmethod
    def _bypass_verdict(cls, result: dict, protection: bool, reason: Any) -> dict:
        success = result.get("bypass_successful")
        method = result.get("bypass_method")
        detail = str(reason or result.get("verdict_reason") or "")
        if success is True:
            return cls._verdict(
                "bypassed", "Bypass venceu", detail, method=method
            )
        if success is False:
            return cls._verdict(
                "resisted", "Proteção resistiu", detail, method=method
            )
        if protection:
            return cls._verdict(
                "not_exercised", "Não exercitado", detail or "bypass não avaliado",
                method=method,
            )
        return cls._verdict(
            "not_applicable", "Não aplicável", "sem proteção a ser contornada"
        )

    @staticmethod
    def _protection_sources(result: dict) -> list:
        """Lista de onde veio a evidência de proteção do app.

        A distinção importa: uma assinatura estática no APK prova que o
        código referencia a checagem, enquanto a observação dinâmica
        prova que o app a executou na janela. O relatório mostra as duas
        coisas separadamente para não sugerir mais do que foi medido.

        Args:
            result: Resultado de um check de proteção (hooking/emulador).

        Returns:
            Lista com ``static_apk``, ``dynamic`` e/ou ``module``.
        """
        sources = []
        static = result.get("static_detection") or {}
        if static.get("static_detected"):
            sources.append("static_apk")
        if (static.get("asc") or {}).get("effective"):
            sources.append("static_asc")
        app_detection = result.get("app_detection") or {}
        if app_detection.get("detected"):
            sources.append("dynamic")
        module = result.get("module_detection") or {}
        if module.get("detection_methods_found"):
            sources.append("module")
        return sources

    @staticmethod
    def _status_for(check_name: str, result: dict) -> Tuple[str, Dict[str, Any]]:
        """Deriva o status textual e o resumo de um check.

        Regra: ``OK`` = a proteção do app funcionou; ``FALHOU`` = o
        bypass venceu; ``ERROR`` = o check não pôde executar.

        Args:
            check_name: Nome do check.
            result: Resultado do ``run_all()``.

        Returns:
            Tupla ``(status, resumo_dict)``.
        """
        if not result:
            return "ERROR", {"error": "resultado vazio"}
        if result.get("skipped"):
            return "SKIP", {"skipped": True}
        if result.get("error"):
            return "ERROR", {"error": result.get("error")}

        if check_name == "anti_root":
            is_rooted = bool(result.get("is_rooted"))
            positive = list(result.get("positive_vectors") or [])
            evaluated = list(result.get("evaluated_vectors") or [])
            app_root = result.get("app_root_detection") or {}
            static_analysis = result.get("static_analysis") or {}
            summary = {
                "is_rooted": is_rooted,
                "confidence": result.get("confidence"),
                "positive_vectors": positive,
                "evaluated_vectors": len(evaluated),
                "app_root_detection": {
                    "present": bool(app_root.get("present")),
                    "confidence": app_root.get("confidence"),
                    "engine": static_analysis.get("engine"),
                    "dynamic_detected": app_root.get("dynamic_detected"),
                },
                "protection_detected": result.get("protection_detected"),
                "bypass_successful": result.get("bypass_successful"),
                "bypass_method": result.get("bypass_method"),
                "coverage_gaps": (
                    (static_analysis.get("coverage") or {})
                    .get("possible_gaps", [])
                ),
            }
            if result.get("verdict_reason"):
                summary["verdict_reason"] = result.get("verdict_reason")
            if result.get("bypass_skipped_reason"):
                summary["skip_reason"] = result.get("bypass_skipped_reason")
            hint = str(result.get("status_hint") or "").upper()
            if hint in ("OK", "FALHOU", "SKIP", "N/A"):
                return hint, summary
            return ("FALHOU" if is_rooted else "OK"), summary

        if check_name == "anti_tampering":
            detected = result.get("tamper_detected")
            bypass = result.get("bypass_successful")
            static_analysis = result.get("static_analysis") or {}
            summary = {
                "tamper_detected": detected,
                "static_detected": bool(result.get("static_detected")),
                "bypass_successful": bypass,
                "probe_method": result.get("bypass_method"),
                "static_engine": static_analysis.get("engine"),
                "static_owners": static_analysis.get("owners") or {},
                "app_evidence": bool(static_analysis.get("app_evidence")),
                "coverage_gaps": (
                    (static_analysis.get("coverage") or {})
                    .get("possible_gaps", [])
                ),
            }
            if result.get("verdict_reason"):
                summary["verdict_reason"] = result.get("verdict_reason")
            if result.get("bypass_skipped_reason"):
                summary["skip_reason"] = result.get("bypass_skipped_reason")
            hint = str(result.get("status_hint") or "").upper()
            if hint in ("OK", "FALHOU", "SKIP", "N/A", "ERROR"):
                return hint, summary
            if bypass is True:
                return "FALHOU", summary
            if bypass is False or detected is True:
                return "OK", summary
            if detected is False:
                return "FALHOU", summary
            return "SKIP", summary

        if check_name == "anti_frida":
            raw_vulnerable = result.get("vulnerable")
            app_detection = result.get("app_detection") or {}
            static_analysis = result.get("static_analysis") or {}
            # O conjunto de chaves do resumo é o mesmo em todos os status:
            # um consumidor não pode falhar com KeyError justamente nos
            # casos inconclusivos.
            summary = {
                "vulnerable": None if raw_vulnerable is None else bool(raw_vulnerable),
                # A presença do Frida é injetada pela própria ferramenta;
                # o nome deixa isso explícito para não ser lido como
                # descoberta sobre o ambiente.
                "frida_injected_by_tool": bool(result.get("frida_present")),
                "observation_status": app_detection.get("observation_status"),
                "detection_signals": list(
                    app_detection.get("detection_methods_found") or []
                )[:6],
                "protection_detected": bool(result.get("protection_detected")),
                "static_present": bool(static_analysis.get("present")),
                "static_engine": static_analysis.get("engine"),
                "static_owners": static_analysis.get("owners") or {},
                "app_evidence": bool(static_analysis.get("app_evidence")),
                "protection_sources": list(result.get("protection_sources") or []),
                "coverage_gaps": (
                    (static_analysis.get("coverage") or {}).get("possible_gaps", [])
                ),
                "bypass_successful": result.get("bypass_successful"),
                "bypass_method": result.get("bypass_method"),
            }
            if result.get("bypass_skipped_reason"):
                summary["bypass_skipped_reason"] = result.get("bypass_skipped_reason")
            if result.get("verdict_reason"):
                summary["verdict_reason"] = result.get("verdict_reason")
            bypass = result.get("bypass_successful")
            if bypass is True:
                summary["reason"] = "bypass anti-Frida venceu: o app sobreviveu à evasão"
                return "FALHOU", summary
            if bypass is False:
                summary["reason"] = "a proteção resistiu à evasão anti-Frida"
                return "OK", summary
            # N/A explícito: não havia proteção no APK nem detecção em
            # runtime, então não existe "bypass vencedor" a reportar.
            if str(result.get("status_hint") or "").upper() == "N/A":
                summary["reason"] = result.get("verdict_reason") or "sem proteção"
                return "N/A", summary
            if raw_vulnerable is None:
                # Observação inconclusiva (crash da instrumentação, morte no
                # baseline, script que não carregou) não é OK nem FALHOU.
                summary["error"] = result.get("error") or "observação inconclusiva"
                return "ERROR", summary
            vulnerable = bool(raw_vulnerable)
            return ("FALHOU" if vulnerable else "OK"), summary

        if check_name in ("anti_emulator", "anti_proxy"):
            # Semântica igual à do anti_hooking: o que interessa é a
            # proteção do APP, e não o tipo de máquina da auditoria.
            # O contexto do dispositivo vai no resumo como informação.
            protected = bool(result.get("protection_detected"))
            bypass = result.get("bypass_successful")
            summary = {
                "protection_detected": protected,
                "bypass_successful": bypass,
                "protection_sources": Reporter._protection_sources(result),
                "static_engine": (result.get("static_analysis") or {}).get("engine"),
                "static_owners": (result.get("static_analysis") or {}).get("owners") or {},
                "app_evidence": bool((result.get("static_analysis") or {}).get("app_evidence")),
                "coverage_gaps": (
                    ((result.get("static_analysis") or {}).get("coverage") or {})
                    .get("possible_gaps", [])
                ),
            }
            if check_name == "anti_emulator":
                summary["device_is_emulator"] = bool(
                    result.get("device_is_emulator")
                )
            else:
                summary["proxy_detected"] = bool(
                    result.get("proxy_detected")
                )
                summary["vpn_detected"] = bool(result.get("vpn_detected"))
                summary["reaction_observed"] = bool(
                    result.get("reaction_observed")
                )
                summary["query_only"] = bool(result.get("query_only"))
                if result.get("bypass_tls_neutralized"):
                    summary["tls_neutralized"] = int(
                        result.get("bypass_tls_neutralized")
                    )
                if result.get("bypass_events_suppressed"):
                    summary["events_suppressed"] = int(
                        result.get("bypass_events_suppressed")
                    )
                summary["channels"] = (result.get("app_detection") or {}).get(
                    "channels"
                ) or {}
            if result.get("probe_method"):
                summary["probe_method"] = result.get("probe_method")
            if result.get("bypass_method"):
                summary["bypass_method"] = result.get("bypass_method")
            blocked = bool((result.get("bypass_details") or {}).get("blocked"))
            if blocked:
                summary["blocked_reason"] = (
                    "o app bloqueou a auditoria durante o bypass"
                )
            if not protected:
                status = "FALHOU"  # app sem proteção
            elif bypass is True:
                status = "FALHOU"  # proteção existe, mas o bypass venceu
            elif bypass is False:
                status = "OK"  # proteção resistiu ao bypass
            else:
                status = "SKIP"
                summary["skip_reason"] = (
                    result.get("bypass_skipped_reason")
                    or "bypass não avaliado"
                )
            return status, summary

        if check_name == "anti_hooking":
            # Sem proteção anti-hook o RASP falha (mesma lógica do
            # anti_frida: app que não detecta a ameaça = FALHOU).
            protected = bool(result.get("protection_detected"))
            bypass = result.get("bypass_successful")
            summary = {
                "protection_detected": protected,
                "bypass_successful": bypass,
                "hook_frameworks_present": bool(result.get("hook_frameworks_present")),
                "protection_sources": Reporter._protection_sources(result),
                "static_engine": (result.get("static_analysis") or {}).get("engine"),
                "static_owners": (result.get("static_analysis") or {}).get("owners") or {},
                "app_evidence": bool((result.get("static_analysis") or {}).get("app_evidence")),
                "coverage_gaps": (
                    ((result.get("static_analysis") or {}).get("coverage") or {})
                    .get("possible_gaps", [])
                ),
            }
            if result.get("bypass_method"):
                summary["bypass_method"] = result.get("bypass_method")
            if result.get("verdict_reason"):
                summary["verdict_reason"] = result.get("verdict_reason")
            evidence_strength = (result.get("bypass_details") or {}).get(
                "evidence_strength"
            )
            if evidence_strength:
                summary["evidence_strength"] = evidence_strength
            hook_probes = (result.get("bypass_details") or {}).get("hook_probes")
            if hook_probes:
                summary["hook_probes"] = list(hook_probes)[:8]
            blocked = bool((result.get("bypass_details") or {}).get("blocked"))
            if blocked:
                # O app bloqueou a auditoria: a proteção resistiu ao
                # bypass. O motivo entra no resumo para que o "OK" não
                # pareça uma ausência de proteção.
                summary["blocked_reason"] = (
                    "o app bloqueou a auditoria durante o bypass"
                )
            if not protected:
                status = "FALHOU"
            elif bypass is True:
                status = "FALHOU"  # proteção existe, mas o bypass venceu
            elif bypass is False:
                status = "OK"  # proteção resistiu ao bypass
            elif protected:
                # A proteção existe mas o bypass não foi avaliado: isso
                # não é "não aplicável", é uma etapa que não rodou.
                status = "SKIP"
                summary["skip_reason"] = (
                    result.get("bypass_skipped_reason")
                    or "bypass não avaliado"
                )
            else:
                status = "N/A"
            return status, summary

        if check_name == "ssl_pinning":
            bypass = result.get("bypass_successful")
            pinned = bool(result.get("pinning_detected"))
            bypass_details = result.get("bypass_details") or {}
            summary = {
                "pinning_detected": pinned,
                "pinning_suspected": bool(result.get("pinning_suspected")),
                "pinning_type": result.get("pinning_type"),
                "bypass_successful": bypass,
                "tls_observed": bool(result.get("tls_observed")),
                "intercepted_hosts": list(
                    bypass_details.get("intercepted_hosts") or []
                )[:8],
                "evidence_strength": bypass_details.get("evidence_strength"),
                "static_engine": (result.get("static_analysis") or {}).get("engine"),
                "static_owners": (result.get("static_analysis") or {}).get("owners") or {},
                "app_evidence": bool((result.get("static_analysis") or {}).get("app_evidence")),
                "coverage_gaps": (
                    ((result.get("static_analysis") or {}).get("coverage") or {})
                    .get("possible_gaps", [])
                ),
            }
            blocked = bool((result.get("bypass_details") or {}).get("blocked"))
            if blocked:
                summary["blocked_reason"] = (
                    "o app bloqueou a auditoria durante o bypass"
                )
            if str(result.get("status_hint") or "").upper() == "SKIP":
                summary["skip_reason"] = (
                    result.get("bypass_skipped_reason")
                    or "evidência estática fraca; resultado inconclusivo"
                )
                return "SKIP", summary
            if bypass is True:
                status = "FALHOU"
            elif bypass is None and pinned:
                # Havia pinning e o bypass não rodou: etapa não executada,
                # não ausência de aplicabilidade.
                status = "SKIP"
                summary["skip_reason"] = (
                    result.get("bypass_skipped_reason")
                    or "bypass não avaliado"
                )
            elif bypass is None:
                status = "N/A"  # sem pinning — bypass não aplicável
            else:
                status = "OK"
            return status, summary

        # Check desconhecido não pode ser reportado como sucesso.
        return "ERROR", {"error": f"check desconhecido: {check_name}"}

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------
    def generate_json(self) -> dict:
        """Monta o documento JSON do relatório.

        Returns:
            Dict com ``metadata`` (tool, versão, timestamp, device,
            package), ``summary`` (status por check) e ``details``
            (resultado completo por check).
        """
        summary: Dict[str, Any] = {}
        for check_name, result in self._results.items():
            status, resumo = self._status_for(check_name, result)
            resumo["status"] = status
            detection, bypass = self._dual_verdicts(check_name, result, status)
            summary[check_name] = {
                "status": status,
                "detection": detection,
                "bypass": bypass,
                **{key: value for key, value in resumo.items() if key != "status"},
            }

        # Ordem estável: os checks dinâmicos podem ser executados fora
        # da ordem canônica (o anti-emulador faz spawns próprios), mas o
        # relatório é lido como uma sequência de verificações.
        if len(summary) > 1:
            ordered = {
                name: summary[name]
                for name in REPORT_ORDER
                if name in summary
            }
            for name, value in summary.items():
                if name not in ordered:
                    ordered[name] = value
            summary = ordered

        metadata: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "timestamp": self.timestamp.isoformat(),
            "device": self.device_info,
            "package": self.package_name,
        }
        session_id = (self.run_context or {}).get("session_id")
        if session_id:
            metadata["session_id"] = session_id
        if self.run_context:
            metadata["run"] = self.run_context

        # Trilha de execução: o que foi tentado, o que foi encontrado e o
        # que foi reportado. A ordem acompanha o resumo, para que a
        # leitura do JSON e do HTML seja a mesma do terminal.
        execution_log: list = []
        for check_name, resumo in summary.items():
            status = resumo.get("status", "ERROR")
            for step in build_execution_log(
                check_name, self._results.get(check_name) or {}, status
            ):
                execution_log.append({"check": check_name, **step})

        return {
            "metadata": metadata,
            "summary": summary,
            "execution_log": execution_log,
            "details": self._results,
            **(
                {"static_profile": self.static_profile}
                if self.static_profile is not None
                else {}
            ),
        }

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def generate_html(self) -> str:
        """Renderiza o relatório HTML a partir do Jinja2.

        Returns:
            String HTML completa (header com logo textual 'RASPilot',
            badges de status coloridos e tabelas de evidências).

        Raises:
            RuntimeError: se o template não puder ser renderizado.
        """
        env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "j2"]),
        )
        try:
            template = env.get_template("report.html.j2")
        except Exception as exc:
            raise RuntimeError(f"Template report.html.j2 indisponível: {exc}") from exc

        doc = self.generate_json()
        execution_by_check: Dict[str, list] = {}
        for step in doc.get("execution_log", []):
            execution_by_check.setdefault(step["check"], []).append(step)
        return template.render(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            metadata=doc["metadata"],
            summary=doc["summary"],
            details=doc["details"],
            execution_log=doc["execution_log"],
            execution_by_check=execution_by_check,
            generated_at=self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            json_blob=json.dumps(doc, ensure_ascii=False, indent=2),
        )

    # ------------------------------------------------------------------
    # Persistência
    # ------------------------------------------------------------------
    @staticmethod
    def _slug(value: str) -> str:
        """Converte uma string em slug seguro para nome de arquivo.

        Args:
            value: String de entrada (ex: package name).

        Returns:
            Slug com apenas [a-z0-9._-].
        """
        return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "app"

    def _base_name(self) -> str:
        """Nome-base do relatório, único mesmo em execuções no mesmo segundo.

        Returns:
            ``<slug>_<YYYYmmdd_HHMMSS_ffffff>``.
        """
        stamp = self.timestamp.strftime("%Y%m%d_%H%M%S_%f")
        return f"{self._slug(self.package_name)}_{stamp}"

    def save(self, write_html: bool = True) -> Tuple[str, str]:
        """Salva os relatórios JSON e HTML no diretório de saída.

        Args:
            write_html: Se False, grava apenas o JSON (útil para
                automação/MCP e para execuções por etapas).

        Returns:
            Tupla ``(caminho_json, caminho_html)`` com paths absolutos.
            ``caminho_html`` é vazio quando ``write_html=False``.

        Raises:
            OSError: em falha de escrita.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        base = self._base_name()

        json_path = os.path.abspath(os.path.join(self.output_dir, base + ".json"))
        html_path = os.path.abspath(os.path.join(self.output_dir, base + ".html"))

        doc = self.generate_json()
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
            fh.write("\n")

        if write_html:
            html = self.generate_html()
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(html)
        else:
            html_path = ""

        logger.info("Relatórios salvos: %s | %s", json_path, html_path or "(sem HTML)")
        return json_path, html_path
