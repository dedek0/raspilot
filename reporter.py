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

# Versão do schema do documento JSON. Incrementada quando a forma do
# relatório muda de modo incompatível, para que um consumidor possa
# detectar a mudança em vez de interpretar campos ausentes.
SCHEMA_VERSION = 3

logger = logging.getLogger("raspilot.reporter")

# Ordem de apresentação dos checks no relatório. A execução dos checks
# dinâmicos não segue essa ordem (o anti-emulador precisa de spawns
# próprios e roda por último), mas o relatório mantém a ordem estável.
REPORT_ORDER = (
    "anti_root",
    "anti_emulator",
    "anti_frida",
    "anti_hooking",
    "ssl_pinning",
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
    ) -> None:
        """Inicializa o relatório com metadados do dispositivo e alvo.

        Args:
            device_info: Dict retornado por ``DeviceManager.get_device_info()``.
            package_name: Package name do app auditado.
            output_dir: Diretório de saída dos relatórios.
            run_context: Metadados da execução (argumentos da CLI, versão
                do Frida, hashes dos scripts, pid alvo, resultado do
                baseline). Tornam a execução reproduzível por terceiros.
        """
        self.device_info = dict(device_info or {})
        self.package_name = package_name
        self.output_dir = output_dir
        self.timestamp = datetime.now(timezone.utc)
        self.run_context: Dict[str, Any] = dict(run_context or {})
        self._results: Dict[str, dict] = {}

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
            return (
                "FALHOU" if is_rooted else "OK",
                {
                    "is_rooted": is_rooted,
                    "confidence": result.get("confidence"),
                },
            )

        if check_name == "anti_frida":
            raw_vulnerable = result.get("vulnerable")
            # O conjunto de chaves do resumo é o mesmo em todos os status:
            # um consumidor não pode falhar com KeyError justamente nos
            # casos inconclusivos.
            summary = {
                "vulnerable": None if raw_vulnerable is None else bool(raw_vulnerable),
                "frida_present": bool(result.get("frida_present")),
            }
            if raw_vulnerable is None:
                # Observação inconclusiva (crash da instrumentação, morte no
                # baseline, script que não carregou) não é OK nem FALHOU.
                summary["error"] = result.get("error") or "observação inconclusiva"
                return "ERROR", summary
            vulnerable = bool(raw_vulnerable)
            return ("FALHOU" if vulnerable else "OK"), summary

        if check_name == "anti_emulator":
            # Semântica igual à do anti_hooking: o que interessa é a
            # proteção do APP, e não o tipo de máquina da auditoria.
            # O contexto do dispositivo vai no resumo como informação.
            protected = bool(result.get("protection_detected"))
            bypass = result.get("bypass_successful")
            summary = {
                "protection_detected": protected,
                "bypass_successful": bypass,
                "device_is_emulator": bool(result.get("device_is_emulator")),
            }
            blocked = bool((result.get("bypass_details") or {}).get("blocked"))
            if blocked:
                summary["blocked_reason"] = (
                    "o app bloqueou a auditoria durante o bypass"
                )
            if not protected:
                status = "FALHOU"  # app sem proteção anti-emulador
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
            }
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
            summary = {
                "pinning_detected": pinned,
                "pinning_type": result.get("pinning_type"),
                "bypass_successful": bypass,
            }
            blocked = bool((result.get("bypass_details") or {}).get("blocked"))
            if blocked:
                summary["blocked_reason"] = (
                    "o app bloqueou a auditoria durante o bypass"
                )
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
            summary[check_name] = resumo

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
        if self.run_context:
            metadata["run"] = self.run_context

        return {
            "metadata": metadata,
            "summary": summary,
            "details": self._results,
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
        return template.render(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            metadata=doc["metadata"],
            summary=doc["summary"],
            details=doc["details"],
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

    def save(self) -> Tuple[str, str]:
        """Salva os relatórios JSON e HTML no diretório de saída.

        Returns:
            Tupla ``(caminho_json, caminho_html)`` com paths absolutos.

        Raises:
            OSError: em falha de escrita.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        stamp = self.timestamp.strftime("%Y%m%d_%H%M%S")
        base = f"{self._slug(self.package_name)}_{stamp}"

        json_path = os.path.abspath(os.path.join(self.output_dir, base + ".json"))
        html_path = os.path.abspath(os.path.join(self.output_dir, base + ".html"))

        doc = self.generate_json()
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
            fh.write("\n")

        html = self.generate_html()
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info("Relatórios salvos: %s | %s", json_path, html_path)
        return json_path, html_path
