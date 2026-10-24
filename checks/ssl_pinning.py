"""RASPilot — Verificação e bypass de SSL Pinning.

Detecta se o app alvo implementa SSL pinning (análise estática do APK)
e tenta contorná-lo em runtime injetando ``scripts/ssl_bypass.js``
via Frida, coletando evidências reais de interceptação.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from rich.console import Console

from checks.apk_utils import pull_apk, scan_apk
from checks.stealth import PROC_FILTER_SCRIPT, load_stealth, unload_stealth
from logcat_analyzer import (
    analyze_since,
    classify_failure,
    format_evidence,
    get_logcat_mark,
)
from script_loader import load_script_file, safe_detach, safe_unload

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.ssl_pinning")

# Intervalo entre as consultas feitas durante a janela de observacao.
# Exposto como constante para que os testes nao dependam de esperar
# tempo real.
OBSERVATION_POLL_INTERVAL = 1.0

console = Console()

# Caminho do script de bypass relativo à raiz do projeto.
SSL_BYPASS_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "ssl_bypass.js"
)

# Script de rastreio de morte do processo (quem chama exit/kill e com
# que pilha) — observado junto com o bypass.
KILL_TRACE_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "kill_trace.js"
)

# Assinaturas estáticas: (tipo, [(needle_bytes, descrição), ...]).
# Ordem define a prioridade na classificação do tipo.
STATIC_SIGNATURES: List[Tuple[str, List[Tuple[bytes, str]]]] = [
    ("flutter", [
        (b"libflutter.so", "biblioteca libflutter.so empacotada"),
        (b"flutter_assets", "diretório flutter_assets"),
        (b"FlutterError", "símbolo Flutter no dex"),
    ]),
    ("okhttp", [
        (b"okhttp3/CertificatePinner", "classe okhttp3.CertificatePinner"),
        (b"CertificatePinner", "string CertificatePinner"),
        (b"okhttp3.internal.tls", "okhttp3 internal tls"),
    ]),
    ("trustkit", [
        (b"com.datatheorem.android.trustkit", "TrustKit package"),
        (b"TrustKit", "string TrustKit"),
        (b"PinningTrustManager", "PinningTrustManager do TrustKit"),
    ]),
    ("network_security_config", [
        (b"networkSecurityConfig", "atributo networkSecurityConfig no Manifest"),
        (b"network_security_config", "resource network_security_config"),
        (b"NetworkSecurityTrustManager", "NetworkSecurityTrustManager"),
        (b"RootTrustManager", "RootTrustManager do Android NSC"),
    ]),
    ("native", [
        (b"libconscrypt_jni.so", "lib conscrypt nativa"),
        (b"org.conscrypt", "provider Conscrypt"),
        (b"SSL_CTX_set_custom_verify", "BoringSSL custom_verify"),
        (b"boringssl", "string boringssl"),
        (b"PublicKeyPinner", "pinner nativo genérico"),
    ]),
]

# Trechos de log do ssl_bypass.js que comprovam interceptação REAL em
# runtime (diferente de mero "hook instalado"). O script separa os dois
# formatos: instalação usa "... hookado"/"... indisponível"; evidência
# usa "bypass (host)"/"interceptado"/"-> ..." — só esta lista conta para
# o veredito. "bypass (" inclui o parêntese de propósito: o nome do
# próprio script ("ssl_bypass.js carregado") nunca pode casar.
EVIDENCE_MARKERS = (
    "bypass (",
    "interceptado",
    "-> proceed()",
    "-> X509_V_OK",
    "-> SSL_VERIFY_NONE",
    "-> 0 (ok)",
    "-> true",
    "ignorado",
)


def _now_iso() -> str:
    """Retorna o timestamp atual em ISO8601 (UTC).

    Returns:
        Ex: ``'2026-10-14T18:00:00+00:00'``.
    """
    return datetime.now(timezone.utc).isoformat()


class SSLPinningCheck:
    """Detecta SSL pinning no APK e tenta bypass via Frida."""

    def __init__(
        self, dm: "DeviceManager", mode: str = "bypass", no_java: bool = False
    ) -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
            mode: ``detect``, ``bypass`` ou ``stealth``.
            no_java: Se True, não tenta carregar hooks Java.
        """
        self.dm = dm
        self.mode = mode
        self.no_java = no_java

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _script_replacements(self, java_only: bool = False) -> Dict[str, str]:
        """Placeholders de configuração injetados nos scripts Frida."""
        value = getattr(self.dm, "frida_port", None)
        port = int(value) if isinstance(value, int) else 27999
        return {
            "__RASPILOT_FRIDA_PORT__": str(port),
            "__RASPILOT_FRIDA_PORT_HEX__": f"{port:04X}",
            "__RASPILOT_JAVA_ONLY__": "true" if java_only else "false",
            "__RASPILOT_PACKAGE_NAME__": getattr(self.dm, "last_spawn_package", None) or "",
        }

    # ------------------------------------------------------------------
    # Detecção estática
    # ------------------------------------------------------------------
    def _pull_apk(self, package_name: str, dest_dir: str) -> List[str]:
        """Baixa o(s) APK(s) do app para o host.

        Delega a :func:`checks.apk_utils.pull_apk` (compartilhado com o
        Anti-Hooking) — mantido como método para permitir mock nos testes.

        Args:
            package_name: Package name do app alvo.
            dest_dir: Diretório local de destino.

        Returns:
            Lista de caminhos locais dos APKs baixados (vazia se falhar).
        """
        return pull_apk(self.dm, package_name, dest_dir)

    def _scan_apk(self, apk_path: str) -> Dict[str, List[str]]:
        """Inspeciona o APK por assinaturas de SSL pinning.

        Delega a :func:`checks.apk_utils.scan_apk` com
        :data:`STATIC_SIGNATURES`.

        Args:
            apk_path: Caminho local do APK.

        Returns:
            Dict ``{tipo: [evidências]}`` apenas com tipos encontrados.

        Raises:
            zipfile.BadZipFile: se o arquivo não for um APK válido.
        """
        return scan_apk(apk_path, STATIC_SIGNATURES)

    def detect_pinning(
        self, package_name: str, apk_path: Optional[str] = None
    ) -> dict:
        """Detecta SSL pinning analisando o APK do app.

        Args:
            package_name: Package name do app alvo.
            apk_path: Caminho opcional de um APK local (pula o ``adb pull``).

        Returns:
            Dict com ``pinning_detected`` (bool), ``type``
            ('okhttp'|'trustkit'|'network_security_config'|'flutter'|
            'native'|'none'), ``evidence`` (lista legível) e, em erro,
            ``error``. Quando há vários tipos, o principal segue a
            prioridade okhttp > trustkit > flutter > nsc > native.
        """
        with tempfile.TemporaryDirectory(prefix="raspilot_apk_") as tmp:
            if apk_path:
                apks = [apk_path]
            else:
                apks = self._pull_apk(package_name, tmp)
                if not apks:
                    return {
                        "pinning_detected": False,
                        "type": "none",
                        "evidence": [],
                        "error": f"Não foi possível obter o APK de {package_name}",
                    }

            all_found: Dict[str, List[str]] = {}
            for apk in apks:
                try:
                    found = self._scan_apk(apk)
                except zipfile.BadZipFile as exc:
                    logger.warning("APK inválido: %s", exc)
                    continue
                for sig_type, evidences in found.items():
                    all_found.setdefault(sig_type, []).extend(evidences)

        if not all_found:
            return {
                "pinning_detected": False,
                "type": "none",
                "evidence": [],
                "details": "Nenhuma assinatura de SSL pinning encontrada no APK",
            }

        # Prioridade: flutter > okhttp > trustkit > nsc > native.
        priority = ["okhttp", "trustkit", "flutter", "network_security_config", "native"]
        chosen = sorted(all_found.keys(), key=lambda t: priority.index(t) if t in priority else 99)[0]
        evidence = [f"[{t}] {e}" for t, items in all_found.items() for e in items]

        result = {
            "pinning_detected": True,
            "type": chosen,
            "evidence": evidence,
            "all_types": sorted(all_found.keys()),
            "details": f"SSL pinning detectado (tipo principal: {chosen})",
        }
        logger.info("SSL pinning detectado: type=%s evidências=%s", chosen, evidence)
        return result

    # ------------------------------------------------------------------
    # Bypass dinâmico
    # ------------------------------------------------------------------
    def attempt_bypass(self, package_name: str, window: int = 12) -> dict:
        """Tenta contornar o SSL pinning injetando o ssl_bypass.js.

        Espawna o app com Frida, carrega o script universal de bypass e
        coleta logs/console pela janela informada. Sucesso exige evidência
        real de interceptação (não apenas "hook instalado").

        Args:
            package_name: Package name do app alvo.
            window: Janela de observação em segundos.

        Returns:
            Dict com ``success`` (bool), ``intercepted_hosts`` (lista),
            ``bypass_logs`` (lista), ``app_alive_at_end`` (bool) e
            ``error`` (str|None).
        """
        bypass_logs: List[str] = []
        intercepted_hosts: List[str] = []
        session = None
        script = None
        java_script = None
        proc_script = None
        kill_script = None
        java_load_error: Optional[str] = None
        stealth_loaded: List[tuple] = []
        died_after: Optional[int] = None

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("type") == "ssl-bypass-host":
                    host = payload.get("host", "")
                    if host and host not in intercepted_hosts:
                        intercepted_hosts.append(host)
                    return
                if payload.get("type") == "app-kill":
                    # Quem matou o processo (kill_trace.js) — diagnóstico.
                    msg = "app-kill: " + payload.get("message", "")
                    if msg and msg not in bypass_logs:
                        bypass_logs.append(msg)
                    return
                msg = payload.get("message", "")
                if msg and msg not in bypass_logs:
                    bypass_logs.append(msg)
            elif message.get("type") == "error":
                desc = message.get("description", "")
                if desc:
                    bypass_logs.append(f"[script-error] {desc}")

        logcat_mark = get_logcat_mark(self.dm)
        try:
            # Spawn suspenso: instala os hooks ANTES do app rodar, para
            # não perder validações de certificado da inicialização.
            session = self.dm.spawn_app(package_name, resume=False)
            if self.mode == "stealth":
                stealth_loaded = load_stealth(
                    session,
                    on_message=on_message,
                    replacements=self._script_replacements(),
                    include_proc_filter=True,
                )
            # Fase 1 (antes do resume): hooks nativos SSL + filtro /proc,
            # sem bridge Java.
            script = load_script_file(
                session, SSL_BYPASS_SCRIPT, on_message=on_message,
                replacements=self._script_replacements(java_only=False),
                with_java_bridge=False,
                load_timeout=5.0,
            )
            proc_loaded = any(
                path == PROC_FILTER_SCRIPT for path, _ in stealth_loaded
            )
            if not proc_loaded:
                try:
                    proc_script = load_script_file(
                        session, PROC_FILTER_SCRIPT, on_message=on_message,
                        replacements=self._script_replacements(java_only=False),
                        with_java_bridge=False,
                        load_timeout=3.0,
                    )
                except Exception:
                    logger.warning("proc_filter.js indisponível", exc_info=True)
            self.dm.resume_app()
            pid = self.dm.last_spawn_pid
            # Fase 2 (após o resume): hooks Java de SSL.
            if self.no_java:
                java_load_error = None
            else:
                try:
                    java_script = load_script_file(
                        session, SSL_BYPASS_SCRIPT, on_message=on_message,
                        replacements=self._script_replacements(java_only=True),
                        with_java_bridge=True,
                        load_timeout=5.0,
                    )
                except Exception as exc:
                    java_load_error = str(exc)
                    logger.warning("Hooks Java SSL não carregaram: %s", exc)
                    safe_detach(session)
            if java_load_error is None:
                # Diagnóstico de kill carregado por último.
                try:
                    kill_script = load_script_file(
                        session, KILL_TRACE_SCRIPT, on_message=on_message,
                        load_timeout=3.0,
                    )
                except Exception:
                    logger.debug("kill_trace.js indisponível no bypass SSL", exc_info=True)
            for elapsed in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante o bypass SSL (~%ss)",
                        pid, died_after,
                    )
                    break
        except Exception as exc:
            logger.warning("Bypass SSL falhou", exc_info=True)
            pid = locals().get("pid") or self.dm.last_spawn_pid
            logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
            failure = classify_failure(logcat, getattr(self.dm, "baseline", None))
            app_alive: Optional[bool] = None
            death_cause = None
            if pid is not None:
                try:
                    app_alive = self.dm.is_app_alive(pid)
                except Exception:
                    app_alive = None
            if app_alive is False:
                try:
                    death_cause = self.dm.capture_death_cause(
                        pid=pid, package=package_name
                    )
                except Exception:
                    logger.debug("Falha ao capturar morte no bypass SSL", exc_info=True)

            if app_alive is False:
                bypass_logs.append("app_terminated: processo morreu durante o bypass")
                if death_cause:
                    bypass_logs.append(
                        "death_cause: " + str(death_cause.get("summary", "?"))
                    )

            # Reação do RASP durante o carregamento: o pinning resistiu
            # (inclusive quando o agente foi derrubado e o app sobreviveu).
            if failure.get("is_rasp"):
                return {
                    "success": False,
                    "intercepted_hosts": intercepted_hosts,
                    "bypass_logs": bypass_logs,
                    "effective_logs": [],
                    "app_alive_at_end": False,
                    "death_cause": death_cause,
                    "logcat": logcat,
                    "logcat_evidence": format_evidence(logcat),
                    "error": None,
                }

            kind = str(failure.get("kind", "unknown"))
            if kind == "start_timeout":
                error = (
                    "app morto por ActivityManager start timeout durante o bypass "
                    "(instrumentação); reduza o trabalho antes do resume"
                )
            elif kind == "baseline_death":
                error = "app encerrou no baseline sem instrumentação; bypass inconclusivo"
            elif kind == "instrumentation_crash":
                error = (
                    "app encerrou por crash/ANR sem evidência de segurança no logcat "
                    "(possível crash da instrumentação)"
                )
            else:
                error = str(exc)
            return {
                "success": False,
                "intercepted_hosts": intercepted_hosts,
                "bypass_logs": bypass_logs,
                "effective_logs": [],
                "app_alive_at_end": app_alive if app_alive is not None else True,
                "death_cause": death_cause,
                "logcat": logcat,
                "logcat_evidence": format_evidence(logcat),
                "error": error,
            }
        finally:
            safe_unload(script)
            safe_unload(java_script)
            safe_unload(proc_script)
            safe_unload(kill_script)
            unload_stealth(stealth_loaded)
            if session is not None:
                safe_detach(session)

        if died_after is not None:
            bypass_logs.append(
                f"app_terminated: processo encerrou ~{died_after}s após resume"
            )
            try:
                death_cause = self.dm.capture_death_cause(
                    pid=pid, package=package_name
                )
                bypass_logs.append(
                    "death_cause: " + str(death_cause.get("summary", "?"))
                )
            except Exception:
                logger.debug("Falha ao capturar causa da morte", exc_info=True)
                death_cause = None
        else:
            death_cause = None

        alive = died_after is None
        # Logs de bypass efetivo são úteis como diagnóstico, mas NÃO
        # provam interceptação: hooks nativos de configuração podem ser
        # instalados sem que nenhuma conexão pinada seja contornada.
        effective = [
            log for log in bypass_logs
            if any(marker in log for marker in EVIDENCE_MARKERS)
        ]
        logcat = analyze_since(
            self.dm, logcat_mark, package_name, locals().get("pid")
        )
        # Veredito estrito: exige host real interceptado e app vivo.
        success = bool(intercepted_hosts) and alive
        if intercepted_hosts:
            evidence_strength = "host"
        elif effective:
            evidence_strength = "config_only"
        else:
            evidence_strength = "none"

        # O app bloqueou a auditoria: encerrou com a instrumentação e a
        # causa é atribuível ao RASP. Isso é uma conclusão sobre a
        # proteção (ela resistiu), não uma etapa que não rodou.
        failure = classify_failure(
            logcat, getattr(self.dm, "baseline", None)
        )
        blocked = bool(not alive and failure.get("is_rasp"))
        death_kind = str(failure.get("kind", "unknown"))
        error: Optional[str] = None
        if alive and java_load_error and not intercepted_hosts:
            # OkHttp/TrustManager são Java; sem esses hooks o bypass não
            # pode ser confirmado, mesmo com hooks nativos ativos.
            success = False
            error = f"hooks Java de SSL não carregaram: {java_load_error}"
        elif not alive:
            # O app encerrou durante o bypass. Só é "bloqueou a
            # auditoria" quando a morte é atribuível ao RASP; caso
            # contrário o bypass fica inconclusivo.
            success = False
            if blocked:
                error = (
                    "o app bloqueou o bypass de SSL: encerrou durante a "
                    "execução do bypass (reação do RASP)"
                )
            elif death_kind == "instrumentation_crash":
                error = (
                    "o app encerrou o agente de instrumentação durante o "
                    "bypass de SSL; resultado inconclusivo"
                )
            else:
                error = (
                    "app encerrou durante o bypass de SSL sem reação RASP "
                    f"atribuível ({death_kind}); resultado inconclusivo"
                )

        result = {
            "success": success,
            "blocked": blocked,
            "intercepted_hosts": intercepted_hosts,
            "bypass_logs": bypass_logs,
            "effective_logs": effective,
            "evidence_strength": evidence_strength,
            "app_alive_at_end": alive,
            "death_cause": death_cause,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "java_load_error": java_load_error,
            "java_skipped": bool(self.no_java),
            "stealth_used": bool(stealth_loaded),
            "error": error,
        }
        logger.info(
            "SSL bypass: success=%s hosts=%s strength=%s",
            success, intercepted_hosts, evidence_strength,
        )
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self,
        package_name: str,
        apk_path: Optional[str] = None,
        window: int = 12,
        precomputed_bypass: Optional[dict] = None,
    ) -> dict:
        """Combina detecção estática e tentativa de bypass.

        Se ``pinning_detected=False``, ``bypass_successful`` é ``None``
        (não aplicável).

        Args:
            package_name: Package name do app alvo.
            apk_path: Caminho opcional de APK local para análise.
            window: Janela de observação do bypass em segundos.

        Returns:
            Dict com ``pinning_detected``, ``pinning_type``,
            ``bypass_successful`` (bool|None), ``evidence`` (lista) e
            ``bypass_details`` (dict|None) e ``timestamp``.
        """
        detection = self.detect_pinning(package_name, apk_path=apk_path)

        # Falha ao obter/analisar o APK é inconclusiva, não "sem pinning".
        if detection.get("error"):
            return {
                "pinning_detected": False,
                "pinning_type": "none",
                "bypass_successful": None,
                "evidence": [],
                "bypass_details": None,
                "detection": detection,
                "error": str(detection["error"]),
                "timestamp": _now_iso(),
            }

        if not detection.get("pinning_detected"):
            return {
                "pinning_detected": False,
                "pinning_type": "none",
                "bypass_successful": None,
                "evidence": [],
                "bypass_details": None,
                "detection": detection,
                "timestamp": _now_iso(),
            }

        bypass_skipped_reason = None
        if self.mode == "detect":
            bypass_skipped_reason = "modo detect: bypass não executado"
        elif self.no_java:
            bypass_skipped_reason = "--no-java: hooks Java necessários ao bypass"

        if bypass_skipped_reason is not None:
            return {
                "pinning_detected": True,
                "pinning_type": detection.get("type", "none"),
                "bypass_successful": None,
                "evidence": detection.get("evidence", []),
                "bypass_details": None,
                "bypass_skipped_reason": bypass_skipped_reason,
                "detection": detection,
                "timestamp": _now_iso(),
            }

        bypass = (
            precomputed_bypass
            if precomputed_bypass is not None
            else self.attempt_bypass(package_name, window=window)
        )
        bypass_error = bypass.get("error") if not bypass.get("success") else None
        # A força da evidência separa "o bypass venceu" de "o bypass foi
        # instalado mas nunca exercido". Sem uma requisição TLS
        # observada, o pinning não chegou a ser testado: afirmar que
        # resistiu seria uma conclusão sem base.
        strength = bypass.get("evidence_strength")
        not_exercised = (
            not bypass.get("success")
            and bypass_error is None
            and strength in ("config_only", "none")
        )
        result = {
            "pinning_detected": True,
            "pinning_type": detection.get("type", "none"),
            # Sem bypass avaliado o resultado é desconhecido, e não
            # "resistiu ao bypass": o pinning detectado continua valendo.
            "bypass_successful": (
                None
                if (bypass_error or not_exercised)
                else bool(bypass.get("success"))
            ),
            "evidence": detection.get("evidence", []),
            "bypass_details": bypass,
            "detection": detection,
            "timestamp": _now_iso(),
        }
        if bypass.get("blocked"):
            # O app bloqueou a auditoria: o pinning resistiu. É uma
            # conclusão sobre a proteção, não uma etapa que não rodou.
            result["bypass_successful"] = False
            result["bypass_skipped_reason"] = (
                "o app bloqueou a auditoria: encerrou durante o bypass de SSL"
            )
        elif bypass_error:
            result["bypass_skipped_reason"] = f"bypass: {bypass_error}"
        elif not_exercised:
            result["bypass_skipped_reason"] = (
                "bypass não exercido: nenhuma requisição TLS observada "
                "durante a janela"
            )
        return result
