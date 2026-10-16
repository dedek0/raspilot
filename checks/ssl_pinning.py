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
from script_loader import load_script_file, safe_unload

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.ssl_pinning")
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

# Filtro de /proc (maps, TracerPid, /proc/net/tcp, comm de threads) —
# esconde os artefatos do Frida durante o bypass.
PROC_FILTER_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "proc_filter.js"
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

    def __init__(self, dm: "DeviceManager") -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
        """
        self.dm = dm

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
        proc_script = None
        kill_script = None
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

        try:
            # Spawn suspenso: instala os hooks ANTES do app rodar, para
            # não perder validações de certificado da inicialização.
            session = self.dm.spawn_app(package_name, resume=False)
            script = load_script_file(
                session, SSL_BYPASS_SCRIPT, on_message=on_message
            )
            try:
                proc_script = load_script_file(
                    session, PROC_FILTER_SCRIPT, on_message=on_message
                )
                kill_script = load_script_file(
                    session, KILL_TRACE_SCRIPT, on_message=on_message
                )
            except Exception:
                logger.warning("scripts auxiliares indisponíveis", exc_info=True)
            self.dm.resume_app()
            pid = self.dm.last_spawn_pid
            for elapsed in range(max(1, int(window))):
                time.sleep(1)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante o bypass SSL (~%ss)",
                        pid, died_after,
                    )
                    break
        except Exception as exc:
            logger.warning("Bypass SSL falhou", exc_info=True)
            return {
                "success": False,
                "intercepted_hosts": intercepted_hosts,
                "bypass_logs": bypass_logs,
                "effective_logs": [],
                "app_alive_at_end": True,
                "death_cause": None,
                "error": str(exc),
            }
        finally:
            safe_unload(script)
            safe_unload(proc_script)
            safe_unload(kill_script)
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    logger.debug("Falha ao detach da sessão", exc_info=True)

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
        # Evidência real: hosts interceptados OU logs de bypass efetivo.
        effective = [
            log for log in bypass_logs
            if any(marker in log for marker in EVIDENCE_MARKERS)
        ]
        success = bool(intercepted_hosts) or bool(effective)

        result = {
            "success": success,
            "intercepted_hosts": intercepted_hosts,
            "bypass_logs": bypass_logs,
            "effective_logs": effective,
            "app_alive_at_end": alive,
            "death_cause": death_cause,
            "error": None,
        }
        logger.info(
            "SSL bypass: success=%s hosts=%s", success, intercepted_hosts
        )
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self, package_name: str, apk_path: Optional[str] = None, window: int = 12
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

        bypass = self.attempt_bypass(package_name, window=window)
        return {
            "pinning_detected": True,
            "pinning_type": detection.get("type", "none"),
            "bypass_successful": bool(bypass.get("success")),
            "evidence": detection.get("evidence", []),
            "bypass_details": bypass,
            "detection": detection,
            "timestamp": _now_iso(),
        }
