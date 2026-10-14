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

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.ssl_pinning")
console = Console()

# Caminho do script de bypass relativo à raiz do projeto.
SSL_BYPASS_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "ssl_bypass.js"
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

# Trechos de log do ssl_bypass.js que comprovam interceptação real
# (diferente de mero "hook instalado").
EVIDENCE_MARKERS = (
    "bypass (",
    "interceptado",
    "-> proceed()",
    "-> X509_V_OK",
    "-> NONE/ok",
    "-> SSL_VERIFY_NONE",
    "-> 0 (ok)",
    "-> true",
    "ignorado",
    "neutralizado",
    "SSLContext.init interceptado",
)


def _now_iso() -> str:
    """Retorna o timestamp atual em ISO8601 (UTC).

    Returns:
        Ex: ``'2026-10-14T18:00:00+00:00'``.
    """
    return datetime.now(timezone.utc).isoformat()


def _contains(bytes_list: List[bytes], needle: bytes) -> bool:
    """Procura um needle (ASCII ou UTF-16LE) em uma lista de blobs.

    O AndroidManifest.binário pode armazenar strings em UTF-16LE
    (API < 30) ou UTF-8 — por isso a dupla busca.

    Args:
        bytes_list: Blobs de bytes a inspecionar.
        needle: Padrão ASCII a localizar.

    Returns:
        True se encontrado em qualquer codificação.
    """
    utf16 = needle.decode("ascii", errors="ignore").encode("utf-16le")
    for blob in bytes_list:
        if needle in blob or (utf16 and utf16 in blob):
            return True
    return False


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

        Args:
            package_name: Package name do app alvo.
            dest_dir: Diretório local de destino.

        Returns:
            Lista de caminhos locais dos APKs baixados (vazia se falhar).
        """
        res = self.dm.run_shell(f"pm path {package_name}", timeout=15)
        if not res["ok"] or not res["stdout"]:
            logger.warning("pm path falhou para %s: %s", package_name, res["stderr"])
            return []

        local_paths: List[str] = []
        for line in res["stdout"].splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            remote = line[len("package:"):]
            local = os.path.join(
                dest_dir, os.path.basename(remote) or f"{package_name}.apk"
            )
            try:
                self.dm._run_adb(["pull", remote, local], timeout=120)
                if os.path.isfile(local):
                    local_paths.append(local)
            except Exception:
                logger.warning("Falha ao baixar %s", remote, exc_info=True)
        return local_paths

    def _scan_apk(self, apk_path: str) -> Dict[str, List[str]]:
        """Inspeciona o APK por assinaturas de SSL pinning.

        Procura as assinaturas em ``AndroidManifest.xml`` (binário),
        ``classes*.dex``, ``lib/**/*.so`` e entradas de assets.

        Args:
            apk_path: Caminho local do APK.

        Returns:
            Dict ``{tipo: [evidências]}`` apenas com tipos encontrados.

        Raises:
            zipfile.BadZipFile: se o arquivo não for um APK válido.
        """
        found: Dict[str, List[str]] = {}
        try:
            zf = zipfile.ZipFile(apk_path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise zipfile.BadZipFile(f"{apk_path}: {exc}") from exc

        with zf:
            # Coleta blobs relevantes (limita tamanho para performance).
            blobs: List[bytes] = []
            interesting: List[str] = []
            for info in zf.infolist():
                name = info.filename
                if (
                    name == "AndroidManifest.xml"
                    or name.endswith(".dex")
                    or name.startswith("lib/") and name.endswith(".so")
                    or name.startswith("assets/flutter_assets")
                    or name.startswith("res/xml/")
                ):
                    interesting.append(name)
                    try:
                        blobs.append(zf.read(name)[: 8 * 1024 * 1024])
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        logger.debug("Não foi possível ler %s do APK", name)

            # Nomes das entradas também são evidência (ex: lib/libflutter.so).
            if interesting:
                blobs.append("\n".join(interesting).encode("utf-8", errors="ignore"))

            for sig_type, needles in STATIC_SIGNATURES:
                for needle, description in needles:
                    if _contains(blobs, needle):
                        found.setdefault(sig_type, []).append(description)

        return found

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
    def attempt_bypass(self, package_name: str) -> dict:
        """Tenta contornar o SSL pinning injetando o ssl_bypass.js.

        Espawna o app com Frida, carrega o script universal de bypass e
        coleta logs/console por ~6s. Sucesso exige evidência real de
        interceptação (não apenas "hook instalado").

        Args:
            package_name: Package name do app alvo.

        Returns:
            Dict com ``success`` (bool), ``intercepted_hosts`` (lista),
            ``bypass_logs`` (lista) e ``error`` (str|None).
        """
        bypass_logs: List[str] = []
        intercepted_hosts: List[str] = []
        session = None
        script = None

        try:
            with open(SSL_BYPASS_SCRIPT, "r", encoding="utf-8") as fh:
                source = fh.read()
        except OSError as exc:
            return {
                "success": False,
                "intercepted_hosts": [],
                "bypass_logs": [],
                "error": f"Script ssl_bypass.js ilegível: {exc}",
            }

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("type") == "ssl-bypass-host":
                    host = payload.get("host", "")
                    if host and host not in intercepted_hosts:
                        intercepted_hosts.append(host)
                    return
                msg = payload.get("message", "")
                if msg and msg not in bypass_logs:
                    bypass_logs.append(msg)
            elif message.get("type") == "error":
                desc = message.get("description", "")
                if desc:
                    bypass_logs.append(f"[script-error] {desc}")

        try:
            session = self.dm.spawn_app(package_name)
            script = session.create_script(source)
            script.on("message", on_message)
            script.load()
            # Janela para o app realizar tráfego/validações de certificado.
            time.sleep(6)
        except Exception as exc:
            logger.warning("Bypass SSL falhou", exc_info=True)
            return {
                "success": False,
                "intercepted_hosts": intercepted_hosts,
                "bypass_logs": bypass_logs,
                "error": str(exc),
            }
        finally:
            if script is not None:
                try:
                    script.unload()
                except Exception:
                    logger.debug("Falha ao unload do ssl_bypass", exc_info=True)
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    logger.debug("Falha ao detach da sessão", exc_info=True)

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
            "error": None,
        }
        logger.info(
            "SSL bypass: success=%s hosts=%s", success, intercepted_hosts
        )
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(self, package_name: str, apk_path: Optional[str] = None) -> dict:
        """Combina detecção estática e tentativa de bypass.

        Se ``pinning_detected=False``, ``bypass_successful`` é ``None``
        (não aplicável).

        Args:
            package_name: Package name do app alvo.
            apk_path: Caminho opcional de APK local para análise.

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

        bypass = self.attempt_bypass(package_name)
        return {
            "pinning_detected": True,
            "pinning_type": detection.get("type", "none"),
            "bypass_successful": bool(bypass.get("success")),
            "evidence": detection.get("evidence", []),
            "bypass_details": bypass,
            "detection": detection,
            "timestamp": _now_iso(),
        }
