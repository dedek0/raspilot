"""RASPilot — Verificação de confiança em CA comprometida (eMudhra emSign G3).

Audita o vetor do incidente Mozilla bug 2083449: os 8 intermediários
eMudhra emSign ECC G3 tinham chaves privadas com escalar mínimo (``d``
∈ {4, 56, 66, 115, 155, 156, 230, 237}), recuperáveis a partir dos
próprios certificados públicos. Um atacante pode assinar leaf certs
arbitrários que se ancoram em raízes presentes no trust store — sem
instalar CA no dispositivo.

O check executa dois vetores:

1. **Chain** (host-side): para cada host observado/ informado, captura a
   chain TLS apresentada e compara SPKI/serial contra os 8 intermediários
   comprometidos. Se o backend do app usa um deles, o tráfego do app está
   diretamente exposto a MITM (CAs comprometidas foram revogadas —
   ``caCompromise`` — mas clientes sem checagem de revogação aceitam).

2. **Probe de aceitação** (device-side): recupera a chave fraca em
   runtime, emite um leaf efêmero (SAN localhost/127.0.0.1) assinado pelo
   intermediário comprometido, serve via TLS local exposto ao device com
   ``adb reverse`` e injeta ``scripts/emudhra_probe.js`` no processo do
   app para medir se o trust path (CA de plataforma e default do app)
   aceita a cadeia. ``accepted`` = o ambiente aceitaria MITM sem instalar
   CA; ``rejected`` = o trust store já rejeita (CA removida/revogação).

As chaves privadas NUNCA são persistidas: derivadas em memória a partir
do escalar público-conhecido, usadas para o leaf efêmero e descartadas.
Uso restrito a auditoria autorizada de apps/alvos do próprio pipeline.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import logging
import os
import socket
import ssl
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from rich.console import Console

from script_loader import load_script_file, safe_detach, safe_unload

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.revoked_ca")

# Intervalo entre as consultas durante a janela de observação do probe.
OBSERVATION_POLL_INTERVAL = 1.0

console = Console()

# Índice dos intermediários comprometidos (metadados + PEMs vendados em
# scripts/emudhra/). Fonte: bug Mozilla 2083449.
INTERMEDIATES_INDEX = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "emudhra_intermediates.json"
)

# Script do probe de aceitação (injetado no processo do app).
PROBE_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "emudhra_probe.js"
)

# SANs do leaf efêmero servido pelo probe (o device acessa via adb reverse
# em 127.0.0.1 — hostname verification exige esses SANs).
TEST_SAN_DNS = ("localhost",)
TEST_SAN_IPS = ("127.0.0.1",)

# Marcadores que comprovam resultado REAL do probe (mensagem de instalação
# nunca conta).
PROBE_RESULT_MARKERS = ("accepted", "rejected")

# Backoff (segundos) antes de uma nova tentativa de probe após queda de
# conexão Frida — dá tempo do device respirar e do servidor ser
# restaurado. Patchável em testes.
RETRY_BACKOFF = 2.0

# Preferência pela CA de menor assurance para o probe (todas servem igual;
# DV é a escolha "mínima" documentada nos PoCs públicos).
_CA_PREFERENCE = ("EM DV", "EM OV", "EM EV")


def _now_iso() -> str:
    """Timestamp UTC atual em ISO8601 (formato dos demais checks)."""
    return datetime.now(timezone.utc).isoformat()


def _is_transport_error(exc: BaseException) -> bool:
    """Detecta quedas de conexão Frida (diretas ou embrulhadas).

    O RASP do app pode derrubar o ``frida-server`` entre spawns; nesse
    caso qualquer chamada Frida levanta ``TransportError`` (ou uma exceção
    de envio que a embrulha). Usado para decidir retry e para dar um
    diagnóstico acionável.

    Args:
        exc: Exceção capturada (direta ou de ``spawn_app``).

    Returns:
        True se o erro indica conexão Frida perdida.
    """
    transport_names = ("TransportError", "ServerNotRunningError", "DeviceLostError")
    current: Optional[BaseException] = exc
    for _ in range(4):  # percorre a cadeia __cause__ (ex: FridaSetupError)
        if current is None:
            break
        if type(current).__name__ in transport_names:
            return True
        text = str(current).lower()
        if "connection is closed" in text or "device lost" in text or "server not running" in text:
            return True
        current = current.__cause__
    return False


# ----------------------------------------------------------------------
# Catálogo de intermediários (vendado)
# ----------------------------------------------------------------------

_INTERMEDIATES_CACHE: Optional[List[dict]] = None


def load_intermediates(refresh: bool = False) -> List[dict]:
    """Carrega os 8 intermediários comprometidos do índice vendado.

    Args:
        refresh: Ignora o cache de módulo.

    Returns:
        Lista de dicts com metadados (``cn``, ``spki_sha256``,
        ``serial_hex``, ``recovered_d``...), o objeto ``cert``
        (``x509.Certificate``) e o PEM original.

    Raises:
        ValueError: índice ausente/inválido ou PEM não parseável.
    """
    global _INTERMEDIATES_CACHE
    if _INTERMEDIATES_CACHE is not None and not refresh:
        return _INTERMEDIATES_CACHE

    try:
        from cryptography import x509

        with open(INTERMEDIATES_INDEX, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        entries: List[dict] = []
        for raw in doc.get("intermediates", []):
            pem_path = os.path.join(os.path.dirname(INTERMEDIATES_INDEX), raw["pem_file"])
            with open(pem_path, "rb") as fh:
                pem = fh.read()
            cert = x509.load_pem_x509_certificate(pem)
            entry = dict(raw)
            entry["cert"] = cert
            entry["pem"] = pem
            entries.append(entry)
    except Exception as exc:
        raise ValueError(f"índice de intermediários eMudhra inválido: {exc}") from exc

    if not entries:
        raise ValueError("índice de intermediários eMudhra vazio")
    _INTERMEDIATES_CACHE = entries
    return entries


def _spki_sha256(cert) -> str:
    """SHA-256 (hex maiúsculo) da SubjectPublicKeyInfo do certificado.

    As variantes emitidas pela eMudhra e cross-signed pela Sectigo
    compartilham a mesma chave — a comparação por SPKI cobre as 16.
    """
    import hashlib

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest().upper()


def recover_ca_key(entry: dict):
    """Recupera a chave privada fraca do intermediário a partir do escalar.

    O incidente deixou ``d`` como inteiro minúsculo; derivar a chave
    ``d·G`` e comparar com a chave pública do certificado prova a recuperação.

    Args:
        entry: Entrada do índice (precisa de ``recovered_d`` e ``cert``).

    Returns:
        ``ec.EllipticCurvePrivateKey`` recuperada.

    Raises:
        ValueError: se a chave derivada não bate com a pública (dados
            vendados corrompidos).
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    cert = entry["cert"]
    pub = cert.public_key()
    d = int(entry["recovered_d"])
    key = ec.derive_private_key(d, pub.curve)
    if key.public_key().public_numbers() != pub.public_numbers():
        raise ValueError(f"chave recuperada não confere com a pública: {entry['cn']}")
    return key


def issue_test_leaf(ca_key, ca_cert, hours_valid: int = 24):
    """Emite um leaf efêmero de servidor assinado pelo CA comprometido.

    Args:
        ca_key: Chave privada recuperada do intermediário.
        ca_cert: Certificado do intermediário (issuer).
        hours_valid: Validade do leaf em horas (curta de propósito).

    Returns:
        Tupla ``(leaf_cert, leaf_key)``.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, TEST_SAN_DNS[0]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RASPilot Audit"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "RASPilot-RevokedCA"),
    ])
    san_entries: List[x509.GeneralName] = [
        x509.DNSName(name) for name in TEST_SAN_DNS
    ] + [
        x509.IPAddress(ipaddress.ip_address(ip)) for ip in TEST_SAN_IPS
    ]
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=hours_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    leaf_cert = builder.sign(ca_key, hashes.SHA256())
    return leaf_cert, leaf_key


# ----------------------------------------------------------------------
# Check A — diagnóstico de chain (host-side)
# ----------------------------------------------------------------------

def parse_host(value: str) -> Tuple[str, int]:
    """Normaliza ``HOST``/``HOST:PORTA``/URL em ``(host, porta)``.

    Args:
        value: String fornecida pelo usuário ou observada no tráfego.

    Returns:
        Tupla ``(host, porta)`` — porta default 443.
    """
    raw = (value or "").strip()
    for prefix in ("https://", "http://"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/", 1)[0]
    host, sep, port = raw.rpartition(":")
    if not sep or not host or not port.isdigit():
        return raw, 443
    return host, int(port)


def grab_chain(host: str, port: int = 443, timeout: float = 10.0) -> Tuple[List[dict], Optional[str]]:
    """Captura a chain TLS apresentada por ``host:port`` (sem validar).

    A validação é irrelevante aqui: interessa a chain APRESENTADA (um
    intermediário comprometido pode estar presente mesmo em clientes que
    o rejeitam).

    Returns:
        Tupla ``(certs, error)`` — ``certs`` é a lista de dicts
        ``{'cn', 'cert_sha256', 'spki_sha256', 'cert'}`` (leaf primeiro).
    """
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                raw_chain = ssock.get_unverified_chain() or []
                # Builds diferentes devolvem objetos _ssl.Certificate ou
                # DER bytes crus — normaliza para DER bytes.
                der_list = [
                    c if isinstance(c, bytes) else c.public_bytes(ssl.ENCODING_DER)
                    for c in raw_chain
                ]
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"

    certs: List[dict] = []
    for der in der_list:
        cert = x509.load_der_x509_certificate(der)
        certs.append({
            "cn": cert.subject.rfc4514_string(),
            "cert_sha256": hashlib.sha256(der).hexdigest().upper(),
            "spki_sha256": _spki_sha256(cert),
            "cert": cert,
        })
    if not certs:
        return [], "chain vazia"
    return certs, None


def match_chain(certs: List[dict], intermediates: Optional[List[dict]] = None) -> List[dict]:
    """Procura os intermediários comprometidos em uma chain apresentada.

    Args:
        certs: Saída de :func:`grab_chain` (ou equivalente local).
        intermediates: Catálogo (default: o vendado).

    Returns:
        Lista de entradas do catálogo que aparecem na chain.
    """
    entries = intermediates if intermediates is not None else load_intermediates()
    by_spki = {e["spki_sha256"].upper(): e for e in entries}
    by_cert = {e["cert_sha256"].upper(): e for e in entries}
    matched: Dict[str, dict] = {}
    for cert in certs:
        entry = by_spki.get(cert["spki_sha256"].upper()) or by_cert.get(
            cert["cert_sha256"].upper()
        )
        if entry is not None:
            matched[entry["id"]] = entry
    return list(matched.values())


def _crl_reachable(cert, timeout: float = 5.0) -> Tuple[Optional[bool], Optional[str]]:
    """Testa se o CRL Distribution Point do certificado responde.

    Best-effort: informação de higiene do backend (a revogação só protege
    clientes que a consultam), nunca derruba o check.

    Returns:
        Tupla ``(reachable, url)``.
    """
    from cryptography import x509

    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        for dp in ext.value:
            for name in dp.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    url = name.value
                    try:
                        with urllib.request.urlopen(url, timeout=timeout) as resp:
                            resp.read(1)
                            return True, url
                    except Exception:
                        return False, url
    except Exception:
        pass
    return None, None


class RevokedCACheck:
    """Check de confiança em CA comprometida (eMudhra emSign ECC G3).

    Args:
        dm: DeviceManager conectado.
        mode: Modo da auditoria (``detect`` pula o probe de aceitação).
        no_java: Se True, não injeta scripts Java (probe pulado).
    """

    def __init__(self, dm: "DeviceManager", mode: str = "bypass", no_java: bool = False) -> None:
        self.dm = dm
        self.mode = mode
        self.no_java = no_java

    # ------------------------------------------------------------------
    # Check A — hosts
    # ------------------------------------------------------------------
    def check_hosts(self, hosts: List[Tuple[str, int]]) -> List[dict]:
        """Inspeciona a chain TLS de cada host informado/observado.

        Args:
            hosts: Lista de ``(host, porta)`` já normalizada.

        Returns:
            Lista de resultados por host.
        """
        results: List[dict] = []
        for host, port in hosts:
            certs, error = grab_chain(host, port)
            entry: Dict[str, object] = {
                "host": host,
                "port": port,
                "chain_cns": [c["cn"] for c in certs],
                "matches": [],
                "error": error,
            }
            if certs:
                matches = match_chain(certs)
                for match in matches:
                    reachable, crl_url = _crl_reachable(match["cert"])
                    entry["matches"].append({
                        "id": match["id"],
                        "cn": match["cn"],
                        "serial_hex": match["serial_hex"],
                        "spki_sha256": match["spki_sha256"],
                        "recovered_d": match["recovered_d"],
                        "crl_url": crl_url,
                        "crl_reachable": reachable,
                    })
            results.append(entry)
        return results

    # ------------------------------------------------------------------
    # Check B — probe de aceitação (device-side)
    # ------------------------------------------------------------------
    def _pick_ca(self) -> dict:
        """Escolhe o intermediário para o probe (preferência DV > OV > EV)."""
        entries = load_intermediates()
        ranked = sorted(
            entries,
            key=lambda e: next(
                (i for i, p in enumerate(_CA_PREFERENCE) if e["cn"].startswith(p)),
                len(_CA_PREFERENCE),
            ),
        )
        return ranked[0]

    def attempt_probe(self, package_name: str, window: int = 12) -> dict:
        """Serve um leaf da CA comprometida e mede a aceitação no device.

        Fluxo: recupera a chave → emite leaf efêmero → sobe TLS server
        local → ``adb reverse`` → spawn suspenso → injeta
        ``emudhra_probe.js`` → resume → observa mensagens ``emudhra-probe``
        durante a janela. Tudo em ``finally`` é desfeito (reverse, server,
        scripts, spawn).

        Returns:
            Dict com ``status`` (``ok``/``skipped``/``error``), resultados
            por caminho (``system``/``app_default``: ``accepted``/
            ``rejected``/``None``), ``details``, ``evidence`` e ``error``.
        """
        result: Dict[str, object] = {
            "status": "ok", "ca": None, "system": None, "app_default": None,
            "details": {}, "evidence": [], "app_alive_at_end": None,
            "phase": None, "error": None,
        }
        evidence: List[str] = result["evidence"]  # type: ignore[assignment]

        entry = self._pick_ca()
        try:
            ca_key = recover_ca_key(entry)
        except Exception as exc:
            result["status"] = "error"
            result["phase"] = "key_recovery"
            result["error"] = f"recuperação da chave fraca falhou: {exc}"
            return result
        evidence.append(
            f"[key] chave recuperada: {entry['cn']} (d={entry['recovered_d']}) "
            "confere com a chave pública"
        )

        try:
            leaf_cert, leaf_key = issue_test_leaf(ca_key, entry["cert"])
        except Exception as exc:
            result["status"] = "error"
            result["phase"] = "leaf"
            result["error"] = f"emissão do leaf efêmero falhou: {exc}"
            return result
        result["ca"] = {  # type: ignore[typeddict-item]
            "id": entry["id"], "cn": entry["cn"], "recovered_d": entry["recovered_d"],
        }

        from cryptography.hazmat.primitives import serialization

        chain_pem = leaf_cert.public_bytes(serialization.Encoding.PEM) + entry["pem"]
        key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        httpd: Optional[http.server.ThreadingHTTPServer] = None
        server_thread: Optional[threading.Thread] = None
        tmpdir: Optional[tempfile.TemporaryDirectory] = None
        session = None
        script = None
        reverse_ok = False
        listen_port: Optional[int] = None
        phase = "setup"

        probe_messages: List[dict] = []
        script_logs: List[str] = []

        def on_message(message, data) -> None:
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("type") == "emudhra-probe":
                    probe_messages.append(payload)
                else:
                    text = str(payload.get("message", ""))
                    if text and text not in script_logs:
                        script_logs.append(text)
            elif message.get("type") == "error":
                script_logs.append(f"[script-error] {message.get('description', '')}")

        try:
            # TLS server local: leaf + intermediário comprometido como chain.
            tmpdir = tempfile.TemporaryDirectory(prefix="raspilot_emudhra_")
            chain_path = os.path.join(tmpdir.name, "chain.pem")
            key_path = os.path.join(tmpdir.name, "leaf.key")
            with open(chain_path, "wb") as fh:
                fh.write(chain_pem)
            with open(key_path, "wb") as fh:
                fh.write(key_pem)

            handler = _quiet_handler()
            httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_ctx.load_cert_chain(chain_path, key_path)
            httpd.socket = tls_ctx.wrap_socket(httpd.socket, server_side=True)
            listen_port = httpd.server_address[1]
            server_thread = threading.Thread(
                target=httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
            )
            server_thread.start()
            evidence.append(f"[probe] TLS de teste em 127.0.0.1:{listen_port} (leaf da CA comprometida)")

            reverse_ok = bool(
                getattr(self.dm, "reverse_port", None)
                and self.dm.reverse_port(listen_port, listen_port)
            )
            if not reverse_ok:
                result["status"] = "error"
                result["phase"] = "adb_reverse"
                result["error"] = "adb reverse indisponível (sem porta no device para o probe)"
                return result

            def _spawn_and_load():
                """Spawn suspenso + injeção do probe; desanexa em falha de load."""
                nonlocal phase
                phase = "spawn"
                sess = self.dm.spawn_app(package_name, resume=False)
                phase = "script_load"
                try:
                    scr = load_script_file(
                        sess, PROBE_SCRIPT, on_message=on_message,
                        replacements={
                            "__RASPILOT_TEST_PORT__": str(listen_port),
                            "__RASPILOT_TEST_URL__": f"https://127.0.0.1:{listen_port}/probe",
                        },
                        with_java_bridge=True, load_timeout=10.0,
                    )
                except Exception:
                    safe_detach(sess)
                    raise
                return sess, scr

            # Uma única tentativa extra quando a conexão Frida caiu (o
            # RASP do app pode derrubar o frida-server entre spawns):
            # backoff curto + restauração do servidor antes de retry.
            server_restore_error: Optional[str] = None
            for attempt in (1, 2):
                try:
                    session, script = _spawn_and_load()
                    break
                except Exception as exc:
                    if attempt == 1 and _is_transport_error(exc):
                        logger.debug(
                            "Conexão Frida caiu no spawn/load do probe; "
                            "restaurando servidor e tentando de novo",
                            exc_info=True,
                        )
                        time.sleep(RETRY_BACKOFF)
                        restore = getattr(self.dm, "ensure_frida_server", None)
                        if callable(restore):
                            try:
                                if not restore():
                                    server_restore_error = (
                                        "frida-server não respondeu após a restauração"
                                    )
                            except Exception as restore_exc:
                                server_restore_error = (
                                    f"restauração do frida-server falhou: {restore_exc}"
                                )
                        if server_restore_error:
                            raise RuntimeError(server_restore_error) from exc
                        continue
                    raise
            phase = "resume"
            self.dm.resume_app()
            pid = getattr(self.dm, "last_spawn_pid", None)

            phase = "observe"
            done = False
            for _ in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if any(m.get("probe") == "done" for m in probe_messages):
                    done = True
                    break
                if pid is not None and not self.dm.is_app_alive(pid):
                    break
            if not done and not probe_messages:
                logger.debug("probe eMudhra sem resposta na janela de %ss", window)

            for payload in probe_messages:
                probe_name = str(payload.get("probe", ""))
                probe_result = str(payload.get("result", ""))
                detail = str(payload.get("detail", ""))
                if probe_name in ("system", "app_default") and probe_result in PROBE_RESULT_MARKERS:
                    result[probe_name] = probe_result  # type: ignore[index]
                    result["details"][probe_name] = detail  # type: ignore[index]
                    evidence.append(f"[probe] {probe_name}: {probe_result} ({detail})")

            if pid is not None:
                result["app_alive_at_end"] = bool(self.dm.is_app_alive(pid))

            if result["system"] is None and result["app_default"] is None:  # type: ignore[comparison-overlap]
                result["status"] = "error"
                result["phase"] = "observe"
                result["error"] = "probe não reportou resultado (bridge Java indisponível?)"
                if script_logs:
                    result["details"] = {"logs": script_logs[:10]}  # type: ignore[typeddict-item]
            return result
        except Exception as exc:
            result["status"] = "error"
            result["phase"] = phase
            message = f"[{phase}] {type(exc).__name__}: {exc}"
            if _is_transport_error(exc):
                message += (
                    " — conexão com o frida-server caiu durante o probe (o RASP "
                    "do app pode ter derrubado o servidor); tente novamente ou "
                    "reinicie o frida-server"
                )
            result["error"] = message
            return result
        finally:
            safe_unload(script)
            if session is not None:
                safe_detach(session)
            if reverse_ok and listen_port is not None:
                try:
                    self.dm.remove_reverse(listen_port)
                except Exception:
                    logger.debug("Falha ao remover adb reverse", exc_info=True)
            if httpd is not None:
                try:
                    httpd.shutdown()
                    httpd.server_close()
                except Exception:
                    logger.debug("Falha ao encerrar TLS server", exc_info=True)
            if tmpdir is not None:
                try:
                    tmpdir.cleanup()
                except Exception:
                    logger.debug("Falha ao limpar diretório temporário", exc_info=True)
            try:
                self.dm.resume_app()  # idempotente: destrava spawn suspenso
            except Exception:
                logger.debug("Falha ao resumir app após probe", exc_info=True)

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self,
        package_name: str,
        window: int = 12,
        hosts: Optional[List[str]] = None,
    ) -> dict:
        """Executa os dois vetores e consolida o veredito.

        Args:
            package_name: Package name do app auditado.
            window: Janela de observação do probe (segundos).
            hosts: Hosts explícitos (``--audit-host``) e/ou observados no
                tráfego durante o pipeline.

        Returns:
            Dict consolidado no padrão dos demais checks.
        """
        evidence: List[str] = []

        # Recuperação das 8 chaves — prova de base do check (rápida: só
        # aritmética ECC em curvas P-384).
        recovery = {"ok": True, "tested": []}
        try:
            for entry in load_intermediates():
                try:
                    recover_ca_key(entry)
                    recovery["tested"].append({"cn": entry["cn"], "d": entry["recovered_d"], "ok": True})
                except Exception:
                    recovery["tested"].append({"cn": entry["cn"], "d": entry["recovered_d"], "ok": False})
                    recovery["ok"] = False
            recovered_ok = sum(1 for t in recovery["tested"] if t["ok"])  # type: ignore[union-attr]
            evidence.append(
                f"[key] recuperação de chaves fracas: {recovered_ok}/{len(recovery['tested'])} "  # type: ignore[arg-type]
                "conferem com as chaves públicas"
            )
        except Exception as exc:
            recovery = {"ok": False, "tested": [], "error": str(exc)}

        # Check A — chains.
        normalized: List[Tuple[str, int]] = []
        seen = set()
        for value in hosts or []:
            parsed = parse_host(str(value))
            if parsed[0] and parsed not in seen:
                seen.add(parsed)
                normalized.append(parsed)

        hosts_checked: List[dict] = []
        compromised_cas: List[str] = []
        if normalized:
            try:
                hosts_checked = self.check_hosts(normalized)
            except Exception as exc:
                hosts_checked = [{"error": f"{type(exc).__name__}: {exc}"}]
        else:
            evidence.append(
                "[chain] nenhum host para inspecionar (use --audit-host ou "
                "deixe o app fazer requisições durante a auditoria)"
            )

        for host_result in hosts_checked:
            for match in host_result.get("matches") or []:  # type: ignore[union-attr]
                compromised_cas.append(str(match["cn"]))
                crl_note = (
                    f"CRL acessível: {match['crl_url']}" if match.get("crl_reachable")
                    else f"CRL inacessível: {match.get('crl_url')}" if match.get("crl_url")
                    else "sem CRL publicado"
                )
                evidence.append(
                    f"[chain] {host_result['host']}:{host_result['port']} usa intermediário "  # type: ignore[union-attr]
                    f"comprometido: {match['cn']} (serial {str(match['serial_hex'])[:16]}…, "
                    f"d={match['recovered_d']}, {crl_note})"
                )
        compromised_cas = sorted(set(compromised_cas))
        server_uses_compromised_ca = bool(compromised_cas)

        # Check B — probe de aceitação.
        if self.mode == "detect":
            probe = {
                "status": "skipped",
                "reason": "modo detect: teste de aceitação não executado",
            }
        elif self.no_java:
            probe = {
                "status": "skipped",
                "reason": "--no-java: teste de aceitação requer a bridge Java",
            }
        else:
            probe = self.attempt_probe(package_name, window=window)

        probe_accepted: Optional[bool] = None
        bypass_skipped_reason: Optional[str] = None
        if probe.get("status") == "ok":
            paths = [probe.get("system"), probe.get("app_default")]
            if "accepted" in paths:
                probe_accepted = True
            elif paths and all(p == "rejected" for p in paths):
                probe_accepted = False
        elif probe.get("status") == "skipped":
            bypass_skipped_reason = str(probe.get("reason"))
        else:
            bypass_skipped_reason = f"probe: {probe.get('error')}"

        if probe.get("evidence"):
            evidence.extend(probe["evidence"])  # type: ignore[arg-type]
        if probe_accepted is True:
            accepted_paths = [
                name for name in ("system", "app_default") if probe.get(name) == "accepted"
            ]
            evidence.append(
                "[veredito] cadeia de CA comprometida ACEITA por: "
                + ", ".join(accepted_paths)
                + " — MITM possível sem instalar CA no dispositivo"
            )

        return {
            "server_uses_compromised_ca": server_uses_compromised_ca,
            "compromised_cas": compromised_cas,
            "hosts_checked": hosts_checked,
            "key_recovery": recovery,
            "probe": probe,
            "probe_accepted": probe_accepted,
            "bypass_skipped_reason": bypass_skipped_reason,
            "evidence": evidence,
            "timestamp": _now_iso(),
        }


def _quiet_handler():
    """Cria a classe de handler HTTP que responde 200 sem logar."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (API do http.server)
            body = b"raspilot-emudhra-probe"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # silencia o servidor de teste
            return

    return _Handler
