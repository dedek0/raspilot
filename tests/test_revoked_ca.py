"""Testes do check de CA comprometida (eMudhra emSign ECC G3).

Cobrem: integridade do catálogo vendado, recuperação da chave fraca,
emissão do leaf, detecção em chains, captura de chain via TLS local,
probe de aceitação com sessão Frida falsa, consolidação do run_all e o
ramo de status no reporter.
"""

from __future__ import annotations

import socket
import ssl
import threading
from unittest import mock

import pytest

from checks.revoked_ca import (
    RevokedCACheck,
    grab_chain,
    issue_test_leaf,
    load_intermediates,
    match_chain,
    parse_host,
    recover_ca_key,
)
from reporter import Reporter

# Valores de d documentados no bug Mozilla 2083449 (fatos públicos).
EXPECTED_D = {
    "EM OV TLS CA - G3C": 4,
    "EM EV TLS CA - G3C": 56,
    "EM OV CS CA - G3B": 66,
    "EM EV TLS CA - G3B": 115,
    "EM OV TLS CA - G3B": 155,
    "EM DV TLS CA - G3B": 156,
    "EM DV TLS CA - G3C": 230,
    "EM OV CS CA - G3C": 237,
}


class TestCatalogo:
    """Índice vendado dos 8 intermediários."""

    def test_loads_eight_entries(self):
        entries = load_intermediates(refresh=True)
        assert len(entries) == 8
        assert {e["cn"] for e in entries} == set(EXPECTED_D)

    def test_entry_metadata_matches_pem(self):
        """Os hashes vendados conferem com os PEMs (integridade)."""
        import hashlib

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        for entry in load_intermediates():
            der = entry["cert"].public_bytes(Encoding.DER)
            assert hashlib.sha256(der).hexdigest().upper() == entry["cert_sha256"], entry["cn"]
            pub_der = entry["cert"].public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            assert hashlib.sha256(pub_der).hexdigest().upper() == entry["spki_sha256"]

    def test_documented_d_values(self):
        for entry in load_intermediates():
            assert entry["recovered_d"] == EXPECTED_D[entry["cn"]], entry["cn"]


class TestKeyRecovery:
    """Recuperação da chave fraca a partir do certificado público."""

    def test_recovers_all_eight(self):
        for entry in load_intermediates():
            key = recover_ca_key(entry)
            cert_pub = entry["cert"].public_key().public_numbers()
            assert key.public_key().public_numbers() == cert_pub, entry["cn"]

    def test_tiny_scalars(self):
        """Os escalarmente são inteiros minúsculos (não aleatórios)."""
        ds = [e["recovered_d"] for e in load_intermediates()]
        assert all(d < 256 for d in ds)


class TestIssueLeaf:
    """Emissão do leaf efêmero assinado pela CA comprometida."""

    def test_leaf_verifies_under_ca(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        entry = load_intermediates()[0]
        ca_key = recover_ca_key(entry)
        leaf, leaf_key = issue_test_leaf(ca_key, entry["cert"])

        # A assinatura do leaf valida sob a chave pública da CA.
        ca_key.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        assert leaf.issuer == entry["cert"].subject
        # A chave do leaf é independente da CA.
        assert leaf.public_key().public_numbers() != entry["cert"].public_key().public_numbers()

    def test_leaf_profile(self):
        from cryptography import x509
        import ipaddress as ipa

        entry = load_intermediates()[0]
        ca_key = recover_ca_key(entry)
        leaf, _ = issue_test_leaf(ca_key, entry["cert"])

        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert "localhost" in san.value.get_values_for_type(x509.DNSName)
        assert ipa.ip_address("127.0.0.1") in san.value.get_values_for_type(x509.IPAddress)
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki.value.key_identifier is not None

    def test_signature_algorithm_matches_key(self):
        """Assinatura ECDSA válida sob a chave recuperada (sanity)."""
        entry = load_intermediates()[0]
        ca_key = recover_ca_key(entry)
        leaf, _ = issue_test_leaf(ca_key, entry["cert"])
        assert leaf.signature_hash_algorithm.name == "sha256"


class TestMatchChain:
    """Detecção dos intermediários comprometidos em chains."""

    @staticmethod
    def _info(cert):
        import hashlib

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        der = cert.public_bytes(Encoding.DER)
        pub_der = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "cn": cert.subject.rfc4514_string(),
            "cert_sha256": hashlib.sha256(der).hexdigest().upper(),
            "spki_sha256": hashlib.sha256(pub_der).hexdigest().upper(),
            "cert": cert,
        }

    def test_detects_intermediate_in_chain(self):
        entry = load_intermediates()[0]
        ca_key = recover_ca_key(entry)
        leaf, _ = issue_test_leaf(ca_key, entry["cert"])
        matches = match_chain([self._info(leaf), self._info(entry["cert"])])
        assert [m["cn"] for m in matches] == [entry["cn"]]

    def test_spki_matches_cross_signed_variant(self):
        """A SPKI cobre as variantes eMudhra-emitida e Sectigo-cross-signed."""
        entry = load_intermediates()[0]
        # A detecção é por SPKI (chave), então basta a chave presente —
        # simulado passando apenas o próprio certificado (mesma SPKI).
        matches = match_chain([self._info(entry["cert"])])
        assert matches and matches[0]["id"] == entry["id"]

    def test_unrelated_ca_not_detected(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from datetime import datetime, timedelta, timezone

        key = ec.generate_private_key(ec.SECP384R1())
        now = datetime.now(timezone.utc)
        ca = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        assert match_chain([self._info(ca)]) == []


class TestParseHost:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("api.example.com", ("api.example.com", 443)),
            ("api.example.com:8443", ("api.example.com", 8443)),
            ("https://api.example.com/v1/x", ("api.example.com", 443)),
            ("http://api.example.com:8080/", ("api.example.com", 8080)),
        ],
    )
    def test_forms(self, raw, expected):
        assert parse_host(raw) == expected


class TestGrabChain:
    """Captura real de chain contra um TLS server local."""

    @staticmethod
    def _serve():
        """Sobe um TLS server efêmero servindo leaf+intermediário real."""
        import tempfile, os

        tmp = tempfile.TemporaryDirectory()
        entry = load_intermediates()[0]
        ca_key = recover_ca_key(entry)
        leaf, leaf_key = issue_test_leaf(ca_key, entry["cert"])
        from cryptography.hazmat.primitives import serialization

        chain = os.path.join(tmp.name, "chain.pem")
        with open(chain, "wb") as fh:
            fh.write(leaf.public_bytes(serialization.Encoding.PEM) + entry["pem"])
        key_path = os.path.join(tmp.name, "k.key")
        with open(key_path, "wb") as fh:
            fh.write(leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))

        import http.server

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                return

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(chain, key_path)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
        return httpd, tmp

    def test_grabs_and_detects(self):
        entry = load_intermediates()[0]
        httpd, tmp = self._serve()
        try:
            port = httpd.server_address[1]
            certs, error = grab_chain("127.0.0.1", port, timeout=5.0)
            assert error is None
            assert len(certs) >= 2  # leaf + intermediário
            matches = match_chain(certs)
            assert [m["cn"] for m in matches] == [entry["cn"]]
        finally:
            httpd.shutdown()
            httpd.server_close()
            tmp.cleanup()

    def test_unreachable_reports_error(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()  # porta fechada
        certs, error = grab_chain("127.0.0.1", port, timeout=1.0)
        assert certs == []
        assert error


class TestAttemptProbe:
    """Probe de aceitação com sessão Frida falsa."""

    class _FakeScript:
        def __init__(self, messages):
            self._messages = messages
            self._cb = None

        def on(self, event, cb):
            self._cb = cb

        def load(self):
            for m in self._messages:
                self._cb(m, None)

        def unload(self):
            pass

    class _FakeSession:
        def __init__(self, messages):
            self._messages = messages

        def create_script(self, source, **kwargs):
            if "emudhra-probe" in source:
                return TestAttemptProbe._FakeScript(self._messages)
            return TestAttemptProbe._FakeScript([])

        def detach(self):
            pass

    @staticmethod
    def _dm(messages):
        dm = mock.MagicMock()
        dm.reverse_port.return_value = True
        dm.spawn_app.return_value = TestAttemptProbe._FakeSession(messages)
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = True
        return dm

    def test_accepted_is_reported(self):
        dm = self._dm([
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "loaded",
                                          "result": "loaded", "detail": ""}},
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "system",
                                          "result": "accepted", "detail": "chain=2"}},
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "app_default",
                                          "result": "accepted", "detail": "http=200"}},
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "done",
                                          "result": "done", "detail": ""}},
        ])
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0):
            res = RevokedCACheck(dm).attempt_probe("com.app", window=3)
        assert res["status"] == "ok"
        assert res["system"] == "accepted"
        assert res["app_default"] == "accepted"
        assert res["ca"]["recovered_d"] in EXPECTED_D.values()
        # Evidência de recuperação + probe presente.
        assert any(e.startswith("[key]") for e in res["evidence"])
        assert any("system: accepted" in e for e in res["evidence"])

    def test_rejected_is_reported(self):
        dm = self._dm([
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "system",
                                          "result": "rejected",
                                          "detail": "SSLHandshakeException: trust failed"}},
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "app_default",
                                          "result": "rejected", "detail": "SSLHandshakeException"}},
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "done",
                                          "result": "done", "detail": ""}},
        ])
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0):
            res = RevokedCACheck(dm).attempt_probe("com.app", window=3)
        assert res["status"] == "ok"
        assert res["system"] == "rejected"
        assert res["app_default"] == "rejected"

    def test_reverse_failure_is_error(self):
        dm = self._dm([])
        dm.reverse_port.return_value = False
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0):
            res = RevokedCACheck(dm).attempt_probe("com.app", window=1)
        assert res["status"] == "error"
        assert res["phase"] == "adb_reverse"
        assert "adb reverse" in res["error"]

    def test_transport_error_reports_phase_and_hint(self):
        """Queda de conexão Frida no spawn registra fase + diagnóstico."""
        dm = self._dm([])
        dm.spawn_app.side_effect = RuntimeError("the connection is closed")
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0), \
                mock.patch("checks.revoked_ca.RETRY_BACKOFF", 0.0):
            res = RevokedCACheck(dm).attempt_probe("com.app", window=1)
        assert res["status"] == "error"
        assert res["phase"] == "spawn"
        assert "[spawn]" in res["error"]
        assert "frida-server" in res["error"]
        # A conexão caiu => houve uma nova tentativa de spawn.
        assert dm.spawn_app.call_count == 2

    def test_retry_succeeds_after_transport_error(self):
        """Primeiro spawn com conexão morta, segundo bem-sucedido => ok."""
        messages = [
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "system",
                                          "result": "accepted", "detail": "chain=2"}},
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "app_default",
                                          "result": "accepted", "detail": "http=200"}},
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "done",
                                          "result": "done", "detail": ""}},
        ]
        dm = mock.MagicMock()
        dm.reverse_port.return_value = True
        dm.ensure_frida_server.return_value = True
        dm.spawn_app.side_effect = [
            RuntimeError("the connection is closed"),
            self._FakeSession(messages),
        ]
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = True
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0), \
                mock.patch("checks.revoked_ca.RETRY_BACKOFF", 0.0):
            res = RevokedCACheck(dm).attempt_probe("com.app", window=3)
        assert res["status"] == "ok"
        assert res["system"] == "accepted"
        assert dm.spawn_app.call_count == 2
        # O servidor foi restaurado antes do retry.
        assert dm.ensure_frida_server.called

    def test_restore_failure_aborts_with_clear_error(self):
        """Servidor irrecuperável => erro claro, sem retry em vão."""
        dm = self._dm([])
        dm.spawn_app.side_effect = RuntimeError("the connection is closed")
        dm.ensure_frida_server.side_effect = RuntimeError("setup falhou")
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0), \
                mock.patch("checks.revoked_ca.RETRY_BACKOFF", 0.0):
            res = RevokedCACheck(dm).attempt_probe("com.app", window=1)
        assert res["status"] == "error"
        assert "restauração do frida-server falhou" in res["error"]
        assert "setup falhou" in res["error"]
        # Abortou antes do segundo spawn.
        assert dm.spawn_app.call_count == 1

    def test_non_transport_error_not_retried(self):
        """Erro comum (não-conexão) não gera retry."""
        dm = self._dm([])
        dm.spawn_app.side_effect = ValueError("boom")
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0):
            res = RevokedCACheck(dm).attempt_probe("com.app", window=1)
        assert res["status"] == "error"
        assert res["phase"] == "spawn"
        assert "[spawn] ValueError: boom" in res["error"]
        assert dm.spawn_app.call_count == 1
        # Sem queda de conexão => servidor intacto.
        assert not dm.ensure_frida_server.called

    def test_cleanup_always_runs(self):
        dm = self._dm([
            {"type": "send", "payload": {"type": "emudhra-probe", "probe": "done",
                                          "result": "done", "detail": ""}},
        ])
        with mock.patch("checks.revoked_ca.OBSERVATION_POLL_INTERVAL", 0.0):
            RevokedCACheck(dm).attempt_probe("com.app", window=2)
        # reverse removido com a porta correta e spawn destravado.
        assert dm.remove_reverse.called
        port = dm.remove_reverse.call_args[0][0]
        assert dm.reverse_port.call_args[0][0] == port
        assert dm.resume_app.called


class TestRunAll:
    """Consolidação dos vetores no run_all."""

    def test_server_hit_flagged(self):
        check = RevokedCACheck(mock.MagicMock())
        hosts_result = [{
            "host": "api.x.com", "port": 443, "chain_cns": [],
            "matches": [{"cn": "EM OV TLS CA - G3B", "serial_hex": "AB", "recovered_d": 155,
                         "crl_url": None, "crl_reachable": None}],
            "error": None,
        }]
        with mock.patch.object(check, "check_hosts", return_value=hosts_result), \
                mock.patch.object(check, "attempt_probe", return_value={
                    "status": "ok", "system": "rejected", "app_default": "rejected",
                    "evidence": [], "details": {}, "error": None,
                }):
            res = check.run_all("com.app", hosts=["api.x.com"])
        assert res["server_uses_compromised_ca"] is True
        assert res["compromised_cas"] == ["EM OV TLS CA - G3B"]
        assert res["probe_accepted"] is False
        assert any("[chain]" in e for e in res["evidence"])

    def test_probe_accepted_flagged(self):
        check = RevokedCACheck(mock.MagicMock())
        with mock.patch.object(check, "check_hosts", return_value=[]), \
                mock.patch.object(check, "attempt_probe", return_value={
                    "status": "ok", "system": "accepted", "app_default": "accepted",
                    "evidence": [], "details": {}, "error": None,
                }):
            res = check.run_all("com.app", hosts=["api.x.com"])
        assert res["server_uses_compromised_ca"] is False
        assert res["probe_accepted"] is True

    def test_no_hosts_no_probe_is_none(self):
        check = RevokedCACheck(mock.MagicMock())
        with mock.patch.object(check, "attempt_probe", return_value={
            "status": "error", "error": "boom", "evidence": [],
        }):
            res = check.run_all("com.app", hosts=[])
        assert res["probe_accepted"] is None
        assert "boom" in res["bypass_skipped_reason"]
        assert res["hosts_checked"] == []

    def test_detect_mode_skips_probe(self):
        check = RevokedCACheck(mock.MagicMock(), mode="detect")
        with mock.patch.object(check, "attempt_probe") as probe:
            res = check.run_all("com.app", hosts=[])
        probe.assert_not_called()
        assert res["probe_accepted"] is None
        assert "modo detect" in res["bypass_skipped_reason"]

    def test_no_java_skips_probe(self):
        check = RevokedCACheck(mock.MagicMock(), no_java=True)
        with mock.patch.object(check, "attempt_probe") as probe:
            res = check.run_all("com.app", hosts=[])
        probe.assert_not_called()
        assert "--no-java" in res["bypass_skipped_reason"]

    def test_hosts_deduplicated_and_parsed(self):
        check = RevokedCACheck(mock.MagicMock())
        captured = []

        def _capture(hosts):
            captured.append(hosts)
            return []

        with mock.patch.object(check, "check_hosts", side_effect=_capture), \
                mock.patch.object(check, "attempt_probe", return_value={
                    "status": "error", "error": "x", "evidence": [],
                }):
            check.run_all("com.app", hosts=[
                "api.x.com", "https://api.x.com/", "api.x.com:443", "outro.com",
            ])
        assert captured[0] == [("api.x.com", 443), ("outro.com", 443)]

    def test_key_recovery_evidence_present(self):
        check = RevokedCACheck(mock.MagicMock())
        with mock.patch.object(check, "check_hosts", return_value=[]), \
                mock.patch.object(check, "attempt_probe", return_value={
                    "status": "error", "error": "x", "evidence": [],
                }):
            res = check.run_all("com.app", hosts=[])
        assert res["key_recovery"]["ok"] is True
        assert len(res["key_recovery"]["tested"]) == 8
        assert any("8/8" in e for e in res["evidence"])


class TestReporterStatus:
    """Ramo de status do revoked_ca no reporter."""

    def test_server_hit_fails(self):
        status, summary = Reporter._status_for("revoked_ca", {
            "server_uses_compromised_ca": True,
            "compromised_cas": ["EM DV TLS CA - G3B"],
            "hosts_checked": [{}],
            "probe_accepted": None,
            "bypass_skipped_reason": "x",
        })
        assert status == "FALHOU"
        assert summary["server_uses_compromised_ca"] is True
        assert summary["compromised_ca"] == ["EM DV TLS CA - G3B"]

    def test_probe_accepted_fails(self):
        status, summary = Reporter._status_for("revoked_ca", {
            "server_uses_compromised_ca": False,
            "compromised_cas": [],
            "hosts_checked": [],
            "probe_accepted": True,
        })
        assert status == "FALHOU"
        assert summary["probe_accepted"] is True

    def test_probe_rejected_ok(self):
        status, _ = Reporter._status_for("revoked_ca", {
            "server_uses_compromised_ca": False,
            "compromised_cas": [],
            "hosts_checked": [],
            "probe_accepted": False,
        })
        assert status == "OK"

    def test_not_evaluated_is_na(self):
        status, summary = Reporter._status_for("revoked_ca", {
            "server_uses_compromised_ca": False,
            "compromised_cas": [],
            "hosts_checked": [],
            "probe_accepted": None,
            "bypass_skipped_reason": "modo detect: teste de aceitação não executado",
        })
        assert status == "N/A"
        assert "modo detect" in summary["skip_reason"]

    def test_error_is_error(self):
        status, _ = Reporter._status_for("revoked_ca", {"error": "boom"})
        assert status == "ERROR"

    def test_skipped_is_skip(self):
        status, _ = Reporter._status_for("revoked_ca", {"skipped": True})
        assert status == "SKIP"


class TestProbeScript:
    """Marcadores do emudhra_probe.js (semântica de evidência)."""

    def test_script_exists_and_markers(self):
        from checks.revoked_ca import PROBE_SCRIPT

        with open(PROBE_SCRIPT, "r", encoding="utf-8") as fh:
            source = fh.read()
        assert "emudhra-probe" in source
        assert "__RASPILOT_TEST_PORT__" in source
        assert "__RASPILOT_TEST_URL__" in source
        assert "setEndpointIdentificationAlgorithm" in source
        assert "app_default" in source and "system" in source
