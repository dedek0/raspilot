"""Testes do SSLPinningCheck — detecção estática e bypass."""

from __future__ import annotations

import os
import zipfile
from unittest import mock

from checks.ssl_pinning import SSL_BYPASS_SCRIPT, SSLPinningCheck


def _make_apk(path: str, entries: dict) -> str:
    """Cria um APK sintético (zip) com as entradas fornecidas.

    Args:
        path: Caminho do arquivo a criar.
        entries: ``{nome: bytes}``.

    Returns:
        O mesmo ``path`` recebido.
    """
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


class TestDetectPinning:
    """Detecção estática de pinning no APK."""

    def test_okhttp_detected(self, tmp_path):
        """CertificatePinner no dex => type=okhttp."""
        apk = _make_apk(str(tmp_path / "ok.apk"), {
            "classes.dex": b"dex\n035\x00okhttp3/CertificatePinner\x00",
        })
        res = SSLPinningCheck(mock.MagicMock()).detect_pinning("pkg", apk_path=apk)
        assert res["pinning_detected"] is True
        assert res["type"] == "okhttp"

    def test_network_security_config_detected(self, tmp_path):
        """networkSecurityConfig no Manifest binário => type=nsc."""
        apk = _make_apk(str(tmp_path / "nsc.apk"), {
            "AndroidManifest.xml": (
                b"\x03\x00" + "networkSecurityConfig".encode("utf-16le")
            ),
        })
        res = SSLPinningCheck(mock.MagicMock()).detect_pinning("pkg", apk_path=apk)
        assert res["pinning_detected"] is True
        assert res["type"] == "network_security_config"

    def test_flutter_detected(self, tmp_path):
        """libflutter.so => type=flutter."""
        apk = _make_apk(str(tmp_path / "fl.apk"), {
            "lib/arm64-v8a/libflutter.so": b"\x7fELFFLUTTER",
            "assets/flutter_assets/AssetManifest.bin": b"x",
        })
        res = SSLPinningCheck(mock.MagicMock()).detect_pinning("pkg", apk_path=apk)
        assert res["pinning_detected"] is True
        assert res["type"] == "flutter"

    def test_trustkit_detected(self, tmp_path):
        """TrustKit => type=trustkit."""
        apk = _make_apk(str(tmp_path / "tk.apk"), {
            "classes.dex": b"com.datatheorem.android.trustkit\x00",
        })
        res = SSLPinningCheck(mock.MagicMock()).detect_pinning("pkg", apk_path=apk)
        assert res["type"] == "trustkit"

    def test_native_conscrypt_detected(self, tmp_path):
        """Conscrypt nativo => type=native."""
        apk = _make_apk(str(tmp_path / "nc.apk"), {
            "classes.dex": b"org.conscrypt.Platform\x00",
        })
        res = SSLPinningCheck(mock.MagicMock()).detect_pinning("pkg", apk_path=apk)
        assert res["type"] == "native"

    def test_no_pinning(self, tmp_path):
        """APK limpo => pinning_detected=False, type=none."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {
            "classes.dex": b"dex\n035\x00com.example.plain\x00",
        })
        res = SSLPinningCheck(mock.MagicMock()).detect_pinning("pkg", apk_path=apk)
        assert res["pinning_detected"] is False
        assert res["type"] == "none"

    def test_priority_okhttp_over_nsc(self, tmp_path):
        """Com okhttp + nsc, o principal é okhttp."""
        apk = _make_apk(str(tmp_path / "both.apk"), {
            "classes.dex": b"okhttp3/CertificatePinner\x00",
            "AndroidManifest.xml": "networkSecurityConfig".encode("utf-16le"),
        })
        res = SSLPinningCheck(mock.MagicMock()).detect_pinning("pkg", apk_path=apk)
        assert res["type"] == "okhttp"
        assert "network_security_config" in res["all_types"]

    def test_pull_failure_returns_error(self):
        """Sem APK e sem pm path: erro estruturado, sem exceção."""
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": False, "rc": 1, "stdout": "", "stderr": "err"}
        res = SSLPinningCheck(dm).detect_pinning("com.missing")
        assert res["pinning_detected"] is False
        assert "error" in res


class TestAttemptBypass:
    """Bypass dinâmico com sessão Frida falsa."""

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
            # O script real (com prelúdio da bridge) deve ser lido do disco.
            # O kill_trace.js recebe mensagens próprias (lista vazia aqui).
            if "ssl" in source.lower():
                return TestAttemptBypass._FakeScript(self._messages)
            return TestAttemptBypass._FakeScript([])

        def detach(self):
            pass

    def test_success_with_host_evidence(self):
        """Bypass com host interceptado => success=True."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = self._FakeSession([
            {"type": "send", "payload": {"type": "ssl-bypass",
                                          "message": "OkHttp CertificatePinner.check bypass (api.x.com)"}},
            {"type": "send", "payload": {"type": "ssl-bypass-host", "host": "api.x.com"}},
        ])
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).attempt_bypass("com.app")
        assert res["success"] is True
        assert res["intercepted_hosts"] == ["api.x.com"]

    def test_failure_without_evidence(self):
        """Apenas logs de instalação (sem bypass real) => success=False."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = self._FakeSession([
            {"type": "send", "payload": {"type": "ssl-bypass",
                                          "message": "OkHttp CertificatePinner.check(String, List) hookado"}},
        ])
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).attempt_bypass("com.app")
        assert res["success"] is False

    def test_spawn_error_is_captured(self):
        """Erro no spawn vira dict com error, sem exceção."""
        dm = mock.MagicMock()
        dm.spawn_app.side_effect = RuntimeError("spawn falhou")
        res = SSLPinningCheck(dm).attempt_bypass("com.app")
        assert res["success"] is False
        assert "spawn falhou" in res["error"]

    def test_app_kill_reported_not_evidence(self):
        """Mensagens do kill_trace entram como diagnóstico, não evidência."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = self._FakeSession([
            {"type": "send", "payload": {"type": "app-kill",
                                          "message": "System.exit(1) <- com.x.Security.kill"}},
        ])
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).attempt_bypass("com.app")
        assert any(log.startswith("app-kill:") for log in res["bypass_logs"])
        assert res["success"] is False

    def test_app_death_captured(self):
        """Morte durante o bypass registra a causa externa no resultado."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = self._FakeSession([])
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": None,
            "summary": "sem registro externo (SIGKILL externo ou exit_group direto)",
        }
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).attempt_bypass("com.app", window=3)
        assert res["app_alive_at_end"] is False
        assert res["death_cause"]["signal"] is None
        assert any(log.startswith("death_cause:") for log in res["bypass_logs"])
        assert res["success"] is False

    def test_kill_trace_script_exists(self):
        """O kill_trace.js existe e cobre os vetores de morte essenciais."""
        from checks.ssl_pinning import KILL_TRACE_SCRIPT

        assert os.path.isfile(KILL_TRACE_SCRIPT)
        with open(KILL_TRACE_SCRIPT, encoding="utf-8") as fh:
            source = fh.read()
        for marker in (
            "System.exit", "Runtime.exit", "Runtime.halt", "killProcess",
            "tgkill", "killpg", "abort", "syscall", "app-kill", "backtrace",
            "raspilotFindExport", "raspilotPerformJava",
        ):
            assert marker in source, f"vetor ausente: {marker}"

    def test_script_file_exists(self):
        """O arquivo ssl_bypass.js existe e cobre as camadas essenciais."""
        assert os.path.isfile(SSL_BYPASS_SCRIPT)
        with open(SSL_BYPASS_SCRIPT, encoding="utf-8") as fh:
            source = fh.read()
        for marker in (
            "CertificatePinner", "HostnameVerifier", "TrustManager",
            "NetworkSecurityTrustManager", "Conscrypt", "WebViewClient",
            "SSL_CTX_set_custom_verify", "libflutter.so",
        ):
            assert marker in source, f"camada ausente: {marker}"

    def test_install_logs_never_match_evidence_markers(self):
        """Nenhum log de instalação ('hookado') contém marcador de evidência."""
        from checks.ssl_pinning import EVIDENCE_MARKERS

        with open(SSL_BYPASS_SCRIPT, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        for line in lines:
            if "log(" in line and "hookado" in line:
                for marker in EVIDENCE_MARKERS:
                    assert marker not in line, f"instalação vira evidência: {line}"

    def test_load_message_is_not_evidence(self):
        """O log de carga do script nunca casa com marcador de evidência.

        Regressão: o marcador 'bypass' (sem parêntese) casava com o nome
        do próprio arquivo ('ssl_bypass.js carregado') e contaminava o
        veredito.
        """
        from checks.ssl_pinning import EVIDENCE_MARKERS

        assert not any(m in "ssl_bypass.js carregado" for m in EVIDENCE_MARKERS)

    def test_okhttp_retry_sni_and_classloader(self):
        """O bypass tem retry/classloaders para OkHttp e SNI no caminho nativo."""
        with open(SSL_BYPASS_SCRIPT, encoding="utf-8") as fh:
            source = fh.read()
        assert "enumerateClassLoaders" in source
        assert "ClassFactory" in source
        assert "scheduleOkHttpRetries" in source
        assert "SSL_get_servername" in source

    def test_anti_frida_script_exists(self):
        """O anti_frida_bypass.js existe e cobre os hooks essenciais."""
        path = SSL_BYPASS_SCRIPT.replace("ssl_bypass.js", "anti_frida_bypass.js")
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        for marker in ("strstr", "strcmp", "memcmp", "File.exists", "Runtime.exec",
                       "ProcessBuilder", "pthread_setname_np"):
            assert marker in source, f"hook ausente: {marker}"

    def test_anti_root_script_exists(self):
        """O anti_root_bypass.js existe e cobre os hooks essenciais."""
        path = SSL_BYPASS_SCRIPT.replace("ssl_bypass.js", "anti_root_bypass.js")
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        for marker in ("RootBeer", "File.exists", "Runtime.exec", "SystemProperties"):
            assert marker in source, f"hook ausente: {marker}"


class TestRunAll:
    """Combinação detecção + bypass."""

    def test_no_pinning_skips_bypass(self, tmp_path):
        """Sem pinning: bypass_successful=None (não aplicável)."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {"classes.dex": b"plain"})
        dm = mock.MagicMock()
        res = SSLPinningCheck(dm).run_all("com.clean", apk_path=apk)
        assert res["pinning_detected"] is False
        assert res["bypass_successful"] is None
        dm.spawn_app.assert_not_called()

    def test_pinning_with_successful_bypass(self, tmp_path):
        """Pinning detectado + evidência de bypass => bypass_successful=True."""
        apk = _make_apk(str(tmp_path / "ok.apk"), {
            "classes.dex": b"okhttp3/CertificatePinner\x00",
        })
        dm = mock.MagicMock()
        dm.spawn_app.return_value = TestAttemptBypass._FakeSession([
            {"type": "send", "payload": {"type": "ssl-bypass",
                                          "message": "CertificatePinner.check bypass (api.x.com)"}},
            {"type": "send", "payload": {"type": "ssl-bypass-host", "host": "api.x.com"}},
        ])
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).run_all("com.app", apk_path=apk)
        assert res["pinning_detected"] is True
        assert res["pinning_type"] == "okhttp"
        assert res["bypass_successful"] is True
        assert res["timestamp"]


class TestReliability:
    """Propagação de erro e rigor da evidência de bypass."""

    def test_detection_error_is_propagated(self):
        """Falha ao obter o APK vira ERROR, não N/A."""
        dm = mock.MagicMock()
        dm.run_shell.return_value = {
            "ok": False, "rc": 1, "stdout": "", "stderr": "pull falhou"
        }
        res = SSLPinningCheck(dm).run_all("com.missing")
        assert res["bypass_successful"] is None
        assert "error" in res
        dm.spawn_app.assert_not_called()

    def test_config_only_logs_are_not_success(self):
        """Log de configuração nativa sem host não comprova bypass."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = TestAttemptBypass._FakeSession([
            {"type": "send", "payload": {
                "type": "ssl-bypass",
                "message": "libssl.so: SSL_get_verify_result -> X509_V_OK",
            }},
        ])
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = True
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).attempt_bypass("com.app", window=2)
        assert res["success"] is False
        assert res["evidence_strength"] == "config_only"
        assert res["effective_logs"]

    def test_success_requires_alive_app_and_host(self):
        """Host interceptado com app morto não é sucesso."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = TestAttemptBypass._FakeSession([
            {"type": "send", "payload": {"type": "ssl-bypass-host", "host": "api.x.com"}},
        ])
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": "SIGKILL", "summary": "SIGKILL",
        }
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).attempt_bypass("com.app", window=2)
        assert res["success"] is False
        assert res["intercepted_hosts"] == ["api.x.com"]

    def test_logcat_evidence_is_attached(self):
        """O logcat do intervalo é anexado ao resultado do bypass."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = TestAttemptBypass._FakeSession([
            {"type": "send", "payload": {"type": "ssl-bypass-host", "host": "api.x.com"}},
        ])
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 42 42 E com.app: SSLHandshakeException: pinning",
        ]
        with mock.patch("checks.ssl_pinning.time.sleep"):
            res = SSLPinningCheck(dm).attempt_bypass("com.app", window=2)
        assert res["success"] is True
        assert res["logcat"]["tls_errors"]
        assert res["logcat_evidence"]
