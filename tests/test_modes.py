"""Testes dos modos de execução e de --no-java."""

from __future__ import annotations

from unittest import mock

from checks.anti_frida import AntiFridaCheck
from checks.anti_hooking import AntiHookingCheck
from checks.ssl_pinning import SSLPinningCheck


class _Script:
    def __init__(self):
        self.unloaded = False

    def on(self, event, cb):
        pass

    def load(self):
        pass

    def unload(self):
        self.unloaded = True


class _Session:
    def __init__(self):
        self.sources = []

    def create_script(self, source, **kwargs):
        self.sources.append(source)
        return _Script()

    def detach(self):
        pass


class TestNoJava:
    def test_anti_frida_skips_java_bridge(self):
        """--no-java carrega só a fase nativa do anti-Frida."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = []
        session = _Session()
        with mock.patch("checks.anti_frida.time.sleep"):
            res = AntiFridaCheck(dm, no_java=True).check_frida_detection_in_app(
                session, window=1, pid=1, package_name="com.example.app"
            )
        assert len(session.sources) == 1
        assert "var Java = bridge;" not in session.sources[0]
        assert res["java_skipped"] is True
        assert res["vulnerable"] is None


class TestModeDetect:
    def test_anti_hooking_skips_bypass(self, tmp_path):
        """Modo detect não executa o bypass anti-hook."""
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        dm.run_shell_root.return_value = dm.run_shell.return_value
        check = AntiHookingCheck(dm, mode="detect")
        detection = {
            "detected": True,
            "detection_methods_found": ["Class.forName: x"],
            "strong_signals": ["Class.forName: x"],
            "weak_signals": [],
            "app_alive_at_end": True,
            "session_unsafe": False,
        }
        with mock.patch.object(check, "detect_static", return_value={
            "static_detected": False, "types": [], "primary": None, "evidence": [],
        }), mock.patch.object(check, "attempt_bypass") as bypass:
            res = check.run_all("com.example.app", precomputed_detection=detection)
        bypass.assert_not_called()
        assert res["bypass_successful"] is None
        assert "modo detect" in res["bypass_skipped_reason"]

    def test_ssl_skips_bypass(self, tmp_path):
        """Modo detect não executa o bypass SSL."""
        apk = tmp_path / "app.apk"
        with __import__("zipfile").ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"okhttp3/CertificatePinner")
        check = SSLPinningCheck(mock.MagicMock(), mode="detect")
        res = check.run_all("com.example.app", apk_path=str(apk))
        assert res["bypass_successful"] is None
        assert "modo detect" in res["bypass_skipped_reason"]

    def test_ssl_precomputed_bypass_is_used(self):
        """Bypass combinado é reaproveitado sem novo spawn."""
        check = SSLPinningCheck(mock.MagicMock())
        with mock.patch.object(check, "detect_pinning", return_value={
            "pinning_detected": True, "type": "okhttp", "evidence": [],
        }), mock.patch.object(check, "attempt_bypass") as attempt:
            res = check.run_all(
                "com.example.app",
                precomputed_bypass={"success": True, "intercepted_hosts": ["api.example"]},
            )
        attempt.assert_not_called()
        assert res["bypass_successful"] is True
