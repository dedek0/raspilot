"""Testes do AntiRootCheck — consolidação e cenários de root."""

from __future__ import annotations

from unittest import mock

from checks.anti_root import ROOT_APP_PACKAGES, SU_PATHS, AntiRootCheck
from reporter import Reporter
from tests.conftest import FakeShellDM


class TestSubChecks:
    """Comportamento individual dos vetores."""

    def test_su_binaries_found(self, fake_dm_factory):
        """Binário su em /system/xbin é reportado com o caminho."""
        dm = fake_dm_factory(
            {"ls -l /system/xbin/su": "/system/xbin/su 2750 root shell"}
        )
        res = AntiRootCheck(dm).check_su_binaries()
        assert res["detected"] is True
        assert "/system/xbin/su" in res["evidence"]

    def test_su_binaries_absent(self, clean_dm):
        """Sem su em nenhum path o vetor é negativo."""
        res = AntiRootCheck(clean_dm).check_su_binaries()
        assert res["detected"] is False
        assert res["evidence"] == []

    def test_magisk_multi_vector(self, magisk_dm):
        """Magisk detectado por package + dirs + which."""
        res = AntiRootCheck(magisk_dm).check_magisk()
        assert res["detected"] is True
        assert any("magisk" in e.lower() for e in res["evidence"])

    def test_root_props_debuggable(self, fake_dm_factory):
        """ro.debuggable=1 marca o vetor de props como positivo."""
        dm = fake_dm_factory({"ro.debuggable": "1", "ro.secure": "1"})
        res = AntiRootCheck(dm).check_root_props()
        assert res["detected"] is True
        assert res["props"]["ro.debuggable"] == "1"

    def test_root_props_secure_zero(self, fake_dm_factory):
        """ro.secure=0 também marca o vetor."""
        dm = fake_dm_factory({"ro.debuggable": "0", "ro.secure": "0"})
        res = AntiRootCheck(dm).check_root_props()
        assert res["detected"] is True

    def test_dangerous_apps_found(self, magisk_dm):
        """Package Magisk instalado aparece em dangerous_apps."""
        res = AntiRootCheck(magisk_dm).check_dangerous_apps()
        assert res["detected"] is True
        assert "com.topjohnwu.magisk" in res["evidence"]

    def test_dangerous_apps_error(self, fake_dm_factory):
        """Falha do pm list não lança exceção — vira error estruturado."""
        dm = fake_dm_factory(
            {"pm list packages": {"ok": False, "rc": 1, "stdout": "", "stderr": "denied"}}
        )
        res = AntiRootCheck(dm).check_dangerous_apps()
        assert res["detected"] is False
        assert "denied" in res["error"]

    def test_rw_system_detected(self, fake_dm_factory):
        """/system rw indica root."""
        dm = fake_dm_factory(
            {"/system ": "/dev/root /system ext4 rw,seclabel,relatime"}
        )
        res = AntiRootCheck(dm).check_rw_system()
        assert res["detected"] is True

    def test_busybox_absent(self, clean_dm):
        """Sem busybox o vetor é negativo."""
        res = AntiRootCheck(clean_dm).check_busybox()
        assert res["detected"] is False

    def test_alt_root_apatch_detected(self, fake_dm_factory):
        """Diretório do APatch em /data/adb/ap é detectado."""
        dm = fake_dm_factory({"ls /data/adb/ap 2>/dev/null": "apd\nap\nmodules"})
        res = AntiRootCheck(dm).check_alt_root_solutions()
        assert res["detected"] is True
        assert any("APatch" in e for e in res["evidence"])

    def test_alt_root_kernelsu_detected(self, fake_dm_factory):
        """Binário ksud é detectado."""
        dm = fake_dm_factory({"which ksud 2>/dev/null": "/data/adb/ksu/bin/ksud"})
        res = AntiRootCheck(dm).check_alt_root_solutions()
        assert res["detected"] is True
        assert any("ksud" in e for e in res["evidence"])

    def test_alt_root_absent(self, clean_dm):
        """Sem APatch/KernelSU o vetor é negativo."""
        res = AntiRootCheck(clean_dm).check_alt_root_solutions()
        assert res["detected"] is False

    def test_root_apps_list_contains_apatch_kernelsu(self):
        """APatch e KernelSU estão na lista de apps perigosos."""
        assert "me.bmax.apatch" in ROOT_APP_PACKAGES
        assert "me.weishu.kernelsu" in ROOT_APP_PACKAGES


class TestRunAll:
    """Consolidação final (veredito + confiança)."""

    def test_clean_device(self, clean_dm):
        """Dispositivo limpo: is_rooted=False, confidence=low."""
        res = AntiRootCheck(clean_dm).run_all()
        assert res["is_rooted"] is False
        assert res["confidence"] == "low"
        assert set(res["checks"]) == {
            "su_binaries", "magisk", "root_props",
            "dangerous_apps", "rw_system", "busybox", "alt_root_solutions",
        }
        assert "T" in res["timestamp"]  # ISO8601

    def test_magisk_device_high_confidence(self, magisk_dm):
        """Magisk: is_rooted=True, confidence=high, magisk.detected=True."""
        res = AntiRootCheck(magisk_dm).run_all()
        assert res["is_rooted"] is True
        assert res["confidence"] == "high"
        assert res["checks"]["magisk"]["detected"] is True

    def test_su_only_medium_confidence(self, fake_dm_factory):
        """Apenas su: is_rooted=True, confidence=medium."""
        dm = fake_dm_factory(
            {
                "ls -l /system/xbin/su": "/system/xbin/su 2750 root shell",
                "pm list packages 2>/dev/null": "package:com.android.chrome",
            }
        )
        res = AntiRootCheck(dm).run_all()
        assert res["is_rooted"] is True
        assert res["confidence"] == "medium"

    def test_shell_failure_never_raises(self, fake_dm_factory):
        """Device com shell 100% quebrado: veredito estruturado, sem exceção."""
        dm = FakeShellDM({})
        dm.run_shell = lambda command, timeout=20: {
            "ok": False, "rc": -1, "stdout": "", "stderr": "timeout após 20s"
        }
        res = AntiRootCheck(dm).run_all()
        assert res["is_rooted"] is False
        assert res["confidence"] == "low"

    def test_pure_callable_twice_same_result(self, magisk_dm):
        """run_all é reprodutível (idempotente) além do timestamp."""
        a = AntiRootCheck(magisk_dm).run_all()
        b = AntiRootCheck(magisk_dm).run_all()
        a.pop("timestamp"), b.pop("timestamp")
        assert a == b

    def test_su_paths_constant_is_complete(self):
        """Cobertura dos 7 paths canônicos de su."""
        assert len(SU_PATHS) == 7
        assert "/data/local/xbin/su" in SU_PATHS

    def test_root_apps_list_contains_magisk(self):
        """Magisk e SuperSU estão na lista de apps perigosos."""
        assert "com.topjohnwu.magisk" in ROOT_APP_PACKAGES
        assert "eu.chainfire.supersu" in ROOT_APP_PACKAGES


def _root_profile(present=True):
    """Perfil estático mínimo para a fase no app."""
    return {
        "available": True,
        "engine": "asc",
        "version": "0.1.2",
        "vectors": {
            "root": {
                "present": present,
                "confidence": "high" if present else "none",
                "findings": [{
                    "vector": "root",
                    "source": "asc",
                    "kind": "string_ref",
                    "value": "magisk",
                    "evidence": "Lcom/x;->checkRoot referencia magisk",
                    "confidence": "high",
                    "class": "Lcom/x;",
                    "method": "checkRoot",
                    "label": "referência ao Magisk",
                    "owner": "app",
                }] if present else [],
                "total": 1 if present else 0,
                "sources": ["asc"],
                "owners": {"app": 1} if present else {},
                "app_evidence": present,
                "techniques": ["referência ao Magisk"] if present else [],
            }
        },
        "coverage": {
            "root": {
                "bypass_hooks": ["RootBeer", "File.exists"],
                "possible_gaps": [],
                "static_present": present,
                "app_evidence": present,
            }
        },
        "manifest": {"available": True, "package": "com.example.app"},
        "rasp_sdks": [],
        "classes_count": 10,
        "summary": {"available": True, "engine": "asc", "vectors_present": []},
        "limitations": [],
        "errors": [],
        "timestamp": "2026-10-27T00:00:00+00:00",
        "cached": False,
    }


class TestAppRootDetectionAndBypass:
    """O check mede a proteção de root do app, não só o dispositivo."""

    def test_bypass_win_sets_failure(self, clean_dm):
        check = AntiRootCheck(clean_dm, mode="bypass")
        detection = {
            "detected": True,
            "detection_methods_found": ["File.exists: /system/xbin/su"],
            "app_alive_at_end": True,
            "details": "app consultou su",
        }
        bypass = {
            "success": True,
            "method": "frida",
            "app_alive_at_end": True,
            "neutralized": ["File.exists -> false"],
            "bypass_logs": [],
            "details": "neutralizado",
        }
        with mock.patch.object(
            check, "_detect_app_root", return_value=detection
        ), mock.patch.object(check, "_attempt_bypass", return_value=bypass):
            result = check.run_all(
                static_profile=_root_profile(),
                package_name="com.example.app",
                window=1,
            )
        assert result["app_detection"] is detection
        assert result["protection_detected"] is True
        assert result["bypass_successful"] is True
        assert result["status_hint"] == "FALHOU"
        assert result["is_rooted"] is False
        status, summary = Reporter._status_for("anti_root", result)
        assert status == "FALHOU"
        assert summary["bypass_successful"] is True

    def test_resisted_bypass_is_ok(self, clean_dm):
        check = AntiRootCheck(clean_dm, mode="bypass")
        with mock.patch.object(
            check,
            "_detect_app_root",
            return_value={"detected": True, "detection_methods_found": ["x"]},
        ), mock.patch.object(
            check,
            "_attempt_bypass",
            return_value={"success": False, "method": "frida", "app_alive_at_end": False},
        ):
            result = check.run_all(
                static_profile=_root_profile(),
                package_name="com.example.app",
                window=1,
            )
        assert result["bypass_successful"] is False
        assert result["status_hint"] == "OK"
        status, _summary = Reporter._status_for("anti_root", result)
        assert status == "OK"

    def test_detect_mode_does_not_run_bypass(self, clean_dm):
        check = AntiRootCheck(clean_dm, mode="detect")
        with mock.patch.object(
            check,
            "_detect_app_root",
            return_value={"detected": True, "detection_methods_found": ["x"]},
        ), mock.patch.object(check, "_attempt_bypass") as bypass:
            result = check.run_all(
                static_profile=_root_profile(),
                package_name="com.example.app",
                window=1,
            )
        bypass.assert_not_called()
        assert result["bypass_successful"] is None
        assert result["status_hint"] == "SKIP"

    def test_attempt_bypass_marks_exercised_check(self):
        dm = mock.MagicMock()
        dm.spawn_app.return_value = mock.MagicMock()
        dm.last_spawn_pid = 1
        dm.is_app_alive.return_value = True
        dm.logcat_mark = None
        dm.last_spawn_package = "com.example.app"
        check = AntiRootCheck(dm, mode="bypass")

        def fake_load(session, path, on_message=None, **kwargs):
            if on_message:
                on_message({"type": "send", "payload": {
                    "type": "raspilot-bypass",
                    "message": "File.exists(/system/xbin/su) -> false",
                }}, None)
            return mock.MagicMock()

        with mock.patch("checks.anti_root.load_script_file", side_effect=fake_load), \
             mock.patch("checks.anti_root.load_stealth", return_value=[]), \
             mock.patch("checks.anti_root.ROOT_OBSERVATION_POLL_INTERVAL", 0.0):
            result = check._attempt_bypass("com.example.app", window=1)
        assert result["success"] is True
        assert result["exercised"] is True
        assert result["neutralized"]

    def test_detect_app_root_collects_java_signal(self):
        dm = mock.MagicMock()
        dm.spawn_app.return_value = mock.MagicMock()
        dm.last_spawn_pid = 1
        dm.is_app_alive.return_value = True
        dm.logcat_mark = None
        dm.last_spawn_package = "com.example.app"
        check = AntiRootCheck(dm, mode="detect")

        def fake_load(session, path, on_message=None, **kwargs):
            if on_message:
                on_message({"type": "send", "payload": {
                    "type": "root-detection",
                    "method": "File.exists",
                    "detail": "/system/xbin/su",
                }}, None)
            return mock.MagicMock()

        with mock.patch("checks.anti_root.load_script_file", side_effect=fake_load), \
             mock.patch("checks.anti_root.load_stealth", return_value=[]), \
             mock.patch("checks.anti_root.ROOT_OBSERVATION_POLL_INTERVAL", 0.0):
            result = check._detect_app_root("com.example.app", window=1)
        assert result["detected"] is True
        assert "File.exists" in result["detection_methods_found"][0]
