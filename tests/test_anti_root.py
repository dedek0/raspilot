"""Testes do AntiRootCheck — consolidação e cenários de root."""

from __future__ import annotations

from checks.anti_root import ROOT_APP_PACKAGES, SU_PATHS, AntiRootCheck
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


class TestRunAll:
    """Consolidação final (veredito + confiança)."""

    def test_clean_device(self, clean_dm):
        """Dispositivo limpo: is_rooted=False, confidence=low."""
        res = AntiRootCheck(clean_dm).run_all()
        assert res["is_rooted"] is False
        assert res["confidence"] == "low"
        assert set(res["checks"]) == {
            "su_binaries", "magisk", "root_props",
            "dangerous_apps", "rw_system", "busybox",
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
