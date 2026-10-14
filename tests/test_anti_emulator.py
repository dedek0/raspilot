"""Testes do AntiEmulatorCheck — classificação de emuladores."""

from __future__ import annotations

from checks.anti_emulator import AntiEmulatorCheck


class TestSubChecks:
    """Vetores individuais."""

    def test_props_qemu(self, avd_dm):
        """AVD: propriedades QEMU detectadas."""
        res = AntiEmulatorCheck(avd_dm).check_emulator_props()
        assert res["detected"] is True
        assert any("qemu" in e for e in res["evidence"])

    def test_props_physical(self, clean_dm):
        """Dispositivo físico: props não indicam emulador."""
        res = AntiEmulatorCheck(clean_dm).check_emulator_props()
        assert res["detected"] is False

    def test_files_qemu(self, avd_dm):
        """/dev/qemu_pipe detectado."""
        res = AntiEmulatorCheck(avd_dm).check_emulator_files()
        assert res["detected"] is True
        assert "/dev/qemu_pipe" in res["evidence"]

    def test_cpu_x86_is_emulator_hint(self, avd_dm):
        """x86_64 sem Chromebook é indício de emulador."""
        res = AntiEmulatorCheck(avd_dm).check_cpu_architecture()
        assert res["detected"] is True
        assert res["is_x86"] is True

    def test_cpu_arm_physical(self, clean_dm):
        """arm64 não é indício de emulador."""
        res = AntiEmulatorCheck(clean_dm).check_cpu_architecture()
        assert res["detected"] is False

    def test_cpu_x86_chromebook_descartado(self, fake_dm_factory):
        """Chromebook x86 é descartado como emulador."""
        dm = fake_dm_factory(
            {"ro.boot.hardware": "chromebook"}, abi="x86_64"
        )
        res = AntiEmulatorCheck(dm).check_cpu_architecture()
        assert res["detected"] is False

    def test_sensors_few_is_emulator(self, avd_dm):
        """Menos de 3 sensores é indício de emulador."""
        res = AntiEmulatorCheck(avd_dm).check_sensors()
        assert res["detected"] is True
        assert res["sensor_count"] == 1

    def test_sensors_many_physical(self, clean_dm):
        """4+ sensores é plausível para hardware real."""
        res = AntiEmulatorCheck(clean_dm).check_sensors()
        assert res["detected"] is False
        assert res["sensor_count"] == 4

    def test_bluetooth_placeholder(self, fake_dm_factory):
        """MAC 02:00:00:00:00:00 é placeholder de emulador."""
        dm = fake_dm_factory(
            {"settings get secure bluetooth_address": "02:00:00:00:00:00"}
        )
        res = AntiEmulatorCheck(dm).check_bluetooth_mac()
        assert res["detected"] is True

    def test_bluetooth_real(self, clean_dm):
        """MAC real não é indício."""
        res = AntiEmulatorCheck(clean_dm).check_bluetooth_mac()
        assert res["detected"] is False

    def test_genymotion_detected(self, fake_dm_factory):
        """Package Genymotion detectado."""
        dm = fake_dm_factory(
            {"pm list packages": "package:com.genymotion.superuser"}
        )
        res = AntiEmulatorCheck(dm).check_genymotion()
        assert res["detected"] is True

    def test_third_party_ldplayer(self, fake_dm_factory):
        """LDPlayer detectado via package."""
        dm = fake_dm_factory(
            {"pm list packages": "package:com.android.flysilkworm", "ps -A": ""}
        )
        res = AntiEmulatorCheck(dm).check_third_party_emulators()
        assert res["detected"] is True
        assert "ldplayer" in res["types"]

    def test_third_party_bluestacks(self, fake_dm_factory):
        """BlueStacks detectado via package."""
        dm = fake_dm_factory(
            {"pm list packages": "package:com.bluestacks.settings", "ps -A": ""}
        )
        res = AntiEmulatorCheck(dm).check_third_party_emulators()
        assert "bluestacks" in res["types"]

    def test_third_party_nox(self, fake_dm_factory):
        """Nox detectado via processo."""
        dm = fake_dm_factory({"pm list packages": "", "ps -A": "root 1 0 noxd"})
        res = AntiEmulatorCheck(dm).check_third_party_emulators()
        assert "nox" in res["types"]

    def test_third_party_waydroid(self, fake_dm_factory):
        """Waydroid detectado via package."""
        dm = fake_dm_factory(
            {"pm list packages": "package:org.lineageos.waydroid", "ps -A": ""}
        )
        res = AntiEmulatorCheck(dm).check_third_party_emulators()
        assert "waydroid" in res["types"]


class TestRunAll:
    """Consolidação e classificação do tipo."""

    def test_avd(self, avd_dm):
        """AVD: is_emulator=True, type=qemu_avd, confidence=high."""
        res = AntiEmulatorCheck(avd_dm).run_all()
        assert res["is_emulator"] is True
        assert res["emulator_type"] == "qemu_avd"
        assert res["confidence"] == "high"

    def test_genymotion(self, fake_dm_factory):
        """Genymotion: type=genymotion, confidence=high."""
        dm = fake_dm_factory({
            "pm list packages": "package:com.genymotion.superuser",
            "ls /system/bin/genymotion": "/system/bin/genymotion",
        })
        res = AntiEmulatorCheck(dm).run_all()
        assert res["is_emulator"] is True
        assert res["emulator_type"] == "genymotion"
        assert res["confidence"] == "high"

    def test_physical_device(self, clean_dm):
        """Físico: is_emulator=False, confidence=high, type=None."""
        res = AntiEmulatorCheck(clean_dm).run_all()
        assert res["is_emulator"] is False
        assert res["emulator_type"] is None
        assert res["confidence"] == "high"

    def test_reproducible(self, avd_dm):
        """run_all é reprodutível (idempotente) além do timestamp."""
        a = AntiEmulatorCheck(avd_dm).run_all()
        b = AntiEmulatorCheck(avd_dm).run_all()
        a.pop("timestamp"), b.pop("timestamp")
        assert a == b

    def test_all_seven_vectors_present(self, clean_dm):
        """Os 7 vetores estão presentes no resultado consolidado."""
        res = AntiEmulatorCheck(clean_dm).run_all()
        assert set(res["checks"]) == {
            "emulator_props", "emulator_files", "cpu_architecture",
            "sensors", "bluetooth_mac", "genymotion", "third_party_emulators",
        }
