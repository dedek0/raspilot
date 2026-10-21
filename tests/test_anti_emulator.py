"""Testes do AntiEmulatorCheck — detecção e bypass de proteção anti-emulador.

O check tem duas partes distintas:

- o **contexto do dispositivo** (a máquina da auditoria é emulada?) —
  preservado do check anterior e agora apenas informativo;
- a **proteção do app** (o app detecta emulador? o bypass vence?) —
  a parte nova, verificada por análise estática do APK e por observação
  dinâmica (probe/bypass).
"""

from __future__ import annotations

import zipfile

from checks.anti_emulator import AntiEmulatorCheck


def _make_apk(path, blobs: dict) -> str:
    """Cria um APK fake com as entradas indicadas.

    Args:
        path: Caminho do arquivo a criar.
        blobs: Mapa ``nome da entrada -> bytes``.

    Returns:
        Caminho do APK criado.
    """
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in blobs.items():
            zf.writestr(name, data)
    return str(path)


class TestDeviceContext:
    """Vetores de classificação do dispositivo de auditoria."""

    def test_props_qemu(self, avd_dm):
        """AVD: propriedades QEMU detectadas."""
        res = AntiEmulatorCheck(avd_dm).check_emulator_props()
        assert res["detected"] is True
        assert any("qemu" in e for e in res["evidence"])

    def test_props_physical(self, clean_dm):
        """Dispositivo físico: props não indicam emulador."""
        res = AntiEmulatorCheck(clean_dm).check_emulator_props()
        assert res["detected"] is False

    def test_google_manufacturer_is_not_emulator_alone(self, fake_dm_factory):
        """Regressão: manufacturer=Google sozinho não marca emulador
        (Pixels físicos também reportam esse valor)."""
        dm = fake_dm_factory({
            "ro.kernel.qemu": "", "ro.boot.qemu": "",
            "ro.hardware": "qcom",
            "ro.product.model": "Pixel 7",
            "ro.product.manufacturer": "Google",
            "ro.build.fingerprint": "google/panther/panther:14/UP1A:user/release-keys",
            "ro.product.device": "panther",
        })
        res = AntiEmulatorCheck(dm).check_emulator_props()
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

    def test_sensors_modern_format_is_parsed(self):
        """Regressão: o formato do Android 10+ é interpretado.

        O parser antigo só reconhecia o formato "- Nome" e deixava o
        vetor permanentemente indisponível em Android moderno — um
        vetor indisponível não é evidência de nada.
        """
        output = (
            "Captured at: 21:19:04.717\n"
            "Sensor Device:\n"
            "Total 17 h/w sensors, 17 running 0 disabled clients:\n"
            "0x00000033) active-count = 1; sampling_period(ms) = {20.0}\n"
            "Sensor List:\n"
            "0x00000001) accelerometer_stk8321 | Sprd Group Ltd. | ver: 1 | "
            "type: android.sensor.accelerometer(1) | perm: n/a\n"
            "0x00000002) gyroscope_stk8321 | Sprd Group Ltd. | ver: 1 | "
            "type: android.sensor.gyroscope(4) | perm: n/a\n"
            "0x00000003) magnetometer_ak09918 | Sprd Group Ltd. | ver: 1 | "
            "type: android.sensor.magnetic_field(2) | perm: n/a\n"
            "0x00000004) light_tmd2712 | Sprd Group Ltd. | ver: 1 | "
            "type: android.sensor.light(5) | perm: n/a\n"
        )
        names = AntiEmulatorCheck._parse_sensors(output)
        assert len(names) == 4
        assert names[0] == "accelerometer_stk8321"

    def test_sensors_virtual_name_is_emulator(self):
        """Sensor com nome de emulador é indício de ambiente virtual."""
        output = (
            "Sensor List:\n"
            "0x00000001) goldfish_accel | AOSP | ver: 1 | "
            "type: android.sensor.accelerometer(1) | perm: n/a\n"
        )
        names = AntiEmulatorCheck._parse_sensors(output)
        assert AntiEmulatorCheck._is_virtual_sensor(names[0]) is True

    def test_sensors_unavailable_is_not_evidence(self, fake_dm_factory):
        """dumpsys indisponível não vira evidência nem erro fatal."""
        dm = fake_dm_factory({
            "dumpsys sensorservice": {"ok": False, "rc": 1, "stdout": "", "stderr": "erro"},
        })
        res = AntiEmulatorCheck(dm).check_sensors()
        assert res["detected"] is False
        assert res["error"]

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

    def test_knox_is_not_nox_false_positive(self, fake_dm_factory):
        """Regressão: substrings 'knox' NÃO devem casar como emulador Nox."""
        dm = fake_dm_factory({
            "pm list packages": (
                "package:com.vendor.knox.securefolder\n"
                "package:com.vendor.knox.attestation\n"
                "package:com.android.chrome"
            ),
            "ps -A": "u0 100 500 0 0 0 S com.vendor.knox.securefolder",
        })
        res = AntiEmulatorCheck(dm).check_third_party_emulators()
        assert res["detected"] is False
        assert res["types"] == []

    def test_third_party_waydroid(self, fake_dm_factory):
        """Waydroid detectado via package."""
        dm = fake_dm_factory(
            {"pm list packages": "package:org.lineageos.waydroid", "ps -A": ""}
        )
        res = AntiEmulatorCheck(dm).check_third_party_emulators()
        assert "waydroid" in res["types"]


class TestDeviceClassification:
    """Consolidação do contexto do dispositivo."""

    def test_avd(self, avd_dm):
        """AVD: is_emulator=True, type=qemu_avd, confidence=high."""
        res = AntiEmulatorCheck(avd_dm).classify_device()
        assert res["is_emulator"] is True
        assert res["emulator_type"] == "qemu_avd"
        assert res["confidence"] == "high"

    def test_genymotion(self, fake_dm_factory):
        """Genymotion: type=genymotion, confidence=high."""
        dm = fake_dm_factory({
            "pm list packages": "package:com.genymotion.superuser",
            "ls /system/bin/genymotion": "/system/bin/genymotion",
        })
        res = AntiEmulatorCheck(dm).classify_device()
        assert res["is_emulator"] is True
        assert res["emulator_type"] == "genymotion"

    def test_physical_device(self, clean_dm):
        """Físico: is_emulator=False, type=None, confidence=high."""
        res = AntiEmulatorCheck(clean_dm).classify_device()
        assert res["is_emulator"] is False
        assert res["emulator_type"] is None
        assert res["confidence"] == "high"

    def test_all_seven_vectors_present(self, clean_dm):
        """Os 7 vetores estão presentes no resultado consolidado."""
        res = AntiEmulatorCheck(clean_dm).classify_device()
        assert set(res["checks"]) == {
            "emulator_props", "emulator_files", "cpu_architecture",
            "sensors", "bluetooth_mac", "genymotion", "third_party_emulators",
        }

    def test_reproducible(self, avd_dm):
        """classify_device é reprodutível (idempotente)."""
        a = AntiEmulatorCheck(avd_dm).classify_device()
        b = AntiEmulatorCheck(avd_dm).classify_device()
        assert a == b


class TestStaticDetection:
    """Detecção estática de assinaturas anti-emulador no APK."""

    def test_no_signature(self, clean_dm, tmp_path):
        """APK sem assinatura: static_detected=False."""
        apk = _make_apk(tmp_path / "clean.apk", {"classes.dex": b"payload sem nada"})
        res = AntiEmulatorCheck(clean_dm).detect_static("com.example.app", apk_path=apk)
        assert res["static_detected"] is False
        assert res["primary"] is None

    def test_sdk_signature_is_high_confidence(self, clean_dm, tmp_path):
        """Método de detecção de SDK: confiança alta."""
        apk = _make_apk(
            tmp_path / "sdk.apk",
            {"classes.dex": b"xxDexGuardEmulatorDetectedyy"},
        )
        res = AntiEmulatorCheck(clean_dm).detect_static("com.example.app", apk_path=apk)
        assert res["static_detected"] is True
        assert res["primary"] == "emulator_sdk"
        assert res["confidence"] == "high"

    def test_generic_strings_are_medium_confidence(self, clean_dm, tmp_path):
        """Apenas strings de fingerprint: confiança média."""
        apk = _make_apk(
            tmp_path / "strings.apk",
            {"classes.dex": b"prefix goldfish suffix"},
        )
        res = AntiEmulatorCheck(clean_dm).detect_static("com.example.app", apk_path=apk)
        assert res["static_detected"] is True
        assert res["primary"] == "emulator_strings"
        assert res["confidence"] == "medium"


class TestEvidenceHelpers:
    """Classificação de evidência (morte e linhas de logcat)."""

    def test_agent_crash_is_instrumentation_death(self, clean_dm):
        """A morte com o agente no logcat é da ferramenta, não do app."""
        logcat = {
            "available": True,
            "agent_terminated": True,
            "categories": {"frida_agent_crash": 12},
            "death": {"detected": True, "kind": "crash", "signal": "SIGSEGV"},
        }
        res = AntiEmulatorCheck(clean_dm)._classify_death(
            logcat, {"available": True, "alive_at_end": True}, False
        )
        assert res == "instrumentation_crash"

    def test_baseline_death_is_not_a_protection_signal(self, clean_dm):
        """App que morre sozinho no baseline não prova nada."""
        logcat = {"available": True, "categories": {}}
        res = AntiEmulatorCheck(clean_dm)._classify_death(
            logcat, {"available": True, "alive_at_end": False}, False
        )
        assert res == "baseline_death"

    def test_alive_process_has_no_death_classification(self, clean_dm):
        """Processo vivo: nenhuma classificação de morte."""
        logcat = {"available": True, "categories": {}}
        res = AntiEmulatorCheck(clean_dm)._classify_death(logcat, None, True)
        assert res is None

    def test_threat_lines_from_target(self, clean_dm):
        """Linha do app que acusa detecção de emulador é evidência."""
        logcat = {
            "target_lines": [
                "10-20 21:34:41.460 9507 9525 F com.example.app: emulator detected",
                "10-20 21:34:41.460 9507 9525 F com.example.app: usando token",
            ],
            "vendor_signals": [],
        }
        res = AntiEmulatorCheck._emulator_threat_lines(logcat)
        assert len(res) == 1
        assert "emulator detected" in res[0]

    def test_generic_emulator_log_is_not_threat(self, clean_dm):
        """Linha genérica sem afirmação de detecção não é evidência."""
        logcat = {
            "target_lines": [
                "10-20 21:34:41.460 9507 9525 I com.example.app: cache do emulator pronto",
            ],
            "vendor_signals": [],
        }
        res = AntiEmulatorCheck._emulator_threat_lines(logcat)
        assert res == []


class TestRunAll:
    """Consolidação do veredito de proteção e bypass."""

    def test_no_protection_is_failure(self, clean_dm, tmp_path):
        """App sem proteção anti-emulador: protection_detected=False."""
        apk = _make_apk(tmp_path / "clean.apk", {"classes.dex": b"nada"})
        res = AntiEmulatorCheck(clean_dm).run_all(
            "com.example.app",
            apk_path=apk,
            precomputed_detection={"detected": False, "error": None},
        )
        assert res["protection_detected"] is False
        assert res["bypass_successful"] is None
        assert res["device_is_emulator"] is False

    def test_protection_resisted_bypass(self, clean_dm, tmp_path):
        """Proteção existe e resiste: bypass_successful=False."""
        apk = _make_apk(
            tmp_path / "sdk.apk", {"classes.dex": b"DexGuardEmulatorDetected"}
        )
        res = AntiEmulatorCheck(clean_dm).run_all(
            "com.example.app",
            apk_path=apk,
            precomputed_detection={"detected": False, "error": None},
            precomputed_bypass={"success": False, "blocked": True, "error": None},
        )
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is False

    def test_bypass_won(self, clean_dm, tmp_path):
        """Proteção existe, mas o bypass venceu."""
        apk = _make_apk(
            tmp_path / "sdk.apk", {"classes.dex": b"DexGuardEmulatorDetected"}
        )
        res = AntiEmulatorCheck(clean_dm).run_all(
            "com.example.app",
            apk_path=apk,
            precomputed_detection={"detected": True, "error": None},
            precomputed_bypass={"success": True, "blocked": False, "error": None},
        )
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is True

    def test_detect_mode_skips_bypass(self, clean_dm, tmp_path):
        """No modo detect o bypass não roda e o motivo é registrado."""
        apk = _make_apk(
            tmp_path / "sdk.apk", {"classes.dex": b"DexGuardEmulatorDetected"}
        )
        res = AntiEmulatorCheck(clean_dm, mode="detect").run_all(
            "com.example.app",
            apk_path=apk,
            precomputed_detection={"detected": True, "error": None},
        )
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is None
        assert "detect" in res["bypass_skipped_reason"]

    def test_no_java_skips_bypass(self, clean_dm, tmp_path):
        """Com --no-java o bypass é pulado (hooks Java são essenciais)."""
        apk = _make_apk(
            tmp_path / "sdk.apk", {"classes.dex": b"DexGuardEmulatorDetected"}
        )
        res = AntiEmulatorCheck(clean_dm, no_java=True).run_all(
            "com.example.app",
            apk_path=apk,
            precomputed_detection={"detected": True, "error": None},
        )
        assert res["bypass_successful"] is None
        assert "no-java" in res["bypass_skipped_reason"]

    def test_detection_error_without_static_is_error(self, clean_dm, tmp_path):
        """Sem sinal estático e sem observação, o check é inconclusivo."""
        apk = _make_apk(tmp_path / "clean.apk", {"classes.dex": b"nada"})
        res = AntiEmulatorCheck(clean_dm).run_all(
            "com.example.app",
            apk_path=apk,
            precomputed_detection={"detected": False, "error": "spawn falhou"},
        )
        assert res["protection_detected"] is False
        assert "spawn falhou" in res["error"]

    def test_device_context_is_kept(self, clean_dm, tmp_path):
        """O contexto do dispositivo continua no resultado."""
        apk = _make_apk(tmp_path / "clean.apk", {"classes.dex": b"nada"})
        res = AntiEmulatorCheck(clean_dm).run_all(
            "com.example.app",
            apk_path=apk,
            precomputed_detection={"detected": False, "error": None},
        )
        assert res["device_environment"]["is_emulator"] is False
        assert res["device_is_emulator"] is False
