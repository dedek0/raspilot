"""Testes do bypass e do probe via módulo de instrumentação.

Cobre os caminhos dos checks de hooking e de emulador quando o bypass
(ou o probe) é executado por um módulo (APK) de hooking no dispositivo,
sem instrumentação externa.
"""

from __future__ import annotations

from typing import List
from unittest import mock

from checks.anti_emulator import AntiEmulatorCheck
from checks.anti_hooking import AntiHookingCheck
from instrumentation import ModuleConfig


class FakeXposed:
    """Gerenciador de módulo falso com respostas por fase."""

    def __init__(self, available: bool = True, phases: dict = None):
        self.available = available
        self.phases = phases or {}
        self.configs: List[ModuleConfig] = []

    def detect(self) -> dict:
        """Informa a disponibilidade do framework."""
        return {
            "available": self.available,
            "name": "Fake" if self.available else None,
            "version": "1.0" if self.available else None,
            "details": "framework fake",
        }

    def run_phase(self, config: ModuleConfig, window: int = 12,
                  keep_enabled: bool = False, interact: bool = False) -> dict:
        """Devolve a resposta programada para a fase."""
        self.configs.append(config)
        key = (config.hook, config.emulator)
        run = self.phases.get(key, {})
        return {
            "ok": not run.get("error"),
            "steps": [],
            "run": run,
            "cleanup": [],
            "error": run.get("error"),
        }

    def framework_artifacts(self, pid) -> List[str]:
        """Sem artefatos no fake."""
        return []

    def scoped_modules_for(self, package: str) -> List[dict]:
        """Sem módulos concorrentes no fake."""
        return []


def _run(alive: bool = True, evidence=None, lines=None) -> dict:
    """Monta o resultado de uma fase do módulo."""
    return {
        "pid": 4242,
        "app_alive_at_end": alive,
        "died_after": None if alive else 3,
        "evidence": evidence or [],
        "lines": lines or [],
        "neutralized": [e for e in (evidence or []) if e["kind"] == "neutralize"],
        "observed": [e for e in (evidence or []) if e["kind"] == "observe"],
        "module_ready": True,
        "effective_config": {"pkg": "com.example.app"},
        "error": None,
    }


# ----------------------------------------------------------------------
# Anti-hooking
# ----------------------------------------------------------------------
def test_module_available_depende_do_metodo(clean_dm):
    """Com o método ``frida`` o módulo nunca é usado."""
    manager = FakeXposed()
    check = AntiHookingCheck(clean_dm, method="frida", xposed=manager)
    assert check.module_available() is False


def test_module_available_exige_framework(clean_dm):
    """Sem framework no dispositivo o módulo não está disponível."""
    check = AntiHookingCheck(
        clean_dm, method="auto", xposed=FakeXposed(available=False)
    )
    assert check.module_available() is False


def test_module_available_com_framework(clean_dm):
    """Com framework disponível o módulo pode ser usado."""
    check = AntiHookingCheck(clean_dm, method="auto", xposed=FakeXposed())
    assert check.module_available() is True


def test_observacao_modulo_registra_checagens(clean_dm):
    """A observação via módulo registra as checagens vistas pelo app."""
    manager = FakeXposed(phases={
        ("observe", "off"): _run(evidence=[
            {"kind": "observe", "channel": "hook", "method": "Class.forName",
             "detail": "de.robv.android.xposed.XposedBridge"},
        ]),
    })
    check = AntiHookingCheck(clean_dm, method="module", xposed=manager)
    result = check.observe_with_module("com.example.app")
    assert result["detection_methods_found"]
    assert "de.robv.android.xposed.XposedBridge" in result["detection_methods_found"][0]


def test_observacao_modulo_e_reaproveitada(clean_dm):
    """A segunda consulta não repete a fase no dispositivo."""
    manager = FakeXposed(phases={
        ("observe", "off"): _run(evidence=[
            {"kind": "observe", "channel": "hook", "method": "File.exists",
             "detail": "/data/adb/xposed"},
        ]),
    })
    check = AntiHookingCheck(clean_dm, method="module", xposed=manager)
    check.observe_with_module("com.example.app")
    check.observe_with_module("com.example.app")
    assert len(manager.configs) == 1


def test_bypass_modulo_com_app_vivo(clean_dm):
    """App vivo com o framework ativo: o bypass venceu."""
    manager = FakeXposed(phases={
        ("observe", "off"): _run(),
        ("bypass", "off"): _run(evidence=[
            {"kind": "neutralize", "channel": "hook", "method": "Class.forName",
             "detail": "de.robv.android.xposed.XposedBridge"},
        ]),
    })
    check = AntiHookingCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_bypass("com.example.app")
    assert result["success"] is True
    assert result["blocked"] is False
    assert result["method"] == "module"
    assert result["neutralized"]


def test_bypass_modulo_com_app_morto(clean_dm):
    """App encerrado durante o bypass: a proteção resistiu."""
    manager = FakeXposed(phases={
        ("observe", "off"): _run(),
        ("bypass", "off"): _run(alive=False),
    })
    check = AntiHookingCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_bypass("com.example.app")
    assert result["success"] is False
    assert result["app_alive_at_end"] is False


def test_bypass_modulo_sem_gerenciador(clean_dm):
    """Sem gerenciador o bypass do módulo é um erro explícito."""
    check = AntiHookingCheck(clean_dm, method="module", xposed=None)
    result = check.attempt_module_bypass("com.example.app")
    assert result["success"] is False
    assert result["error"]


def test_run_all_usa_modulo_no_bypass(clean_dm):
    """O run_all delega o bypass ao módulo quando ele está disponível.

    Com evidência de neutralização e app vivo, o bypass vence — a
    delegação e o veredito são verificados juntos.
    """
    manager = FakeXposed(phases={
        ("observe", "off"): _run(),
        ("bypass", "off"): _run(evidence=[
            {"kind": "neutralize", "channel": "hook", "method": "File.exists",
             "detail": "/data/local/tmp/frida-server -> false"},
        ]),
    })
    check = AntiHookingCheck(clean_dm, method="module", xposed=manager)
    with mock.patch.object(
        AntiHookingCheck, "detect_static", return_value={
            "static_detected": True, "types": ["xposed"], "primary": "xposed",
            "evidence": ["[xposed] classe XposedBridge"],
        }
    ):
        result = check.run_all("com.example.app", window=1)
    assert result["bypass_method"] == "module"
    assert result["bypass_successful"] is True


def test_run_all_modulo_sem_evidencia_e_inconclusivo(clean_dm):
    """App vivo mas nada observado/neutralizado => inconclusivo, não True.

    Regrava o cenário do falso positivo: módulo carregado, app vivo ao
    fim da janela, zero checagens exercitadas — o veredito não pode ser
    'bypass venceu'.
    """
    manager = FakeXposed(phases={
        ("observe", "off"): _run(),
        ("bypass", "off"): _run(),
    })
    check = AntiHookingCheck(clean_dm, method="module", xposed=manager)
    with mock.patch.object(
        AntiHookingCheck, "detect_static", return_value={
            "static_detected": True, "types": ["xposed"], "primary": "xposed",
            "evidence": ["[xposed] classe XposedBridge"],
        }
    ):
        result = check.run_all("com.example.app", window=1)
    assert result["bypass_method"] == "module"
    assert result["bypass_successful"] is None
    assert "não exercitado" in result["bypass_skipped_reason"]


# ----------------------------------------------------------------------
# Anti-emulador
# ----------------------------------------------------------------------
def test_probe_modulo_separa_canais(clean_dm):
    """As consultas do app são separadas em decisivas e secundárias."""
    manager = FakeXposed(phases={
        ("bypass", "probe"): _run(evidence=[
            {"kind": "neutralize", "channel": "emulator:decisive",
             "method": "SystemProperties.get", "detail": "ro.kernel.qemu=1"},
            {"kind": "neutralize", "channel": "emulator:secondary",
             "method": "TelephonyManager.getNetworkOperatorName", "detail": "Android"},
            {"kind": "spoof", "channel": "emulator:spoof", "method": "Build.MODEL",
             "detail": "sdk_gphone64_x86_64"},
        ]),
    })
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_probe("com.example.app", window=1)
    assert result["detected"] is True
    assert result["channels"]["decisive"]
    assert result["channels"]["secondary"]
    # O spoof do módulo não é uma consulta do app.
    assert not any("Build.MODEL" in item for item in result["detection_methods_found"])


def test_probe_modulo_sem_reacao(clean_dm):
    """App que não reage ao emulador não é detecção."""
    manager = FakeXposed(phases={
        ("bypass", "probe"): _run(evidence=[
            {"kind": "neutralize", "channel": "emulator:secondary",
             "method": "TelephonyManager.getNetworkOperatorName", "detail": "Android"},
        ]),
    })
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_probe("com.example.app", window=1)
    assert result["detected"] is False
    assert result["weak_signals"]


def test_bypass_emulador_modulo_com_app_vivo(clean_dm):
    """Com os artefatos ocultos e o app vivo, o bypass venceu."""
    manager = FakeXposed(phases={
        ("bypass", "mask"): _run(evidence=[
            {"kind": "neutralize", "channel": "emulator:decisive",
             "method": "File.exists", "detail": "/dev/qemu_pipe (oculto)"},
        ]),
    })
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_bypass("com.example.app", window=1)
    assert result["success"] is True
    assert result["masked_channels"]
    assert result["coverage"]["not_covered"]


def test_bypass_emulador_modulo_com_app_morto(clean_dm):
    """App encerrado durante o bypass: o app bloqueou a auditoria."""
    manager = FakeXposed(phases={("bypass", "mask"): _run(alive=False)})
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_bypass("com.example.app", window=1)
    assert result["success"] is False
    assert result["app_alive_at_end"] is False


def test_bypass_emulador_modulo_sem_evidencia_e_inconclusivo(clean_dm):
    """App vivo mas nenhuma consulta anti-emulador exercitada => None.

    Regrava o falso positivo: no device físico, sem consultas observadas
    e sem spoof, o app "sobreviver" não prova que o bypass venceu.
    """
    manager = FakeXposed(phases={("bypass", "mask"): _run()})
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_bypass("com.example.app", window=1)
    assert result["success"] is None
    assert result["blocked"] is False
    assert "não exercitado" in result["skipped_reason"]
    assert result["details"].startswith("nenhuma consulta anti-emulador")


def test_bypass_emulador_modulo_so_spoof_e_inconclusivo(clean_dm):
    """O self-report do spoof não é consulta do app.

    Antes o spoof de Build no modo mask contava como "bypass exercitado"
    e um app vivo sem nenhuma consulta era classificado como sucesso.
    """
    manager = FakeXposed(phases={
        ("bypass", "mask"): _run(evidence=[
            {"kind": "spoof", "channel": "emulator:spoof",
             "method": "Build.MODEL", "detail": "sdk_gphone64_x86_64"},
        ]),
    })
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    result = check.attempt_module_bypass("com.example.app", window=1)
    assert result["success"] is None
    assert result["exercised"] is False
    assert "não exercitado" in result["skipped_reason"]


def test_bypass_emulador_modulo_morte_pos_janela(clean_dm):
    """Morte logo após a janela (kill assíncrono) invalida o sucesso."""
    dm = mock.MagicMock()
    dm.baseline = None
    dm.is_app_alive.return_value = False  # re-checagem pós-janela
    dm.capture_death_cause.return_value = {"summary": "sinal fatal", "evidence": []}
    manager = FakeXposed(phases={
        ("bypass", "mask"): _run(evidence=[
            {"kind": "neutralize", "channel": "emulator:decisive",
             "method": "File.exists", "detail": "/dev/qemu_pipe (oculto)"},
        ]),
    })
    check = AntiEmulatorCheck(dm, method="module", xposed=manager)
    result = check.attempt_module_bypass("com.example.app", window=1)
    assert result["post_window_death"] is True
    assert result["app_alive_at_end"] is False
    assert result["success"] is False


def test_run_all_emulador_modulo_sem_evidencia_vira_skip(clean_dm):
    """run_all mapeia success=None do módulo para bypass_successful=None."""
    manager = FakeXposed(phases={
        ("bypass", "probe"): _run(evidence=[
            {"kind": "neutralize", "channel": "emulator:secondary",
             "method": "TelephonyManager.getNetworkOperatorName", "detail": "Android"},
        ]),
        ("bypass", "mask"): _run(),
    })
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    with mock.patch.object(
        AntiEmulatorCheck, "detect_static", return_value={
            "static_detected": True, "types": ["emulator_sdk"], "primary": "emulator_sdk",
            "evidence": ["[emulator_sdk] isProbablyAnEmulator"],
        }
    ), mock.patch.object(
        AntiEmulatorCheck, "classify_device",
        return_value={"is_emulator": False, "emulator_type": None, "checks": {}, "confidence": "high"},
    ):
        result = check.run_all("com.example.app", window=1)
    assert result["protection_detected"] is True
    assert result["bypass_successful"] is None
    assert "não exercitado" in result["bypass_skipped_reason"]


def test_run_all_emulador_so_canal_secundario_vira_skip(clean_dm):
    """Consulta apenas a canais secundários não comprova bypass.

    O app pode ler telefonia ou android_id por motivo legítimo. Se a
    proteção só foi vista no APK e o probe dinâmico não a observou, o
    bypass não pode ser creditado como vencido apenas por esses sinais.
    """
    secondary = {"kind": "neutralize", "channel": "emulator:secondary",
                 "method": "TelephonyManager.getNetworkOperatorName",
                 "detail": "Android"}
    manager = FakeXposed(phases={
        ("bypass", "probe"): _run(evidence=[secondary]),
        ("bypass", "mask"): _run(evidence=[secondary]),
    })
    check = AntiEmulatorCheck(clean_dm, method="module", xposed=manager)
    with mock.patch.object(
        AntiEmulatorCheck, "detect_static", return_value={
            "static_detected": True, "types": ["emulator_sdk"],
            "primary": "emulator_sdk",
            "evidence": ["[emulator_sdk] isProbablyAnEmulator"],
        }
    ), mock.patch.object(
        AntiEmulatorCheck, "classify_device",
        return_value={"is_emulator": False, "emulator_type": None,
                      "checks": {}, "confidence": "high"},
    ):
        result = check.run_all("com.example.app", window=1)
    assert result["protection_detected"] is True
    assert result["bypass_successful"] is None
    assert "canal decisivo" in result["bypass_skipped_reason"]
