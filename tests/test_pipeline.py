"""Teste de integração do pipeline completo do RASPilot.

Executa ``main.main()`` com um ``DeviceManager`` inteiramente mockado
e valida o relatório gerado de ponta a ponta — sem dispositivo real.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

import checks.anti_emulator as anti_emulator_mod
import checks.anti_frida as anti_frida_mod
import checks.anti_hooking as anti_hooking_mod
import checks.combined as combined_mod
import checks.ssl_pinning as ssl_pinning_mod
import main as mainmod
from device_manager import DeviceManager

SHELL = {
    "pm list packages 2>/dev/null | grep -i magisk": "package:com.topjohnwu.magisk",
    "ls /data/adb/magisk 2>/dev/null": "magisk64",
    "pm list packages 2>/dev/null": "package:com.topjohnwu.magisk\npackage:com.example.app",
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ps -A 2>/dev/null | grep -i frida": "root 999 1 0 0 0 S frida-server",
    "netstat -tlnp 2>/dev/null": "tcp 0 0 127.0.0.1:27042 0.0.0.0:* LISTEN",
    "cat /proc/1234/task": "com.example.app\nJit thread pool\n",
    "ro.kernel.qemu": "",
    "ro.hardware": "qcom",
    "ro.product.model": "Pixel 7",
    "ro.product.manufacturer": "Google",
    "ro.build.fingerprint": "google/panther/panther:14",
    "ro.product.device": "panther",
    "dumpsys sensorservice": "  - a\n  - b\n  - c\n",
    "settings get secure bluetooth_address": "a4:cf:12:00:00:01",
    "&& echo alive": "alive",
}


def fake_shell(self, command, timeout=20):
    """Substitui ``DeviceManager.run_shell`` com respostas canned."""
    for key, value in SHELL.items():
        if key in command:
            return {"ok": True, "rc": 0, "stdout": value, "stderr": ""}
    return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}


class FakeScript:
    """Script Frida fake com mensagens pré-carregadas."""

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


class FakeSession:
    """Sessão Frida fake (detecção vazia; bypass com evidência)."""

    def enumerate_modules(self):
        return []

    def create_script(self, source, **kwargs):
        messages = []
        if "CertificatePinner" in source or "ssl_verify_result" in source:
            messages.extend([
                {"type": "send", "payload": {
                    "type": "ssl-bypass",
                    "message": "OkHttp CertificatePinner.check bypass (api.x.com)",
                }},
                {"type": "send", "payload": {"type": "ssl-bypass-host", "host": "api.x.com"}},
            ])
        if "var Java = bridge;" in source:
            # A camada Java e instalada de forma adiada: o script
            # sinaliza a prontidao depois do carregamento.
            messages.append({"type": "send", "payload": {
                "type": "raspilot-java-ready", "label": "fake"}})
        return FakeScript(messages)

    def detach(self):
        pass


@pytest.fixture
def fast_windows():
    """Encurta as janelas de observação (sleeps) dos checks."""
    with mock.patch.object(anti_frida_mod, "OBSERVATION_POLL_INTERVAL", 0.0), \
         mock.patch.object(anti_hooking_mod, "OBSERVATION_POLL_INTERVAL", 0.0), \
         mock.patch.object(anti_emulator_mod, "OBSERVATION_POLL_INTERVAL", 0.0), \
         mock.patch.object(ssl_pinning_mod, "OBSERVATION_POLL_INTERVAL", 0.0), \
         mock.patch.object(combined_mod, "OBSERVATION_POLL_INTERVAL", 0.0):
        yield


@pytest.fixture
def runtime_mocks():
    """Isola baseline/logcat (sem adb real) nos testes de pipeline."""
    with mock.patch.object(DeviceManager, "start_logcat_capture", return_value=True), \
         mock.patch.object(DeviceManager, "stop_logcat_capture", return_value=None), \
         mock.patch.object(
             DeviceManager, "run_app_baseline",
             return_value={"available": False, "reason": "mock"},
         ), \
         mock.patch.object(DeviceManager, "logcat_mark", return_value=0), \
         mock.patch.object(DeviceManager, "logcat_since", return_value=[]), \
         mock.patch.object(DeviceManager, "is_app_alive", return_value=True), \
         mock.patch.object(
             DeviceManager, "wait_for_app_ready", return_value=True
         ):
        yield


def test_pipeline_end_to_end(tmp_path, fast_windows, runtime_mocks, capsys):
    """Pipeline completo: roda, gera relatórios e retorna 0."""
    detection = {
        "pinning_detected": True,
        "type": "okhttp",
        "evidence": ["[okhttp] CertificatePinner"],
    }

    with mock.patch.object(DeviceManager, "connect_adb", return_value=True), \
         mock.patch.object(DeviceManager, "get_device_info", return_value={
             "serial": "SER1", "model": "Pixel 7", "android_version": "14",
             "sdk": "34", "abi": "arm64-v8a", "is_rooted_shell": False,
         }), \
         mock.patch.object(DeviceManager, "setup_frida_server", return_value=True), \
         mock.patch.object(DeviceManager, "run_shell", fake_shell), \
         mock.patch.object(DeviceManager, "spawn_app", return_value=FakeSession()), \
         mock.patch.object(DeviceManager, "get_app_pid", return_value=1234), \
         mock.patch.object(DeviceManager, "remove_frida_server", return_value=None), \
         mock.patch.object(DeviceManager, "_detect_abi", return_value="arm64-v8a"), \
         mock.patch.object(
             ssl_pinning_mod.SSLPinningCheck, "detect_pinning", return_value=detection
         ), \
         mock.patch.object(
             ssl_pinning_mod.SSLPinningCheck, "_pull_apk", return_value=[]
         ):
        rc = mainmod.main([
            "--package", "com.example.app",
            "--output-dir", str(tmp_path),
        ])

    assert rc == 0

    jsons = list(tmp_path.glob("*.json"))
    htmls = list(tmp_path.glob("*.html"))
    assert len(jsons) == 1 and len(htmls) == 1

    doc = json.loads(jsons[0].read_text(encoding="utf-8"))
    assert doc["metadata"]["tool_name"] == "RASPilot"
    assert doc["metadata"]["package"] == "com.example.app"
    # Cenário mockado: root=True, frida vulnerável, sem anti-hook, pinning bypassado.
    assert doc["summary"]["anti_root"]["status"] == "FALHOU"
    assert doc["summary"]["anti_frida"]["status"] == "FALHOU"
    assert doc["summary"]["ssl_pinning"]["status"] == "FALHOU"
    # Cenário mockado: sem APK e sem reação do app ao ambiente emulado,
    # o check não encontra proteção anti-emulador.
    assert doc["summary"]["anti_emulator"]["status"] == "FALHOU"
    assert doc["summary"]["anti_hooking"]["status"] == "FALHOU"

    html = htmls[0].read_text(encoding="utf-8")
    assert "RASPilot" in html

    out = capsys.readouterr().out
    assert "RASPilot — Relatório de Auditoria RASP" in out


def test_pipeline_skip_marks_skip(tmp_path, fast_windows, runtime_mocks):
    """Checks pulados aparecem como SKIP no relatório."""
    with mock.patch.object(DeviceManager, "connect_adb", return_value=True), \
         mock.patch.object(DeviceManager, "get_device_info", return_value={
             "serial": "S", "model": "m", "android_version": "14",
             "sdk": "34", "abi": "arm64-v8a", "is_rooted_shell": False,
         }), \
         mock.patch.object(DeviceManager, "setup_frida_server", return_value=True), \
         mock.patch.object(DeviceManager, "run_shell", fake_shell), \
         mock.patch.object(DeviceManager, "spawn_app", return_value=FakeSession()), \
         mock.patch.object(DeviceManager, "get_app_pid", return_value=1234), \
         mock.patch.object(DeviceManager, "remove_frida_server", return_value=None), \
         mock.patch.object(DeviceManager, "_detect_abi", return_value="arm64-v8a"), \
         mock.patch.object(
             ssl_pinning_mod.SSLPinningCheck, "detect_pinning",
             return_value={"pinning_detected": False, "type": "none", "evidence": []},
         ):
        rc = mainmod.main([
            "--package", "com.example.app",
            "--output-dir", str(tmp_path),
            "--skip", "anti_root", "anti_emulator", "anti_hooking",
        ])
    assert rc == 0
    doc = json.loads(list(tmp_path.glob("*.json"))[0].read_text(encoding="utf-8"))
    assert doc["summary"]["anti_root"]["status"] == "SKIP"
    assert doc["summary"]["anti_emulator"]["status"] == "SKIP"
    assert doc["summary"]["anti_hooking"]["status"] == "SKIP"
    assert doc["summary"]["anti_frida"]["status"] == "FALHOU"
    assert doc["summary"]["ssl_pinning"]["status"] == "N/A"


def test_pipeline_check_failure_does_not_abort(tmp_path, fast_windows, runtime_mocks):
    """Falha em um check marca ERROR e o pipeline continua."""
    with mock.patch.object(DeviceManager, "connect_adb", return_value=True), \
         mock.patch.object(DeviceManager, "get_device_info", return_value={
             "serial": "S", "model": "m", "android_version": "14",
             "sdk": "34", "abi": "arm64-v8a", "is_rooted_shell": False,
         }), \
         mock.patch.object(DeviceManager, "setup_frida_server", return_value=True), \
         mock.patch.object(DeviceManager, "run_shell", fake_shell), \
         mock.patch.object(DeviceManager, "spawn_app", return_value=FakeSession()), \
         mock.patch.object(DeviceManager, "get_app_pid", return_value=1234), \
         mock.patch.object(DeviceManager, "remove_frida_server", return_value=None), \
         mock.patch.object(DeviceManager, "_detect_abi", return_value="arm64-v8a"), \
         mock.patch(
             "checks.anti_emulator.AntiEmulatorCheck.run_all",
             side_effect=RuntimeError("boom"),
         ), \
         mock.patch.object(
             ssl_pinning_mod.SSLPinningCheck, "detect_pinning",
             return_value={"pinning_detected": False, "type": "none", "evidence": []},
         ):
        rc = mainmod.main([
            "--package", "com.example.app",
            "--output-dir", str(tmp_path),
        ])
    assert rc == 0
    doc = json.loads(list(tmp_path.glob("*.json"))[0].read_text(encoding="utf-8"))
    assert doc["summary"]["anti_emulator"]["status"] == "ERROR"
    assert doc["summary"]["anti_root"]["status"] == "FALHOU"
