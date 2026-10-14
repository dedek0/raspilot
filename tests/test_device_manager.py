"""Testes do DeviceManager — parsing de output ADB e helpers.

Todos os testes usam mocks de ``subprocess.run``/``_run``: nenhum
dispositivo é necessário.
"""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest

from device_manager import (
    DeviceConnectionError,
    DeviceManager,
    FridaSetupError,
)


def _proc(stdout="", stderr="", returncode=0):
    """Monta um CompletedProcess fake."""
    return subprocess.CompletedProcess(
        args=["adb"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestListDevices:
    """Parsing de ``adb devices``."""

    def test_parses_devices_output(self):
        """Extrai pares (serial, state) ignorando cabeçalho/linhas do daemon."""
        dm = DeviceManager()
        output = (
            "List of devices attached\n"
            "emulator-5554\tdevice\n"
            "R58M12345\tunauthorized\n"
            "* daemon started successfully\n"
            "192.168.0.10:5555\toffline\n"
        )
        with mock.patch.object(dm, "_run", return_value=output):
            devices = dm._list_devices()
        assert devices == [
            ("emulator-5554", "device"),
            ("R58M12345", "unauthorized"),
            ("192.168.0.10:5555", "offline"),
        ]

    def test_empty_devices(self):
        """Sem dispositivos retorna lista vazia."""
        dm = DeviceManager()
        with mock.patch.object(
            dm, "_run", return_value="List of devices attached\n"
        ):
            assert dm._list_devices() == []

    def test_error_returns_empty(self):
        """Falha do comando adb não propaga exceção neste helper."""
        dm = DeviceManager()
        with mock.patch.object(
            dm, "_run", side_effect=DeviceConnectionError("boom")
        ):
            assert dm._list_devices() == []


class TestConnectAdb:
    """Fluxo de conexão (USB e Wi-Fi) com timeout."""

    def test_usb_connect_success(self):
        """Dispositivo em estado 'device' conecta sem wifi_target."""
        dm = DeviceManager()
        with mock.patch.object(dm, "_run", return_value="ok"), \
             mock.patch.object(
                 dm, "_list_devices", return_value=[("emulator-5554", "device")]
             ):
            assert dm.connect_adb() is True
            assert dm.device_id == "emulator-5554"

    def test_wifi_connect_calls_adb_connect(self):
        """wifi_target dispara `adb connect ip:porta`."""
        dm = DeviceManager(wifi_target="192.168.0.10:5555")
        calls = []

        def fake_run(cmd, timeout=20, check=True):
            calls.append(cmd)
            return "ok"

        with mock.patch.object(dm, "_run", side_effect=fake_run), \
             mock.patch.object(
                 dm, "_list_devices", return_value=[("192.168.0.10:5555", "device")]
             ):
            assert dm.connect_adb() is True
        assert ["adb", "connect", "192.168.0.10:5555"] in calls

    def test_unauthorized_raises(self):
        """Estado 'unauthorized' gera erro instrutivo."""
        dm = DeviceManager()
        with mock.patch.object(dm, "_run", return_value="ok"), \
             mock.patch.object(
                 dm, "_list_devices", return_value=[("R58M", "unauthorized")]
             ):
            with pytest.raises(DeviceConnectionError, match="AUNAUTHORIZED"):
                dm.connect_adb()

    def test_timeout_raises(self):
        """Sem dispositivo pronto em 15s levanta DeviceConnectionError."""
        dm = DeviceManager()
        with mock.patch.object(dm, "_run", return_value="ok"), \
             mock.patch.object(dm, "_list_devices", return_value=[]), \
             mock.patch("device_manager.time.sleep"):  # não espera de verdade
            with pytest.raises(DeviceConnectionError, match="não ficou pronto"):
                dm.connect_adb()


class TestDeviceInfo:
    """`get_device_info` e `_detect_abi`."""

    def test_detect_abi_arm64(self):
        """getprop ro.product.cpu.abi retorna arm64-v8a."""
        dm = DeviceManager()
        with mock.patch.object(dm, "_getprop", return_value="arm64-v8a"):
            assert dm._detect_abi() == "arm64-v8a"

    def test_detect_abi_unknown_fallback(self):
        """ABI desconhecida cai no fallback armeabi-v7a."""
        dm = DeviceManager()
        with mock.patch.object(dm, "_getprop", return_value="mips"):
            assert dm._detect_abi() == "armeabi-v7a"

    def test_get_device_info_fields(self):
        """Retorna todos os campos esperados."""
        dm = DeviceManager(device_id="SER1")
        props = {
            "ro.product.model": "SM-G991B",
            "ro.build.version.release": "14",
            "ro.build.version.sdk": "34",
        }
        with mock.patch.object(dm, "_getprop", side_effect=lambda p: props.get(p, "")), \
             mock.patch.object(dm, "_detect_abi", return_value="arm64-v8a"), \
             mock.patch.object(dm, "verify_root_access", return_value=False):
            info = dm.get_device_info()
        assert info["serial"] == "SER1"
        assert info["model"] == "SM-G991B"
        assert info["android_version"] == "14"
        assert info["sdk"] == "34"
        assert info["abi"] == "arm64-v8a"
        assert info["is_rooted_shell"] is False

    def test_verify_root_access_true(self):
        """shell id com uid=0(root) indica root."""
        dm = DeviceManager()
        with mock.patch.object(
            dm, "_run_adb", return_value="uid=0(root) gid=0(root) groups=0(root)"
        ):
            assert dm.verify_root_access() is True

    def test_verify_root_access_false(self):
        """shell id de app user não indica root."""
        dm = DeviceManager()
        with mock.patch.object(
            dm, "_run_adb", return_value="uid=2000(shell) gid=2000(shell)"
        ):
            assert dm.verify_root_access() is False


class TestRunShell:
    """`run_shell` nunca lança exceção."""

    def test_success(self, tmp_path):
        """Comando ok devolve stdout limpo."""
        dm = DeviceManager()
        with mock.patch(
            "device_manager.subprocess.run", return_value=_proc(stdout="hello\n")
        ):
            res = dm.run_shell("echo hello")
        assert res == {"ok": True, "rc": 0, "stdout": "hello", "stderr": ""}

    def test_timeout_is_captured(self):
        """Timeout vira dict estruturado, sem exceção."""
        dm = DeviceManager()
        with mock.patch(
            "device_manager.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="adb", timeout=1),
        ):
            res = dm.run_shell("sleep 999", timeout=1)
        assert res["ok"] is False
        assert "timeout" in res["stderr"]

    def test_includes_device_serial(self):
        """Serial é injetado como `adb -s <serial> shell ...`."""
        dm = DeviceManager(device_id="SER1")
        seen = {}

        def fake_run(cmd, capture_output=True, text=True, timeout=20, check=False):
            seen["cmd"] = cmd
            return _proc(stdout="ok")

        with mock.patch("device_manager.subprocess.run", side_effect=fake_run):
            dm.run_shell("id")
        assert seen["cmd"][:4] == ["adb", "-s", "SER1", "shell"]


class TestFridaHelpers:
    """Helpers do frida-server (sem download real)."""

    def test_frida_binary_name_matches_local_version(self):
        """Nome do binário usa versão local do frida + ABI."""
        dm = DeviceManager()
        import frida

        with mock.patch.object(dm, "_detect_abi", return_value="arm64-v8a"):
            assert dm._frida_binary_name() == (
                f"frida-server-{frida.__version__}-android-arm64-v8a"
            )

    def test_missing_frida_package_raises(self):
        """Sem pacote frida instalado o erro é instrutivo."""
        dm = DeviceManager()
        with mock.patch("device_manager.frida", None):
            with pytest.raises(FridaSetupError, match="pip install"):
                dm._local_frida_version()

    def test_remove_frida_server_never_raises(self):
        """Cleanup não propaga exceção."""
        dm = DeviceManager()
        with mock.patch.object(
            dm, "_run_adb", side_effect=DeviceConnectionError("offline")
        ):
            dm.remove_frida_server()  # não deve levantar
