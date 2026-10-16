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
            "ro.product.model": "Pixel 7",
            "ro.build.version.release": "14",
            "ro.build.version.sdk": "34",
        }
        with mock.patch.object(dm, "_getprop", side_effect=lambda p: props.get(p, "")), \
             mock.patch.object(dm, "_detect_abi", return_value="arm64-v8a"), \
             mock.patch.object(dm, "verify_root_access", return_value=False), \
             mock.patch.object(dm, "has_su_access", return_value=True):
            info = dm.get_device_info()
        assert info["serial"] == "SER1"
        assert info["model"] == "Pixel 7"
        assert info["android_version"] == "14"
        assert info["sdk"] == "34"
        assert info["abi"] == "arm64-v8a"
        assert info["is_rooted_shell"] is False
        assert info["root_via_su"] is True

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

    def test_run_shell_root_wraps_with_su_when_available(self):
        """Com root via su, o comando é elevado em `su -c`."""
        dm = DeviceManager()
        with mock.patch.object(dm, "has_su_access", return_value=True), \
             mock.patch.object(dm, "run_shell", return_value={"ok": True}) as rs:
            dm.run_shell_root("ls /data/adb/ap")
        assert rs.call_args[0][0].startswith("su -c '")

    def test_run_shell_root_plain_without_su(self):
        """Sem su, o comando roda como shell comum (sem elevação)."""
        dm = DeviceManager()
        with mock.patch.object(dm, "has_su_access", return_value=False), \
             mock.patch.object(dm, "run_shell", return_value={"ok": True}) as rs:
            dm.run_shell_root("id")
        rs.assert_called_once_with("id", timeout=20)


class TestCaptureDeathCause:
    """`capture_death_cause` distingue crash, kill e ausência de registro."""

    @staticmethod
    def _dm_with(mapping):
        """DeviceManager com run_shell fake respondendo por substring."""
        dm = DeviceManager()

        def fake_run_shell(command, timeout=20):
            for key, value in mapping.items():
                if key in command:
                    return {"ok": True, "rc": 0, "stdout": value, "stderr": ""}
            return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

        dm.run_shell = fake_run_shell
        return dm

    def test_detects_fatal_signal(self):
        """Sinal fatal no buffer de crash vira signal=SIGSEGV."""
        dm = self._dm_with({
            "logcat -d -b crash": (
                "01-01 00:00:00.000  1234  1234 F libc    : Fatal signal 11 "
                "(SIGSEGV), code 1, fault addr 0x0 in tid 99 (com.example.app), "
                "pid 1234 (com.example.app)\n"
            ),
        })
        res = dm.capture_death_cause(pid=1234, package="com.example.app")
        assert res["signal"] == "SIGSEGV"
        assert any("SIGSEGV" in e for e in res["evidence"])

    def test_events_kill_line(self):
        """Linha am_kill citando o alvo é registrada (sem signal)."""
        dm = self._dm_with({
            "logcat -d -b events": (
                "01-01 00:00:00.000  900  900 I am_kill : [0,1234,com.example.app,force stop]\n"
            ),
        })
        res = dm.capture_death_cause(pid=1234, package="com.example.app")
        assert res["signal"] is None
        assert any("am_kill" in e for e in res["evidence"])
        assert res["summary"] == "morte registrada em logcat"

    def test_no_external_record(self):
        """Sem nada no logcat: resumo aponta SIGKILL externo/exit_group."""
        dm = self._dm_with({})
        res = dm.capture_death_cause(pid=1234, package="com.example.app")
        assert res["evidence"] == []
        assert res["signal"] is None
        assert "sem registro externo" in res["summary"]

    def test_sigkill_from_zygote_line(self):
        """Linha do Zygote 'exited due to signal 9' vira SIGKILL."""
        dm = self._dm_with({
            "logcat -d -t 400": (
                "01-01 00:00:00.000  857  857 I Zygote  : Process 1234 "
                "exited due to signal 9 (Killed)\n"
            ),
        })
        res = dm.capture_death_cause(pid=1234, package="com.example.app")
        assert res["signal"] == "SIGKILL"
        assert "não interceptável" in res["summary"]

    def test_stale_crash_lines_are_excluded_with_pid(self):
        """Com pid, linha fatal de crash antigo (sem o pid) é ignorada."""
        dm = self._dm_with({
            "logcat -d -b crash": (
                "01-01 00:00:00.000  9999  9999 F libc : Fatal signal 6 "
                "(SIGABRT) in tid 9999 (outro.app), pid 9999 (outro.app)\n"
            ),
        })
        res = dm.capture_death_cause(pid=1234, package="com.example.app")
        assert res["signal"] is None
        assert res["evidence"] == []

    def test_crash_pid_match_requires_word(self):
        """Pid aparecendo só dentro de um endereço não conta como match."""
        dm = self._dm_with({
            "logcat -d -b crash": (
                "01-01 00:00:00.000  9  9 F libc : Fatal signal 6 (SIGABRT), "
                "fault addr 0x000000018544 in tid 9999 (outro.app), pid 9999\n"
            ),
        })
        res = dm.capture_death_cause(pid=8544, package="com.example.app")
        assert res["evidence"] == []
        assert res["signal"] is None


class TestFridaStealth:
    """Stealth do frida-server (porta não-padrão + nome opaco)."""

    def test_remote_path_is_opaque(self):
        """O path remoto não contém 'frida' (evita scan por nome)."""
        from device_manager import FRIDA_REMOTE_PATH

        assert "frida" not in FRIDA_REMOTE_PATH

    def test_port_is_not_default(self):
        """A porta do servidor não é 27042/27043 (evita port-scan)."""
        from device_manager import FRIDA_PORT

        assert FRIDA_PORT not in (27042, 27043)

    def test_kill_covers_stealth_binary(self):
        """kill_frida_server encerra também o binário stealth."""
        dm = DeviceManager()
        seen = []

        def fake_shell(command, timeout=20):
            seen.append(command)
            return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

        with mock.patch.object(dm, "run_shell", side_effect=fake_shell), \
             mock.patch.object(dm, "has_su_access", return_value=False), \
             mock.patch("device_manager.time.sleep"):
            dm.kill_frida_server()
        assert any(".lloader" in c for c in seen)

    def test_patch_renames_memfd_strings(self, tmp_path):
        """O patch renomeia as strings do memfd do agente (mesmo tamanho)."""
        src = tmp_path / "srv.bin"
        src.write_bytes(
            b"\x7fELFpad" + b"frida-agent-64.so" + b"x" + b"frida-agent-32.so"
        )
        dst = tmp_path / "out.bin"
        count = DeviceManager._patch_frida_binary(str(src), str(dst))
        data = dst.read_bytes()
        assert count == 2
        assert b"frida-agent" not in data
        assert b"libloader64_v8.so" in data
        assert b"libloader32_v7.so" in data
        # Tamanhos preservados (patch binário seguro).
        assert len(data) == src.stat().st_size


class TestFridaHelpers:
    """Helpers do frida-server (sem download real)."""

    def test_frida_binary_name_matches_local_version(self):
        """Nome do binário usa versão local do frida + arquitetura da asset."""
        dm = DeviceManager()
        import frida

        with mock.patch.object(dm, "_detect_abi", return_value="arm64-v8a"):
            assert dm._frida_binary_name() == (
                f"frida-server-{frida.__version__}-android-arm64"
            )

    def test_frida_binary_name_maps_abis(self):
        """ABIs Android são mapeadas para os nomes de asset do Frida."""
        dm = DeviceManager()
        import frida

        version = frida.__version__
        for abi, arch in (
            ("armeabi-v7a", "arm"),
            ("x86_64", "x86_64"),
        ):
            with mock.patch.object(dm, "_detect_abi", return_value=abi):
                assert dm._frida_binary_name() == (
                    f"frida-server-{version}-android-{arch}"
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

    def test_get_app_pid_falls_back_to_last_spawn(self):
        """Regressão: pid do spawn recente é usado quando o lookup falha.

        Apps com anti-debug podem sumir da lista de processos logo após o
        spawn — o RASPilot deve usar o PID devolvido pelo próprio spawn.
        """
        dm = DeviceManager(device_id="SER1")
        dm.last_spawn_pid = 4242
        with mock.patch.object(dm, "_require_frida", return_value=mock.MagicMock()), \
             mock.patch.object(dm, "_frida_device", side_effect=Exception("sumiu")):
            assert dm.get_app_pid("com.example.app") == 4242
