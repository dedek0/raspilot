"""Fixtures compartilhadas da suíte de testes do RASPilot.

Fornece um ``DeviceManager`` falso (``FakeShellDM``) que responde
comandos shell a partir de um mapping, permitindo testar cada check
sem um dispositivo real.
"""

from __future__ import annotations

from typing import Dict, Union

import pytest

from checks.anti_emulator import AntiEmulatorCheck
from checks.anti_frida import AntiFridaCheck
from checks.anti_root import AntiRootCheck
from checks.ssl_pinning import SSLPinningCheck

ShellResponse = Union[str, Dict[str, object]]


class FakeShellDM:
    """Substituto do ``DeviceManager`` para testes de checks.

    Args:
        mapping: ``{trecho_do_comando: resposta}`` — a resposta pode ser
            uma string (stdout com rc=0) ou um dict completo
            ``{'ok', 'rc', 'stdout', 'stderr'}``.
        abi: ABI devolvida por ``_detect_abi``.
    """

    def __init__(self, mapping: Dict[str, ShellResponse], abi: str = "arm64-v8a"):
        self.mapping = mapping
        self._abi = abi

    def _detect_abi(self) -> str:
        """Retorna a ABI configurada."""
        return self._abi

    def run_shell(self, command: str, timeout: int = 20) -> dict:
        """Simula ``DeviceManager.run_shell`` a partir do mapping.

        Args:
            command: Comando shell executado pelo check.
            timeout: Ignorado nos testes.

        Returns:
            Dict estruturado ``{'ok', 'rc', 'stdout', 'stderr'}``.
        """
        for key, value in self.mapping.items():
            if key in command:
                if isinstance(value, dict):
                    return value
                return {"ok": True, "rc": 0, "stdout": value, "stderr": ""}
        return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

    def run_shell_root(self, command: str, timeout: int = 20) -> dict:
        """Simula ``DeviceManager.run_shell_root`` (sem su real nos testes)."""
        return self.run_shell(command, timeout=timeout)

    def is_app_alive(self, pid: int) -> bool:
        """Simula ``DeviceManager.is_app_alive``.

        Args:
            pid: Ignorado nos testes.

        Returns:
            Valor de ``mapping['__alive__']`` (default True).
        """
        return bool(self.mapping.get("__alive__", True))


@pytest.fixture
def fake_dm_factory():
    """Factory fixture: ``fake_dm_factory(mapping, abi) -> FakeShellDM``."""
    return FakeShellDM


# Cenários shell pré-montados reutilizados entre os testes.
CLEAN_PHYSICAL_SHELL: Dict[str, ShellResponse] = {
    "pm list packages 2>/dev/null": "package:com.android.chrome\npackage:com.google.android.gms",
    "ro.debuggable": "0",
    "ro.secure": "1",
    "service.adb.root": "",
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.flash.locked": "1",
    "mount 2>/dev/null | grep ' /system '": "/dev/root /system ext4 ro,seclabel,relatime",
    "which busybox": "",
    "ro.kernel.qemu": "",
    "ro.boot.qemu": "",
    "ro.hardware": "qcom",
    "ro.product.model": "Pixel 7",
    "ro.product.manufacturer": "Google",
    "ro.build.fingerprint": "google/panther/panther:14/UP1A.231005.007:user/release-keys",
    "ro.product.device": "panther",
    "dumpsys sensorservice": "  - LSM6DSO Accelerometer\n  - LSM6DSO Gyroscope\n  - AK09918 Magnetometer\n  - Barometer\n",
    "settings get secure bluetooth_address": "a4:cf:12:d3:55:01",
    "ps -A 2>/dev/null": "u0_a123 1234 500 0 0 0 S com.example.app",
}

MAGISK_SHELL: Dict[str, ShellResponse] = {
    **CLEAN_PHYSICAL_SHELL,
    "pm list packages 2>/dev/null | grep -i magisk": "package:com.topjohnwu.magisk",
    "ls /data/adb/magisk 2>/dev/null": "magisk64\nmagiskinit",
    "ls /sbin/.magisk 2>/dev/null": ".magisk",
    "which magisk 2>/dev/null": "/sbin/magisk",
    "pm list packages 2>/dev/null": "package:com.topjohnwu.magisk\npackage:com.example.app",
}

AVD_SHELL: Dict[str, ShellResponse] = {
    "ro.kernel.qemu": "1",
    "ro.boot.qemu": "1",
    "ro.hardware": "ranchu",
    "ro.product.model": "sdk_gphone64_x86_64",
    "ro.product.manufacturer": "Google",
    "ro.build.fingerprint": "google/sdk_gphone64_x86_64/emu64xa:14",
    "ro.product.device": "emu64xa",
    "ls /dev/qemu_pipe 2>/dev/null": "/dev/qemu_pipe",
    "dumpsys sensorservice": "  - AOSP Accelerometer\n",
    "settings get secure bluetooth_address": "02:00:00:00:00:00",
    "pm list packages 2>/dev/null": "package:com.android.chrome",
}


@pytest.fixture
def clean_dm() -> FakeShellDM:
    """DeviceManager fake: dispositivo físico limpo."""
    return FakeShellDM(CLEAN_PHYSICAL_SHELL)


@pytest.fixture
def magisk_dm() -> FakeShellDM:
    """DeviceManager fake: dispositivo rooteado com Magisk."""
    return FakeShellDM(MAGISK_SHELL)


@pytest.fixture
def avd_dm() -> FakeShellDM:
    """DeviceManager fake: AVD QEMU x86_64."""
    return FakeShellDM(AVD_SHELL, abi="x86_64")


@pytest.fixture
def anti_root(clean_dm):
    """AntiRootCheck sobre dispositivo limpo."""
    return AntiRootCheck(clean_dm)


@pytest.fixture
def anti_frida(clean_dm):
    """AntiFridaCheck sobre dispositivo limpo."""
    return AntiFridaCheck(clean_dm)


@pytest.fixture
def anti_emulator(clean_dm):
    """AntiEmulatorCheck sobre dispositivo limpo."""
    return AntiEmulatorCheck(clean_dm)


@pytest.fixture
def ssl_pinning(clean_dm):
    """SSLPinningCheck sobre dispositivo limpo."""
    return SSLPinningCheck(clean_dm)
