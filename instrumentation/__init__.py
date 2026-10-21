"""RASPilot — Módulo de instrumentação (APK de hooking).

Pacote que reúne o módulo usado pelos checks de anti-hooking e de
anti-emulador: o lado Python (:mod:`instrumentation.manager`) e os
fontes do APK Android (:mod:`instrumentation.xposed`).

O módulo é compilado, instalado e limitado ao pacote alvo auditado;
o app é então executado **sem** instrumentação externa, com o framework
de hooking do próprio dispositivo.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from instrumentation.manager import (
    MODULE_PACKAGE,
    ModuleConfig,
    XposedError,
    XposedManager,
)

__all__ = [
    "MODULE_PACKAGE",
    "ModuleConfig",
    "XposedError",
    "XposedManager",
]
