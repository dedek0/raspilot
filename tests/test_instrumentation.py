"""Testes do gerenciador do módulo de instrumentação (APK Xposed)."""

from __future__ import annotations

import os
from typing import Dict, Union

from instrumentation.manager import (
    MODULE_PACKAGE,
    ModuleConfig,
    XposedManager,
    _failed_entries,
    _framework_name,
    _parse_ready,
    _parse_status,
    parse_evidence,
    partition_evidence,
    probe_evidence,
)

ShellResponse = Union[str, Dict[str, object]]


class FakeDM:
    """DeviceManager fake com respostas de shell por trecho de comando."""

    def __init__(self, mapping: Dict[str, ShellResponse]):
        self.mapping = mapping
        self.commands = []

    def run_shell(self, command: str, timeout: int = 20) -> dict:
        """Simula ``DeviceManager.run_shell``."""
        self.commands.append(command)
        return self._match(command)

    def run_shell_root(self, command: str, timeout: int = 20) -> dict:
        """Simula ``DeviceManager.run_shell_root``."""
        self.commands.append(command)
        return self._match(command)

    def _match(self, command: str) -> dict:
        for key, value in self.mapping.items():
            if key in command:
                if isinstance(value, dict):
                    return value
                return {"ok": True, "rc": 0, "stdout": value, "stderr": ""}
        return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

    def logcat_mark(self) -> int:
        """Marcador de logcat fixo."""
        return 0

    def logcat_since(self, mark: int = 0) -> list:
        """Linhas de logcat fixas."""
        return list(self.mapping.get("__lines__", []) or [])

    def get_app_pid(self, package_name: str):
        """PID fixo do alvo."""
        return int(self.mapping.get("__pid__", 4242))

    def is_app_alive(self, pid: int) -> bool:
        """Estado de vida fixo."""
        return bool(self.mapping.get("__alive__", True))


def _framework_mapping(**extra) -> Dict[str, ShellResponse]:
    """Monta o mapping de shell de um dispositivo com framework de hooking."""
    base: Dict[str, ShellResponse] = {
        "ls /data/adb/modules": "zygisk_vector\nmagisk\n",
        "test -x /data/adb/modules/zygisk_vector/cli": "yes\n",
        "status": "Framework Version: 2.2\nVersion Code: 3080\n",
        "scope ls": (
            "APP_PACKAGE     USER_ID\n"
            "-----------------------\n"
            "com.example.app 0      \n"
        ),
        "modules ls": (
            "PACKAGE              UID    STATUS\n"
            "------------------------------------\n"
            f"{MODULE_PACKAGE}              10258  disabled\n"
        ),
    }
    base.update(extra)
    return base


# ----------------------------------------------------------------------
# Configuração
# ----------------------------------------------------------------------
def test_config_serializa_propriedade():
    """A configuração vira a propriedade lida pelo módulo."""
    config = ModuleConfig(
        hook="bypass", emulator="probe", target="com.example.app", label="fase"
    )
    assert config.as_property() == (
        "hook=bypass;root=off;tamper=off;emu=probe;proxy=off;"
        "target=com.example.app;label=fase"
    )


def test_config_camada_tamper():
    """A camada de tampering também é configurável por fase."""
    config = ModuleConfig(tamper="bypass", target="com.example.app")
    assert "tamper=bypass" in config.as_property()
    assert "--tamper" in config.as_build_args()
    assert "bypass" in config.as_build_args()


def test_config_argumentos_de_build():
    """A configuração vira argumentos do script de build."""
    config = ModuleConfig(hook="observe", emulator="off", target="a.b", label="x")
    args = config.as_build_args()
    assert args[:2] == ["--hook", "observe"]
    assert "--proxy" in args
    assert "a.b" in args and "x" in args


def test_config_camada_proxy():
    """A camada de proxy/VPN também é configurável por fase."""
    config = ModuleConfig(proxy="bypass", target="com.example.app")
    assert "proxy=bypass" in config.as_property()
    assert "--proxy" in config.as_build_args()
    assert "bypass" in config.as_build_args()


def test_config_fingerprint_estavel():
    """A mesma configuração produz o mesmo fingerprint."""
    a = ModuleConfig(hook="bypass", emulator="off", target="a.b", label="x")
    b = ModuleConfig(hook="bypass", emulator="off", target="a.b", label="x")
    c = ModuleConfig(hook="observe", emulator="off", target="a.b", label="x")
    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != c.fingerprint()


def test_source_digest_invalida_build_antigo(tmp_path, monkeypatch):
    """Mudar o código-fonte do módulo muda o diretório de cache do APK.

    O cache era indexado só pela configuração: uma correção no Java
    continuava executando o APK antigo no dispositivo.
    """
    import instrumentation.manager as manager_mod

    src = tmp_path / "src"
    src.mkdir()
    source = src / "Module.java"
    source.write_text("class Module { }", encoding="utf-8")
    monkeypatch.setattr(manager_mod, "MODULE_SRC_DIR", str(src))

    first = manager_mod.XposedManager._source_digest()
    source.write_text("class Module { int fixed; }", encoding="utf-8")
    second = manager_mod.XposedManager._source_digest()
    assert first != second


def test_build_reutiliza_apk_entre_fases(tmp_path, monkeypatch):
    """O mesmo APK atende observe/bypass; a fase é aplicada em runtime.

    Antes o cache era indexado pela configuração da fase
    (hook/root/tamper/emu/label), então cada fase recompilava e
    reinstalava o módulo mesmo com os mesmos fontes.
    """
    import instrumentation.manager as manager_mod

    src = tmp_path / "src"
    src.mkdir()
    (src / "Module.java").write_text("class Module { }", encoding="utf-8")
    script = tmp_path / "build.sh"
    script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    old = build_dir / "aaaaaaaaaaaa"
    old.mkdir()
    (old / "raspilot-module.apk").write_text("old", encoding="utf-8")

    monkeypatch.setattr(manager_mod, "MODULE_SRC_DIR", str(src))
    monkeypatch.setattr(manager_mod, "BUILD_SCRIPT", str(script))
    monkeypatch.setattr(manager_mod, "BUILD_DIR", str(build_dir))

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        out = cmd[cmd.index("--out") + 1]
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as handle:
            handle.write(b"apk")

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    monkeypatch.setattr(manager_mod.subprocess, "run", fake_run)

    manager = XposedManager(FakeDM({}), "com.example.app")
    observe = manager.build(ModuleConfig(
        hook="observe", target="com.example.app", label="hook-observe"
    ))
    bypass = manager.build(ModuleConfig(
        hook="bypass", target="com.example.app", label="hook-bypass"
    ))

    assert observe["ok"] is True
    assert bypass["ok"] is True
    assert observe["apk"] == bypass["apk"]
    assert len(calls) == 1
    assert not old.exists()  # a poda removeu o build antigo


def test_mask_spoofs_secondary_and_hides_decisive():
    """O modo mask mantém os canais secundários expostos.

    O bypass precisa exercitar o app: sem o spoof dos canais
    secundários, o app veria o device físico e o módulo não teria
    nenhuma consulta para observar.
    """
    from instrumentation.manager import MODULE_SRC_DIR

    source = open(
        f"{MODULE_SRC_DIR}/src/com/raspilot/module/EmulatorShield.java",
        encoding="utf-8",
    ).read()
    assert "hookTelephony(probe || mask)" in source
    assert "hookAndroidId(probe || mask)" in source
    assert "if (!probe && !mask)" in source


def test_hookshield_tem_sondas_ativas_e_cobertura():
    """A camada anti-hook inclui sonda de ciclo de vida e de visibilidade."""
    from instrumentation.manager import MODULE_SRC_DIR

    source = open(
        f"{MODULE_SRC_DIR}/src/com/raspilot/module/HookShield.java",
        encoding="utf-8",
    ).read()
    for marker in (
        "probe-installed",
        "bypass-verified",
        "bypass-incomplete",
        "runVisibilityProbe",
        "mapsContainsFramework",
        "probing",
    ):
        assert marker in source, f"sonda/hook ausente: {marker}"


# ----------------------------------------------------------------------
# Evidência
# ----------------------------------------------------------------------
def test_parse_evidence_extreme_eventos():
    """As linhas do módulo são convertidas em eventos."""
    lines = [
        "10-21 15:19:38.867 32662 32662 W RASPilotModule: EVT|error|hook|-|falhou",
        "10-21 15:19:38.867 32662 32662 I RASPilotModule: EVT|neutralize|hook|"
        "Class.forName|de.robv.android.xposed.XposedBridge",
        "10-21 15:19:38.867 32662 32662 I RASPilotModule: EVT|ready|module|"
        "handleLoadPackage|pkg=com.example.app hook=bypass emu=off label=x",
        "10-21 15:19:38.867 32662 32662 I ActivityManager: Start proc com.example.app",
    ]
    events = parse_evidence(lines)
    assert len(events) == 3
    assert events[1]["kind"] == "neutralize"
    assert events[1]["method"] == "Class.forName"
    assert events[1]["detail"] == "de.robv.android.xposed.XposedBridge"


def test_parse_evidence_sem_linhas_do_modulo():
    """Linhas de outros processos são ignoradas."""
    assert parse_evidence(["ActivityManager: Start proc com.example.app"]) == []


def test_parse_ready_converte_resumo():
    """O resumo do módulo vira pares chave=valor."""
    values = _parse_ready("pkg=com.example.app hook=bypass emu=off label=fase")
    assert values["pkg"] == "com.example.app"
    assert values["hook"] == "bypass"


# ----------------------------------------------------------------------
# Saída do cli do framework
# ----------------------------------------------------------------------
def test_failed_entries_vazio():
    """Lista de falhas vazia significa operação concluída."""
    assert _failed_entries("Enabled: [com.raspilot.module]\nFailed: []") == []


def test_failed_entries_com_item():
    """A lista de falhas é extraída da saída do cli."""
    assert _failed_entries("Enabled: []\nFailed: [com.raspilot.module]") == [
        "com.raspilot.module"
    ]


def test_parse_status_extrai_versao():
    """Nome e versão saem da saída do comando status."""
    name, version = _parse_status("Framework Version: 2.2\nVersion Code: 3080\n")
    assert version == "2.2"
    assert name is None


def test_framework_name_derivado_do_diretorio():
    """O nome do framework vem do diretório do módulo."""
    assert _framework_name(["zygisk_vector"]) == "Vector"
    assert _framework_name(["zygisk_lsposed"]) == "LSPosed"
    assert _framework_name([]) is None


# ----------------------------------------------------------------------
# Gerenciador
# ----------------------------------------------------------------------
def test_detect_encontra_framework():
    """O framework é detectado pelo cli e pelos módulos do /data/adb."""
    dm = FakeDM(_framework_mapping())
    manager = XposedManager(dm, "com.example.app")
    info = manager.detect()
    assert info["available"] is True
    assert info["version"] == "2.2"
    assert info["name"] == "Vector"


def test_detect_sem_framework():
    """Sem framework a detecção é indisponível."""
    dm = FakeDM({"ls /data/adb/modules": "magisk\n"})
    manager = XposedManager(dm, "com.example.app")
    info = manager.detect()
    assert info["available"] is False
    assert manager.cli_path is None


def test_enable_module_aceita_saida_com_lista_vazia():
    """A lista ``Failed: []`` não é interpretada como falha."""
    dm = FakeDM(_framework_mapping(
        **{"modules enable": "Enabled: [%s]\nFailed: []\n" % MODULE_PACKAGE}
    ))
    manager = XposedManager(dm, "com.example.app")
    manager.detect()
    result = manager.enable_module()
    assert result["ok"] is True


def test_enable_module_detecta_falha():
    """Uma falha real do cli é propagate."""
    dm = FakeDM(_framework_mapping(
        **{"modules enable": "Enabled: []\nFailed: [%s]\n" % MODULE_PACKAGE}
    ))
    manager = XposedManager(dm, "com.example.app")
    manager.detect()
    result = manager.enable_module()
    assert result["ok"] is False


def test_set_scope_monta_entradas():
    """O escopo é aplicado com o par pacote/usuário."""
    dm = FakeDM(_framework_mapping(**{"scope set": "Successfully overwrote scope\n"}))
    manager = XposedManager(dm, "com.example.app")
    manager.detect()
    result = manager.set_scope(["com.example.app"])
    assert result["ok"] is True
    assert any("scope set" in cmd for cmd in dm.commands)
    assert any("com.example.app/0" in cmd for cmd in dm.commands)


def test_scope_list_lê_tabela():
    """O escopo atual é lido da saída do cli."""
    dm = FakeDM(_framework_mapping())
    manager = XposedManager(dm, "com.example.app")
    manager.detect()
    assert manager.scope_list() == ["com.example.app"]


def test_apply_runtime_config_confirma_propriedade():
    """A configuração em execução é confirmada pela propriedade."""
    dm = FakeDM({
        "setprop": "",
        "getprop persist.raspilot.module.config":
            "hook=bypass;root=off;tamper=off;emu=off;proxy=off;"
            "target=com.example.app;label=x",
    })
    manager = XposedManager(dm, "com.example.app")
    config = ModuleConfig(hook="bypass", emulator="off", target="com.example.app",
                          label="x")
    result = manager.apply_runtime_config(config)
    assert result["ok"] is True


def test_apply_runtime_config_detecta_divergencia():
    """Uma propriedade que não confere é considerada falha."""
    dm = FakeDM({"setprop": "", "getprop persist.raspilot.module.config": "hook=off"})
    manager = XposedManager(dm, "com.example.app")
    config = ModuleConfig(hook="bypass")
    result = manager.apply_runtime_config(config)
    assert result["ok"] is False


def test_framework_artifacts_lista_bibliotecas():
    """As bibliotecas do framework no processo alvo são listadas."""
    dm = FakeDM({
        "cat /proc/1234/maps": (
            "7a0b45b000-7a0b45d000 rw-p 00000000 00:00 0 [anon:InternalMmapVector]\n"
            "7a0c81c000-7a0c944000 r-xp 00000000 fd:2b 105096 "
            "/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so\n"
            "7a0d000000-7a0d001000 r-xp 00000000 fd:2b 105096 /system/lib64/libc.so\n"
        )
    })
    manager = XposedManager(dm, "com.example.app")
    artifacts = manager.framework_artifacts(1234)
    assert "/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so" in artifacts
    assert not any("/system/lib64/libc.so" in item for item in artifacts)


def test_scoped_modules_for_lista_modulos_concorrentes():
    """Módulos ativos no escopo do alvo são listados."""
    dm = FakeDM(_framework_mapping(**{
        "modules ls": (
            "PACKAGE              UID    STATUS\n"
            "------------------------------------\n"
            f"{MODULE_PACKAGE}              10258  enabled\n"
            "com.other.module              10259  enabled\n"
            "com.disabled.module           10260  disabled\n"
        ),
        "scope ls com.other.module": (
            "APP_PACKAGE     USER_ID\n"
            "-----------------------\n"
            "com.example.app 0      \n"
        ),
        "scope ls com.disabled.module": "No records found.\n",
    }))
    manager = XposedManager(dm, "com.example.app")
    manager.detect()
    found = manager.scoped_modules_for("com.example.app")
    assert [item["package"] for item in found] == ["com.other.module"]


def test_cleanup_restaura_escopo_e_desabilita():
    """O cleanup devolve o escopo original e desabilita o módulo."""
    dm = FakeDM(_framework_mapping(
        **{"scope set": "Successfully overwrote scope\n",
           "modules disable": "Disabled: [%s]\nFailed: []\n" % MODULE_PACKAGE}
    ))
    manager = XposedManager(dm, "com.example.app")
    manager.detect()
    manager.original_scope = ["com.other.app"]
    manager.scope_applied = True
    manager.enabled_by_us = True
    actions = manager.cleanup()
    steps = [action["step"] for action in actions]
    assert "scope_restore" in steps
    assert "disable" in steps
    assert any("com.other.app/0" in cmd for cmd in dm.commands)


class TestPartitionEvidence:
    """Separação de eventos por papel-veredito."""

    def test_aplica_observado_e_neutralizado(self):
        """Eventos aplicação/observação/contexto vão para listas distintas."""
        events = [
            {"kind": "observe", "channel": "hook", "method": "File.exists", "detail": "/x"},
            {"kind": "neutralize", "channel": "hook", "method": "File.exists", "detail": "/x"},
            {"kind": "ready", "channel": "module", "method": "state", "detail": "hook=observe"},
            {"kind": "context", "channel": "hook", "method": "FileInputStream", "detail": "/proc/self/maps"},
        ]
        applied, observed, contexts = partition_evidence(events)
        assert [i["method"] for i in applied] == ["File.exists"]
        assert [i["method"] for i in observed] == ["File.exists"]
        assert [i["detail"] for i in contexts] == ["/proc/self/maps"]

    def test_sondas_ativas_ficam_separadas_das_consultas_do_app(self):
        """Eventos ``probe`` são do módulo, não checagens do app."""
        events = [
            {"kind": "probe", "channel": "hook", "method": "visibility",
             "detail": "class=hidden;stack=hidden;maps=hidden"},
            {"kind": "observe", "channel": "hook", "method": "File.exists",
             "detail": "/data/adb/lspd"},
        ]
        applied, observed, contexts = partition_evidence(events)
        assert applied == []
        assert len(observed) == 1  # a sonda não vira consulta do app
        probes = probe_evidence(events)
        assert [item["method"] for item in probes] == ["visibility"]

    def test_evento_interno_nao_evidencia(self):
        """Eventos do canal interno do módulo são ignorados em todos."""
        events = [
            {"kind": "observe", "channel": "module", "method": "m", "detail": "d"},
            {"kind": "neutralize", "channel": "module", "method": "m", "detail": "d"},
            {"kind": "context", "channel": "module", "method": "m", "detail": "d"},
        ]
        applied, observed, contexts = partition_evidence(events)
        assert applied == []
        assert observed == []
        assert contexts == []

    def test_tipos_desconhecidos_ficam_fora(self):
        """Kinds não pertencentes à separação não viram evidência por engano."""
        events = [
            {"kind": "error", "channel": "hook", "method": "m", "detail": "d"},
            {"kind": "other", "channel": "hook", "method": "m", "detail": "d"},
        ]
        applied, observed, contexts = partition_evidence(events)
        assert applied == []
        assert observed == []
        assert contexts == []
