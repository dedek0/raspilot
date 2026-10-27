"""Testes do AntiHookingCheck — vetores, detecção estática/dinâmica e bypass."""

from __future__ import annotations

import os
import zipfile
from unittest import mock

from checks.anti_hooking import (
    HOOK_BYPASS_SCRIPT,
    HOOK_DETECTION_SCRIPT,
    KILL_TRACE_SCRIPT,
    PROC_FILTER_SCRIPT,
    STATIC_SIGNATURES,
    AntiHookingCheck,
)


def _make_apk(path: str, entries: dict) -> str:
    """Cria um APK sintético (zip) com as entradas fornecidas.

    Args:
        path: Caminho do arquivo a criar.
        entries: ``{nome: bytes}``.

    Returns:
        O mesmo ``path`` recebido.
    """
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


class FakeScript:
    """Script Frida fake que dispara mensagens pré-definidas no load."""

    def __init__(self, messages):
        self._messages = messages
        self._cb = None

    def on(self, event, cb):
        self._cb = cb

    def load(self):
        for msg in self._messages:
            self._cb(msg, None)

    def unload(self):
        pass


class FakeSession:
    """Sessão Frida fake: separa mensagens de observação e de bypass.

    O dispatcher usa o fonte do script (o de bypass contém a marca
    ``raspilot-hooking-bypass``) para devolver o conjunto de mensagens
    correto para cada fase.
    """

    def __init__(self, detection_messages=None, bypass_messages=None):
        self.detection_messages = detection_messages or []
        self.bypass_messages = bypass_messages or []

    def enumerate_modules(self):
        return []

    def create_script(self, source, **kwargs):
        if "raspilot-hooking-bypass" in source:
            return FakeScript(self.bypass_messages)
        return FakeScript(self.detection_messages)

    def detach(self):
        pass


class FakeRpcSession:
    """Sessão sem ``enumerate_modules`` (Frida 17) — enumeração via RPC."""

    def __init__(self, names):
        self._names = names
        self.created = None

    def create_script(self, source, **kwargs):
        names = self._names

        class _Script:
            def __init__(self):
                self.unloaded = False

            class _Exports:
                def __init__(self, values):
                    self._values = values

                def listmodules(self):
                    return self._values

            @property
            def exports(self):
                return _Script._Exports(names)

            def load(self):
                pass

            def unload(self):
                self.unloaded = True

        self.created = _Script()
        return self.created


class _Mod:
    """Módulo Frida fake (apenas .name)."""

    def __init__(self, name):
        self.name = name


class FakeModuleSession:
    """Sessão legada com ``enumerate_modules`` no host."""

    def __init__(self, names):
        self._names = names

    def enumerate_modules(self):
        return [_Mod(n) for n in self._names]


def _det(method, detail):
    """Monta uma mensagem de observação anti-hook."""
    return {"type": "send", "payload": {"type": "hook-detection",
                                        "method": method, "detail": detail}}


def _bypass(message):
    """Monta uma mensagem do script de bypass."""
    return {"type": "send", "payload": {"type": "raspilot-hooking-bypass",
                                        "message": message}}


class TestDeviceVectors:
    """Vetores de dispositivo (pacotes, módulos, libs no processo)."""

    def test_hook_packages_detected(self, fake_dm_factory):
        """LSPosed instalado é detectado via pm list packages."""
        dm = fake_dm_factory({
            "pm list packages 2>/dev/null": (
                "package:com.android.chrome\npackage:org.lsposed.manager"
            )
        })
        res = AntiHookingCheck(dm).check_hook_framework_packages()
        assert res["detected"] is True
        assert "org.lsposed.manager" in res["evidence"]

    def test_hook_packages_absent(self, clean_dm):
        """Dispositivo limpo não tem framework de hooking instalado."""
        res = AntiHookingCheck(clean_dm).check_hook_framework_packages()
        assert res["detected"] is False
        assert res["evidence"] == []

    def test_hook_packages_shell_error(self, fake_dm_factory):
        """Falha no pm vira error estruturado, sem exceção."""
        dm = fake_dm_factory({
            "pm list packages 2>/dev/null": {"ok": False, "rc": 1,
                                             "stdout": "", "stderr": "denied"}
        })
        res = AntiHookingCheck(dm).check_hook_framework_packages()
        assert res["detected"] is False
        assert "denied" in res["error"]

    def test_hook_modules_on_device_detected(self, fake_dm_factory):
        """Módulo zygisk_lsposed e dir do LSPosed são detectados."""
        dm = fake_dm_factory({
            "ls /data/adb/modules 2>/dev/null": "zygisk_lsposed\nsystemless-hosts",
            "ls /data/adb/lspd 2>/dev/null": "config",
        })
        res = AntiHookingCheck(dm).check_hook_modules_on_device()
        assert res["detected"] is True
        assert "/data/adb/modules/zygisk_lsposed" in res["evidence"]
        assert any("lspd" in e for e in res["evidence"])

    def test_module_keywords_cover_zygisk_frameworks(self):
        """Frameworks usados como módulo Zygisk entram nos vetores."""
        from checks.anti_hooking import HOOK_MODULE_KEYWORDS

        for name in ("zygisk_lsposed", "zygisk_vector", "shamiko", "lspatch"):
            assert any(k in name.lower() for k in HOOK_MODULE_KEYWORDS), name

    def test_module_prop_version_evidence(self, fake_dm_factory):
        """O module.prop do módulo detectado vira evidência com versão."""
        dm = fake_dm_factory({
            "ls /data/adb/modules 2>/dev/null": "zygisk_vector\nunrelated-module",
            "module.prop": (
                "name=Vector Zygisk Module\nversion=2.2\nversionCode=22\n"
            ),
            "ls /data/adb/lspd 2>/dev/null": "",
        })
        res = AntiHookingCheck(dm).check_hook_modules_on_device()
        assert res["detected"] is True
        assert "/data/adb/modules/zygisk_vector (Vector Zygisk Module 2.2)" in res["evidence"]
        assert res["frameworks"] == ["Vector Zygisk Module 2.2"]
        # Módulo sem tema de hooking não entra.
        assert not any("unrelated-module" in e for e in res["evidence"])

    def test_hook_modules_absent(self, fake_dm_factory):
        """Sem /data/adb de hooking o vetor é negativo."""
        dm = fake_dm_factory({})
        res = AntiHookingCheck(dm).check_hook_modules_on_device()
        assert res["detected"] is False

    def test_hook_libraries_via_session(self):
        """liblsplant.so no processo é detectada via sessão Frida."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeModuleSession(["libc.so", "liblsplant.so"])
        res = check.check_hook_libraries(session)
        assert res["detected"] is True
        assert "liblsplant.so" in res["evidence"]
        assert res["source"] == "processo"

    def test_hook_libraries_ignores_frida(self):
        """Libs do Frida não contam: são do anti_frida / da ferramenta."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeModuleSession(
            ["frida-agent-64.so", "libfrida-gadget.so", "libc.so"]
        )
        res = check.check_hook_libraries(session)
        assert res["detected"] is False
        assert res["evidence"] == []

    def test_hook_libraries_rpc_fallback(self):
        """Sessão sem enumerate_modules enumera via RPC no script."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeRpcSession(["libc.so", "liblspd.so"])
        res = check.check_hook_libraries(session)
        assert res["detected"] is True
        assert "liblspd.so" in res["evidence"]
        assert session.created.unloaded is True

    def test_hook_libraries_maps_fallback(self, fake_dm_factory):
        """Sem sessão: /proc/<pid>/maps com elevação é o fallback."""
        dm = fake_dm_factory({
            "cat /proc/1234/maps": (
                "7a000000-7a100000 r-xp 00000000 08:01 42 "
                "/data/app/lib/arm64-v8a/libSandHook.so\n"
            )
        })
        res = AntiHookingCheck(dm).check_hook_libraries(None, pid=1234)
        assert res["detected"] is True
        assert res["source"] == "/proc/<pid>/maps"
        assert any("SandHook" in e for e in res["evidence"])

    def test_hook_libraries_skipped_without_session_and_pid(self):
        """Sem sessão nem pid o vetor é marcado como skipped."""
        res = AntiHookingCheck(mock.MagicMock()).check_hook_libraries(None, pid=None)
        assert res["detected"] is False
        assert res["skipped"] is True

    def test_hook_libraries_process_gone_is_skipped(self):
        """Sessão destruída com processo morto => skipped, sem error."""

        class _GoneSession:
            def enumerate_modules(self):
                raise RuntimeError("session is gone")

        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        res = AntiHookingCheck(dm).check_hook_libraries(_GoneSession(), pid=99)
        assert res["detected"] is False
        assert res["skipped"] is True
        assert "error" not in res


class TestDetectStatic:
    """Detecção estática de assinaturas anti-hook no APK."""

    def test_xposed_signature(self, tmp_path):
        """Classe Xposed no dex => static_detected, primary=xposed."""
        apk = _make_apk(str(tmp_path / "x.apk"), {
            "classes.dex": b"dex\n035\x00de.robv.android.xposed.XposedBridge\x00",
        })
        res = AntiHookingCheck(mock.MagicMock()).detect_static("pkg", apk_path=apk)
        assert res["static_detected"] is True
        assert res["primary"] == "xposed"

    def test_frida_signature(self, tmp_path):
        """gum-js-loop no dex => primary=frida (anti-Frida embutido)."""
        apk = _make_apk(str(tmp_path / "f.apk"), {
            "classes.dex": b"dex\n035\x00gum-js-loop\x00",
        })
        res = AntiHookingCheck(mock.MagicMock()).detect_static("pkg", apk_path=apk)
        assert res["static_detected"] is True
        assert res["primary"] == "frida"

    def test_lsposed_priority_over_frida(self, tmp_path):
        """LSPosed + frida => principal LSPosed (prioridade do check)."""
        apk = _make_apk(str(tmp_path / "p.apk"), {
            "classes.dex": b"org.lsposed.lspd\x00frida",
        })
        res = AntiHookingCheck(mock.MagicMock()).detect_static("pkg", apk_path=apk)
        assert res["primary"] == "lsposed"
        assert set(res["types"]) == {"lsposed", "frida"}

    def test_clean_apk(self, tmp_path):
        """APK sem assinaturas => static_detected=False."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {
            "classes.dex": b"dex\n035\x00com.example.plain\x00",
        })
        res = AntiHookingCheck(mock.MagicMock()).detect_static("pkg", apk_path=apk)
        assert res["static_detected"] is False
        assert res["primary"] is None

    def test_pull_failure_returns_error(self):
        """Sem APK e sem pm path: erro estruturado, sem exceção."""
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": False, "rc": 1, "stdout": "", "stderr": "err"}
        res = AntiHookingCheck(dm).detect_static("com.missing")
        assert res["static_detected"] is False
        assert "error" in res

    def test_signatures_cover_main_frameworks(self):
        """As assinaturas cobrem os frameworks principais."""
        types = {sig_type for sig_type, _ in STATIC_SIGNATURES}
        assert {"xposed", "lsposed", "edxposed", "substrate",
                "inline_hook", "frida"} <= types


class TestAppDetection:
    """Observação de checagens anti-hook executadas pelo app."""

    def test_app_without_protection_not_detected(self):
        """Sem mensagens => detected=False, lists vazias."""
        check = AntiHookingCheck(mock.MagicMock())
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(FakeSession())
        assert res["detected"] is False
        assert res["detection_methods_found"] == []
        assert res["app_alive_at_end"] is True

    def test_class_for_name_is_strong_signal(self):
        """Class.forName de classe Xposed => detected=True (forte)."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeSession(detection_messages=[
            _det("Class.forName", "de.robv.android.xposed.XposedBridge"),
        ])
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(session)
        assert res["detected"] is True
        assert any("Class.forName" in s for s in res["strong_signals"])

    def test_maps_scan_is_weak_signal(self):
        """Leitura de /proc/self/maps sozinha não define detected."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeSession(detection_messages=[
            _det("maps_scan", "/proc/self/maps via open"),
        ])
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(session)
        assert res["detected"] is False
        assert res["weak_signals"]
        assert any("maps_scan" in s for s in res["detection_methods_found"])

    def test_net_and_comm_scan_are_weak_signals(self):
        """Port-scan via /proc/net/tcp e leitura de comm são fracos."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeSession(detection_messages=[
            _det("net_scan", "/proc/net/tcp via open"),
            _det("comm_scan", "/proc/self/task/1/comm via open"),
        ])
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(session)
        assert res["detected"] is False
        assert len(res["weak_signals"]) == 2

    def test_strong_and_weak_coexist(self):
        """Sinal fraco + forte => detected=True e ambos reportados."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeSession(detection_messages=[
            _det("status_scan", "/proc/self/status via open"),
            _det("native_strstr", "needle=xposed"),
        ])
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(session)
        assert res["detected"] is True
        assert res["weak_signals"] and res["strong_signals"]

    def test_ignores_non_detection_payloads(self):
        """Mensagens de outros tipos (ex: bypass) não viram sinal."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeSession(detection_messages=[
            {"type": "send", "payload": {"type": "raspilot-hooking-bypass",
                                         "message": "neutralizado: x -> null"}},
        ])
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(session)
        assert res["detected"] is False
        assert res["detection_methods_found"] == []

    def test_ignores_hook_install_errors(self):
        """Erros de instalação do próprio script não viram detecção."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeSession(detection_messages=[
            {"type": "send", "payload": {"type": "hook-detection-error",
                                         "message": "instalação de strstr falhou"}},
        ])
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(session)
        assert res["detected"] is False
        assert res["detection_methods_found"] == []

    def test_app_death_is_strong_signal(self):
        """Morte na janela => reação do RASP + causa externa capturada."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": ["crash: Fatal signal 9 (SIGKILL)"],
            "signal": None,
            "summary": "morte registrada em logcat",
        }
        check = AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(
                FakeSession(), window=3, pid=99, package_name="com.app"
            )
        assert res["detected"] is True
        assert res["app_alive_at_end"] is False
        assert any("app_terminated" in s for s in res["strong_signals"])
        assert any("app_kill_external" in s for s in res["strong_signals"])
        assert res["death_cause"]["summary"] == "morte registrada em logcat"
        dm.capture_death_cause.assert_called_once_with(pid=99, package="com.app")

    def test_app_kill_trace_is_strong_signal(self):
        """Mensagem do kill_trace (quem matou) vira sinal forte."""
        check = AntiHookingCheck(mock.MagicMock())
        session = FakeSession(detection_messages=[
            {"type": "send", "payload": {"type": "app-kill",
                                          "message": "System.exit(1) <- com.x.Security.kill"}},
        ])
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(session)
        assert res["detected"] is True
        assert any("app_kill" in s for s in res["strong_signals"])

    def test_kill_trace_script_exists(self):
        """O kill_trace.js existe e cobre os vetores de morte essenciais."""
        assert os.path.isfile(KILL_TRACE_SCRIPT)
        with open(KILL_TRACE_SCRIPT, encoding="utf-8") as fh:
            source = fh.read()
        for marker in (
            "System.exit", "Runtime.exit", "killProcess", "tgkill",
            "abort", "syscall", "app-kill", "backtrace",
        ):
            assert marker in source, f"vetor ausente: {marker}"

    def test_script_exists_with_essential_hooks(self):
        """O script de observação cobre as checagens anti-hook essenciais."""
        for marker in (
            "Class.forName", "ClassLoader.loadClass", "File.exists",
            "Runtime.exec", "ProcessBuilder", "getStackTrace",
            "maps_scan", "status_scan", "strstr", "strcmp", "memcmp",
            "fopen", "faccessat", "hook-detection",
            # Compatibilidade Frida 16/17 (validada em dispositivo real):
            "raspilotFindExport", "raspilotPerformJava",
        ):
            assert marker in HOOK_DETECTION_SCRIPT, f"hook ausente: {marker}"
        assert "Module.findExportByName" not in HOOK_DETECTION_SCRIPT


class TestAttemptBypass:
    """Bypass dinâmico com sessão Frida falsa."""

    def test_success_with_neutralization_evidence(self):
        """Neutralização registrada + app vivo => success=True."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = FakeSession(bypass_messages=[
            _bypass("neutralizado: Class.forName('de.robv.android.xposed.XposedBridge') -> null"),
            _bypass("libc.strstr hookado"),
        ])
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = True
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).attempt_bypass("com.app")
        assert res["success"] is True
        assert res["effective_logs"]

    def test_failure_without_evidence(self):
        """Apenas logs de instalação (sem neutralização) => inconclusivo."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = FakeSession(bypass_messages=[
            _bypass("libc.strstr hookado"),
            _bypass("anti_hooking_bypass.js carregado"),
        ])
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = True
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).attempt_bypass("com.app")
        assert res["success"] is None
        assert res["effective_logs"] == []
        assert "não exercitado" in res["skipped_reason"]

    def test_app_death_beats_evidence(self):
        """Morte durante o bypass anula a evidência: RASP reagiu."""
        dm = mock.MagicMock()
        dm.spawn_app.return_value = FakeSession(bypass_messages=[
            _bypass("neutralizado: File.exists(/data/local/tmp/frida-server) -> false"),
        ])
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = False
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).attempt_bypass("com.app", window=3)
        assert res["success"] is False
        assert res["app_alive_at_end"] is False
        assert any("app_terminated" in log for log in res["bypass_logs"])

    def test_spawn_error_is_captured(self):
        """Erro no spawn vira dict com error, sem exceção."""
        dm = mock.MagicMock()
        dm.spawn_app.side_effect = RuntimeError("spawn falhou")
        res = AntiHookingCheck(dm).attempt_bypass("com.app")
        assert res["success"] is False
        assert "spawn falhou" in res["error"]

    def test_script_file_exists(self):
        """O anti_hooking_bypass.js existe e cobre as técnicas essenciais."""
        assert os.path.isfile(HOOK_BYPASS_SCRIPT)
        with open(HOOK_BYPASS_SCRIPT, encoding="utf-8") as fh:
            source = fh.read()
        for marker in (
            "Class.forName", "ClassLoader.loadClass", "File.exists",
            "File.list", "File.listFiles", "Runtime.exec", "ProcessBuilder",
            "getStackTrace", "strstr", "strcmp", "memcmp",
            "openat", "fopen", "access", "faccessat",
            "raspilot-hooking-bypass",
            # Compatibilidade Frida 16/17 (validada em dispositivo real):
            "raspilotFindExport",
        ):
            assert marker in source, f"técnica ausente: {marker}"
        # A camada Java é instalada por um dos helpers de compatibilidade.
        assert ("raspilotPerformJava" in source
                or "raspilotDeferJava" in source)
        assert "Module.findExportByName" not in source

    def test_proc_filter_script_exists(self):
        """O proc_filter.js cobre maps, TracerPid, portas Frida e comm."""
        assert os.path.isfile(PROC_FILTER_SCRIPT)
        with open(PROC_FILTER_SCRIPT, encoding="utf-8") as fh:
            source = fh.read()
        for marker in (
            "TracerPid", "fgets", "/net/tcp", "69A2", "69A3", "comm",
            "maps", "raspilotFindExport", "raspilot-hooking-bypass",
            "pthread_setname_np",
        ):
            assert marker in source, f"filtro ausente: {marker}"
        assert "Module.findExportByName" not in source


class TestAttemptModuleBypass:
    """Bypass via módulo Xposed: evidência obrigatória (sem falso positivo).

    O bug coberto aqui: "app vivo no fim da janela" **não** é evidência
    de bypass — se nenhuma checagem anti-hook foi observada ou
    neutralizada, o resultado é inconclusivo (success=None), nunca
    sucesso. Kills assíncronos de RASP (após a janela) também invalidam
    a conclusão.
    """

    @staticmethod
    def _manager(observe=None, neutralize=None, alive=True):
        """Gerenciador falso: observe/bypass devolvem runs determinísticos."""
        mgr = mock.MagicMock()

        def run_phase(config, window=12, keep_enabled=False, interact=False):
            if config.hook == "observe":
                return {"ok": True, "run": {
                    "observed": list(observe or []),
                    "app_alive_at_end": True,
                    "module_ready": True,
                    "lines": [], "pid": 42,
                }}
            return {"ok": True, "run": {
                "neutralized": list(neutralize or []),
                "app_alive_at_end": alive,
                "module_ready": True,
                "lines": [], "pid": 42,
            }}

        mgr.run_phase.side_effect = run_phase
        mgr.detect.return_value = {"available": True, "framework": "vector"}
        mgr.framework_artifacts.return_value = []
        mgr.scoped_modules_for.return_value = []
        return mgr

    @staticmethod
    def _check(mgr, alive=True):
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = alive
        return AntiHookingCheck(dm, xposed=mgr), dm

    def test_alive_without_evidence_is_inconclusive(self):
        """Vivo sem nada observado/neutralizado => success=None, não True."""
        mgr = self._manager(observe=[], neutralize=[], alive=True)
        check, dm = self._check(mgr)
        res = check.attempt_module_bypass("com.app", window=3)
        assert res["success"] is None
        assert res["blocked"] is False
        assert res["error"] is None
        assert "não exercitado" in res["skipped_reason"]

    def test_neutralized_with_alive_is_success(self):
        """Neutralização registrada + app vivo => success=True."""
        mgr = self._manager(
            neutralize=[{"method": "File.exists", "detail": "/data/local/tmp -> false"}],
            alive=True,
        )
        check, dm = self._check(mgr)
        res = check.attempt_module_bypass("com.app", window=3)
        assert res["success"] is True
        assert res["app_alive_at_end"] is True

    def test_observed_only_with_alive_is_success(self):
        """App consultou artefatos (observe) e sobreviveu => success=True."""
        mgr = self._manager(
            observe=[{"method": "Class.forName", "detail": "XposedBridge"}],
            neutralize=[], alive=True,
        )
        check, dm = self._check(mgr)
        res = check.attempt_module_bypass("com.app", window=3)
        assert res["success"] is True

    def test_post_window_death_overrides_success(self):
        """Morte logo após a janela (kill assíncrono) anula o sucesso."""
        mgr = self._manager(
            neutralize=[{"method": "File.exists", "detail": "x -> false"}],
            alive=True,  # run_phase achou vivo...
        )
        check, dm = self._check(mgr, alive=False)  # ...a re-checagem, não
        with mock.patch("checks.anti_hooking.classify_failure",
                        return_value={"is_rasp": False, "kind": "instrumentation_crash"}):
            res = check.attempt_module_bypass("com.app", window=3)
        assert res["success"] is False
        assert res["app_alive_at_end"] is False
        assert res["blocked"] is False
        assert any("logo após a janela" in log for log in res["bypass_logs"])

    def test_post_window_rasp_death_is_blocked(self):
        """Morte pós-janela classificada como RASP => blocked=True."""
        mgr = self._manager(
            neutralize=[{"method": "File.exists", "detail": "x -> false"}],
            alive=True,
        )
        check, dm = self._check(mgr, alive=False)
        with mock.patch("checks.anti_hooking.classify_failure",
                        return_value={"is_rasp": True, "kind": "rasp_reaction"}):
            res = check.attempt_module_bypass("com.app", window=3)
        assert res["blocked"] is True
        assert res["success"] is False

    def test_run_all_maps_inconclusive_to_skip(self, tmp_path):
        """success=None no bypass de módulo => bypass_successful=None + reason."""
        apk = _make_apk(str(tmp_path / "x.apk"), {
            "classes.dex": b"de.robv.android.xposed.XposedBridge\x00",
        })
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        dm.run_shell_root.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        dm.spawn_app.return_value = FakeSession()
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = True
        check = AntiHookingCheck(dm, xposed=self._manager(observe=[], neutralize=[]))
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.run_all("com.app", apk_path=apk, window=3)
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is None
        assert "não exercitado" in res["bypass_skipped_reason"]


class TestRunAll:
    """Consolidação: vetores + estático + dinâmico + bypass."""

    @staticmethod
    def _mock_dm(session=None, alive=True):
        """Monta um DeviceManager mock compatível com o run_all."""
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        dm.run_shell_root.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        dm.spawn_app.return_value = session or FakeSession()
        dm.last_spawn_pid = 42
        dm.is_app_alive.return_value = alive
        return dm

    def test_no_protection_anywhere(self, tmp_path):
        """Sem sinal estático nem dinâmico => sem bypass, sem error."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {"classes.dex": b"plain"})
        dm = self._mock_dm()
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["protection_detected"] is False
        assert res["bypass_successful"] is None
        assert res["hook_frameworks_present"] is False
        assert "error" not in res
        dm.spawn_app.assert_called_once()  # só a observação

    def test_static_protection_with_bypass_success(self, tmp_path):
        """Assinatura no APK + neutralização => bypass_successful=True."""
        apk = _make_apk(str(tmp_path / "x.apk"), {
            "classes.dex": b"de.robv.android.xposed.XposedBridge\x00",
        })
        dm = self._mock_dm(session=FakeSession(bypass_messages=[
            _bypass("neutralizado: Class.forName('de.robv.android.xposed.XposedBridge') -> null"),
        ]))
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is True
        assert res["static_detection"]["static_detected"] is True

    def test_run_all_expoem_framework_runtime(self, tmp_path):
        """O framework identificado pelo gerenciador (nome/versão) entra nos checks.

        Antes isso só aparecia enterrado nos steps do bypass; agora é
        vetor de detecção com evidência própria.
        """
        apk = _make_apk(str(tmp_path / "x.apk"), {
            "classes.dex": b"de.robv.android.xposed.XposedBridge\x00",
        })
        dm = self._mock_dm()
        mgr = mock.MagicMock()
        mgr.detect.return_value = {
            "available": True, "name": "Vector", "version": "2.2",
            "details": "Vector 2.2 (módulos de framework: zygisk_vector)",
            "modules": ["zygisk_vector"],
        }
        check = AntiHookingCheck(dm, mode="detect", xposed=mgr)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.run_all("com.app", apk_path=apk)
        runtime = res["checks"]["hook_framework_runtime"]
        assert runtime["detected"] is True
        assert runtime["evidence"] == ["Vector 2.2"]
        assert "Vector 2.2" in runtime["details"]
        assert res["hook_frameworks_present"] is True
        assert res["bypass_successful"] is None  # modo detect

    def test_dynamic_protection_without_exercised_bypass_is_skip(self, tmp_path):
        """Detecção em runtime e bypass sem evidência => etapa não exercitada.

        Antes o resultado era ``bypass_successful=False`` (OK), o que
        afirmava que a proteção resistiu sem que nenhuma checagem
        anti-hook tivesse sido exercitada durante o bypass.
        """
        apk = _make_apk(str(tmp_path / "clean.apk"), {"classes.dex": b"plain"})
        dm = self._mock_dm(session=FakeSession(
            detection_messages=[_det("Class.forName", "org.lsposed.XposedBridge")],
            bypass_messages=[_bypass("libc.strstr hookado")],
        ))
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is None
        assert "não exercitado" in res["bypass_skipped_reason"]

    def test_weak_signals_do_not_trigger_bypass(self, tmp_path):
        """Só sinais fracos => sem proteção e sem fase de bypass."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {"classes.dex": b"plain"})
        dm = self._mock_dm(session=FakeSession(
            detection_messages=[_det("maps_scan", "/proc/self/maps via open")],
        ))
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["protection_detected"] is False
        assert res["bypass_successful"] is None
        dm.spawn_app.assert_called_once()

    def test_bypass_failure_keeps_protection_and_marks_step_not_run(self, tmp_path):
        """Bypass que não executa não invalida a proteção detectada.

        O que se sabe é que existe proteção anti-hook; o que não se sabe
        é se ela resistiu ao bypass. O resultado reflete as duas coisas.
        """
        apk = _make_apk(str(tmp_path / "x.apk"), {
            "classes.dex": b"de.robv.android.xposed.XposedBridge\x00",
        })
        dm = self._mock_dm()
        dm.spawn_app.side_effect = [FakeSession(), RuntimeError("spawn falhou")]
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is None
        assert "spawn falhou" in res["bypass_skipped_reason"]

    def test_bypass_blocked_by_app_is_a_resisted_protection(self, tmp_path):
        """App que bloqueia o bypass prova que a proteção resistiu.

        Não é uma etapa que não rodou: o app encerrou durante o bypass,
        e a proteção respondeu. O veredito é "resistiu", não "SKIP".
        """
        apk = _make_apk(str(tmp_path / "x.apk"), {
            "classes.dex": b"de.robv.android.xposed.XposedBridge\x00",
        })
        dm = self._mock_dm()
        dm.spawn_app.side_effect = [FakeSession(), FakeSession()]
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": "SIGKILL", "summary": "SIGKILL",
        }
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 42 42 I ActivityManager: "
            "Process com.app (pid 42) has died",
        ]
        dm.baseline = {"available": True, "alive_at_end": True}
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["protection_detected"] is True
        assert res["bypass_successful"] is False
        assert res["bypass_details"]["blocked"] is True

    def test_observation_failure_without_static_is_error(self, tmp_path):
        """Spawn da observação falha e sem APK => error (sem veredito)."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {"classes.dex": b"plain"})
        dm = self._mock_dm()
        dm.spawn_app.side_effect = RuntimeError("spawn falhou")
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["protection_detected"] is False
        assert "spawn falhou" in res["error"]
        assert res["app_detection"]["error"]

    def test_framework_presence_is_reported(self, tmp_path):
        """Framework instalado no device vira hook_frameworks_present."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {"classes.dex": b"plain"})
        dm = self._mock_dm()
        dm.run_shell.return_value = {
            "ok": True, "rc": 0,
            "stdout": "package:org.lsposed.manager\n", "stderr": "",
        }
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(dm).run_all("com.app", apk_path=apk)
        assert res["hook_frameworks_present"] is True
        assert res["checks"]["hook_framework_packages"]["detected"] is True

    def test_timestamp_present(self, tmp_path):
        """O resultado consolidado carrega timestamp ISO8601."""
        apk = _make_apk(str(tmp_path / "clean.apk"), {"classes.dex": b"plain"})
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = AntiHookingCheck(self._mock_dm()).run_all("com.app", apk_path=apk)
        assert res["timestamp"]
        assert "T" in res["timestamp"]


class TestLogcatCorrelation:
    """Correlação de logcat/baseline no anti-hooking."""

    def test_logcat_security_signal_is_detection(self):
        """Mensagem de segurança no logcat vira sinal forte."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 42 42 I com.app: detected xposed framework",
        ]
        check = AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(
                FakeSession(), window=2, pid=42, package_name="com.app",
                logcat_mark=0,
            )
        assert res["detected"] is True
        assert any(s.startswith("logcat_hooking") for s in res["strong_signals"])

    def test_crash_after_healthy_baseline_is_a_blocked_audit(self):
        """App que sobrevive sem instrumentação e morre com ela bloqueou a auditoria."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": "SIGSEGV", "summary": "SIGSEGV",
        }
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 42 42 F libc: Fatal signal 11 (SIGSEGV), pid 42",
        ]
        dm.baseline = {"available": True, "alive_at_end": True}
        check = AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(
                FakeSession(), window=2, pid=42, package_name="com.app",
                logcat_mark=0,
            )
        assert res["observation_status"] == "ok"
        assert res["death_classification"] == "rasp_reaction"
        assert res["detected"] is True

    def test_crash_without_baseline_is_inconclusive(self):
        """Sem baseline não há como atribuir a causa da morte."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": "SIGSEGV", "summary": "SIGSEGV",
        }
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 42 42 F libc: Fatal signal 11 (SIGSEGV), pid 42",
        ]
        dm.baseline = {"available": False}
        check = AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(
                FakeSession(), window=2, pid=42, package_name="com.app",
                logcat_mark=0,
            )
        assert res["observation_status"] == "crashed"
        assert res["death_classification"] == "instrumentation_crash"
        assert res["detected"] is False

    def test_baseline_death_is_not_detection(self):
        """Morte que também ocorre sem instrumentação não é anti-hook."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": None, "summary": "sem registro",
        }
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 42 42 I com.app: normal exit",
        ]
        dm.baseline = {"available": True, "alive_at_end": False}
        check = AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_hook_detection_in_app(
                FakeSession(), window=2, pid=42, package_name="com.app",
                logcat_mark=0,
            )
        assert res["death_classification"] == "baseline_death"
        assert res["observation_status"] == "baseline_death"
        assert res["error"]
        assert res["detected"] is False
