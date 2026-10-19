"""Testes do AntiFridaCheck — presença de Frida e detecção pelo app."""

from __future__ import annotations

from unittest import mock

from checks.anti_frida import DETECTION_SCRIPT, AntiFridaCheck


class FakeModule:
    """Módulo Frida fake (apenas .name)."""

    def __init__(self, name: str):
        self.name = name


class FakeScript:
    """Script Frida fake que dispara mensagens pré-definidas no load."""

    def __init__(self, messages):
        self.messages = messages
        self._cb = None

    def on(self, event, cb):
        self._cb = cb

    def load(self):
        for msg in self.messages:
            self._cb(msg, None)

    def unload(self):
        pass


class FakeSession:
    """Sessão Frida fake com módulos e mensagens configuráveis."""

    def __init__(self, modules=None, messages=None):
        self._modules = modules or []
        self._messages = messages or []

    def enumerate_modules(self):
        return self._modules

    def create_script(self, source, **kwargs):
        return FakeScript(self._messages)


class FakeScriptExports:
    """Script Frida fake que expõe ``exports.listmodules()`` (RPC)."""

    def __init__(self, names):
        self._names = names
        self.unloaded = False

    class _Exports:
        def __init__(self, names):
            self._names = names

        def listmodules(self):
            return self._names

    @property
    def exports(self):
        return FakeScriptExports._Exports(self._names)

    def load(self):
        pass

    def unload(self):
        self.unloaded = True


class FakeSessionNoEnum:
    """Sessão Frida 17 fake, sem ``enumerate_modules`` no host."""

    def __init__(self, names):
        self._names = names
        self.created = None

    def create_script(self, source, **kwargs):
        self.created = FakeScriptExports(self._names)
        return self.created


class TestDeviceVectors:
    """Vetores de dispositivo (processos, portas, threads)."""

    def test_frida_processes_detected(self, fake_dm_factory):
        """frida-server no ps é detectado."""
        dm = fake_dm_factory(
            {"ps -A 2>/dev/null | grep -i frida": "root 999 1 0 0 0 S frida-server"}
        )
        res = AntiFridaCheck(dm).check_frida_processes()
        assert res["detected"] is True
        assert "frida-server" in " ".join(res["evidence"])

    def test_frida_processes_absent(self, fake_dm_factory):
        """Sem frida no ps o vetor é negativo."""
        dm = fake_dm_factory({"ps -A": "u0 123 500 0 0 0 S com.example.app"})
        res = AntiFridaCheck(dm).check_frida_processes()
        assert res["detected"] is False

    def test_frida_ports_via_netstat(self, fake_dm_factory):
        """Porta 27042 via netstat é detectada."""
        dm = fake_dm_factory(
            {"netstat -tlnp": "tcp 0 0 127.0.0.1:27042 0.0.0.0:* LISTEN 999/frida"}
        )
        res = AntiFridaCheck(dm).check_frida_ports()
        assert res["detected"] is True

    def test_frida_ports_via_proc_net_tcp(self, fake_dm_factory):
        """Fallback /proc/net/tcp com porta em hex (69A2 = 27042)."""
        dm = fake_dm_factory(
            {
                "netstat -tlnp": "",
                "ss -tlnp": "",
                "/proc/net/tcp ": (
                    "  sl  local_address rem_address\n"
                    "   1: 0100007F:69A2 00000000:0000 0A\n"
                ),
            }
        )
        res = AntiFridaCheck(dm).check_frida_ports()
        assert res["detected"] is True

    def test_frida_ports_absent(self, fake_dm_factory):
        """Sem portas Frida o vetor é negativo."""
        dm = fake_dm_factory(
            {"netstat": "", "ss": "", "/proc/net/tcp": "  sl local\n   1: 0100007F:0016\n"}
        )
        res = AntiFridaCheck(dm).check_frida_ports()
        assert res["detected"] is False

    def test_frida_threads_detected(self, fake_dm_factory):
        """Thread gum-js-loop é detectada em /proc/pid/task."""
        dm = fake_dm_factory(
            {"task/*/comm": "com.example.app\ngum-js-loop\nBinder:1_1\n"}
        )
        res = AntiFridaCheck(dm).check_frida_threads(1234)
        assert res["detected"] is True
        assert "gum-js-loop" in res["evidence"]

    def test_frida_libraries_detected(self):
        """libfrida-gadget.so no processo é detectada via session."""
        check = AntiFridaCheck(mock.MagicMock())
        session = FakeSession(modules=[FakeModule("libfrida-gadget.so")])
        res = check.check_frida_libraries(1, session=session)
        assert res["detected"] is True
        assert "libfrida-gadget.so" in res["evidence"]

    def test_frida_libraries_absent(self):
        """Sem libs Frida o vetor é negativo."""
        check = AntiFridaCheck(mock.MagicMock())
        session = FakeSession(modules=[FakeModule("libc.so"), FakeModule("libtarget.so")])
        res = check.check_frida_libraries(1, session=session)
        assert res["detected"] is False

    def test_frida_libraries_via_rpc_without_host_enum(self):
        """Frida 17 (sem Session.enumerate_modules) enumera via RPC no script."""
        check = AntiFridaCheck(mock.MagicMock())
        session = FakeSessionNoEnum(["libc.so", "libfrida-gadget.so"])
        res = check.check_frida_libraries(1, session=session)
        assert res["detected"] is True
        assert "libfrida-gadget.so" in res["evidence"]
        assert session.created.unloaded is True

    def test_frida_libraries_rpc_error_is_captured(self):
        """Erro de load/enumeração via RPC vira error estruturado."""
        class _BadSession:
            def create_script(self, source, **kwargs):
                raise RuntimeError("load falhou")

        check = AntiFridaCheck(mock.MagicMock())
        res = check.check_frida_libraries(1, session=_BadSession())
        assert res["detected"] is False
        assert "load falhou" in res["error"]


class TestAppDetection:
    """Observação de detecção de Frida pelo app."""

    def test_app_without_protection_is_vulnerable(self):
        """App que não chama nada relacionado a frida => vulnerable=True."""
        check = AntiFridaCheck(mock.MagicMock())
        session = FakeSession(messages=[])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(session)
        assert res["vulnerable"] is True
        assert res["detection_methods_found"] == []

    def test_app_with_protection_is_not_vulnerable(self):
        """App que executa Runtime.exec('frida') => vulnerable=False + evidência."""
        check = AntiFridaCheck(mock.MagicMock())
        session = FakeSession(messages=[{
            "type": "send",
            "payload": {"method": "Runtime.exec", "detail": "ls /data/local/tmp/frida-server"},
        }])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(session)
        assert res["vulnerable"] is False
        assert any("Runtime.exec" in m for m in res["detection_methods_found"])

    def test_detection_script_exists(self):
        """O script de observação contém os hooks essenciais."""
        assert "strstr" in DETECTION_SCRIPT
        assert "Runtime.exec" in DETECTION_SCRIPT
        assert "File.exists" in DETECTION_SCRIPT
        # Técnicas nativas comuns (sem string 'frida' no alvo):
        assert "native_connect" in DETECTION_SCRIPT
        assert "27042" in DETECTION_SCRIPT
        assert "openat" in DETECTION_SCRIPT
        assert "faccessat" in DETECTION_SCRIPT
        assert "'access'" in DETECTION_SCRIPT
        assert "'stat'" in DETECTION_SCRIPT
        # Compatibilidade Frida 16/17 (validada em dispositivo real):
        assert "raspilotFindExport" in DETECTION_SCRIPT
        assert "raspilotPerformJava" in DETECTION_SCRIPT
        assert "Module.findExportByName" not in DETECTION_SCRIPT

    def test_hook_install_errors_not_counted(self):
        """Erros de instalação do próprio script não viram detecção."""
        check = AntiFridaCheck(mock.MagicMock())
        session = FakeSession(messages=[{
            "type": "send",
            "payload": {"type": "frida-detection-error",
                        "message": "instalação de strstr falhou"},
        }])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(session)
        assert res["vulnerable"] is True
        assert res["detection_methods_found"] == []

    def test_app_death_during_observation_is_not_vulnerable(self):
        """App que se encerra na janela => reação do RASP, vulnerable=False."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        check = AntiFridaCheck(dm)
        session = FakeSession(messages=[])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(session, window=3, pid=99)
        assert res["vulnerable"] is False
        assert res["app_alive_at_end"] is False
        assert any("app_terminated" in m for m in res["detection_methods_found"])

    def test_app_alive_reports_app_alive_at_end(self):
        """App vivo ao fim da janela => app_alive_at_end=True."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = True
        check = AntiFridaCheck(dm)
        session = FakeSession(messages=[])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(session, window=3, pid=99)
        assert res["app_alive_at_end"] is True
        assert res["vulnerable"] is True


class TestRunAll:
    """Consolidação."""

    def test_vulnerable_when_no_app_detection(self, fake_dm_factory):
        """frida ativo + app sem detecção => vulnerable=True."""
        dm = fake_dm_factory({
            "ps -A | grep -i frida": "root 999 1 0 0 0 S frida-server",
            "netstat": "tcp 0 0 127.0.0.1:27042 0.0.0.0:* LISTEN",
            "task/*/comm": "com.example.app",
        })
        check = AntiFridaCheck(dm)
        session = FakeSession(messages=[])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.run_all(session, pid=1234)
        assert res["vulnerable"] is True
        assert res["frida_present"] is True
        assert res["frida_injected_by_tool"] is True
        assert res["frida_pid"] == 1234

    def test_not_vulnerable_with_app_detection(self, fake_dm_factory):
        """App detecta frida => vulnerable=False (proteção funcionou)."""
        dm = fake_dm_factory({
            "ps -A | grep -i frida": "root 999 1 0 0 0 S frida-server",
            "netstat": "tcp 0 0 127.0.0.1:27042 0.0.0.0:* LISTEN",
            "task/*/comm": "gum-js-loop",
        })
        check = AntiFridaCheck(dm)
        session = FakeSession(messages=[{
            "type": "send",
            "payload": {"method": "File.exists", "detail": "/data/local/tmp/frida-server"},
        }])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.run_all(session, pid=1234)
        assert res["vulnerable"] is False
        assert res["app_detection"]["detection_methods_found"]


class TestObservationReliability:
    """Correlação de erro/logcat/baseline no veredito anti-Frida."""

    def test_observation_error_is_error_not_vulnerable(self):
        """Falha ao carregar o script vira error inconclusivo, não FALHOU."""
        class _BadSession:
            def create_script(self, source, **kwargs):
                raise RuntimeError("script load falhou")

        check = AntiFridaCheck(mock.MagicMock())
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(_BadSession())
        assert res["vulnerable"] is None
        assert res["observation_status"] == "error"
        assert "script load falhou" in res["error"]

    def test_logcat_security_signal_marks_detection(self):
        """Sinal de segurança no logcat conta como detecção mesmo sem hook."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 1234 1234 I com.app: detected frida-server",
        ]
        check = AntiFridaCheck(dm)
        session = FakeSession(messages=[])
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(
                session, window=2, pid=1234, package_name="com.app", logcat_mark=0
            )
        assert res["vulnerable"] is False
        assert any(s.startswith("logcat_frida") for s in res["detection_methods_found"])

    def test_crash_without_security_is_inconclusive(self):
        """Crash nativo sem evidência de segurança não vira proteção OK."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": "SIGSEGV", "summary": "sinal fatal SIGSEGV",
        }
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 1234 1234 F libc: Fatal signal 11 (SIGSEGV), pid 1234",
        ]
        dm.baseline = {"available": True, "alive_at_end": True}
        check = AntiFridaCheck(dm)
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(
                FakeSession(messages=[]), window=2, pid=1234,
                package_name="com.app", logcat_mark=0,
            )
        assert res["vulnerable"] is None
        assert res["observation_status"] == "crashed"
        assert res["death_classification"] == "instrumentation_crash"

    def test_baseline_death_is_not_rasp_detection(self):
        """Morte que já ocorre no baseline não é reação ao Frida."""
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = False
        dm.capture_death_cause.return_value = {
            "evidence": [], "signal": None, "summary": "sem registro externo",
        }
        dm.logcat_since.return_value = [
            "10-16 10:00:00.000 1234 1234 I com.app: normal shutdown",
        ]
        dm.baseline = {"available": True, "alive_at_end": False}
        check = AntiFridaCheck(dm)
        with mock.patch("checks.anti_frida.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.check_frida_detection_in_app(
                FakeSession(messages=[]), window=2, pid=1234,
                package_name="com.app", logcat_mark=0,
            )
        assert res["death_classification"] == "baseline_death"
        assert res["observation_status"] == "baseline_death"
        assert res["vulnerable"] is None
        assert res["error"]

    def test_stealth_port_is_checked(self, fake_dm_factory):
        """A porta stealth real (não só 27042/27043) é procurada."""
        dm = fake_dm_factory(
            {"netstat -tlnp": "tcp 0 0 127.0.0.1:27999 0.0.0.0:* LISTEN"}
        )
        dm.frida_port = 27999
        res = AntiFridaCheck(dm).check_frida_ports()
        assert res["detected"] is True
        assert 27999 in res["ports_checked"]

    def test_detection_script_has_port_placeholder(self):
        """O script usa o placeholder para receber a porta real no load."""
        assert "__RASPILOT_FRIDA_PORT__" in DETECTION_SCRIPT
