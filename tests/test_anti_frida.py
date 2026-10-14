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

    def create_script(self, source):
        return FakeScript(self._messages)


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


class TestAppDetection:
    """Observação de detecção de Frida pelo app."""

    def test_app_without_protection_is_vulnerable(self):
        """App que não chama nada relacionado a frida => vulnerable=True."""
        check = AntiFridaCheck(mock.MagicMock())
        session = FakeSession(messages=[])
        with mock.patch("checks.anti_frida.time.sleep"):
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
        with mock.patch("checks.anti_frida.time.sleep"):
            res = check.check_frida_detection_in_app(session)
        assert res["vulnerable"] is False
        assert any("Runtime.exec" in m for m in res["detection_methods_found"])

    def test_detection_script_exists(self):
        """O script de observação contém os hooks essenciais."""
        assert "strstr" in DETECTION_SCRIPT
        assert "Runtime.exec" in DETECTION_SCRIPT
        assert "File.exists" in DETECTION_SCRIPT


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
        with mock.patch("checks.anti_frida.time.sleep"):
            res = check.run_all(session, pid=1234)
        assert res["vulnerable"] is True
        assert res["frida_present"] is True
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
        with mock.patch("checks.anti_frida.time.sleep"):
            res = check.run_all(session, pid=1234)
        assert res["vulnerable"] is False
        assert res["app_detection"]["detection_methods_found"]
