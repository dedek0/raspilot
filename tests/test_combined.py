"""Testes da observação/bypass combinados em sessão única."""

from __future__ import annotations

from unittest import mock

from checks.combined import run_combined_bypass, run_combined_observation


class _Script:
    def __init__(self, messages):
        self.messages = messages
        self._cb = None
        self.unloaded = False

    def on(self, event, cb):
        self._cb = cb

    def load(self):
        for msg in self.messages:
            self._cb(msg, None)

    def unload(self):
        self.unloaded = True


class _Session:
    def __init__(self, messages=None):
        self.messages = messages or []
        self.sources = []
        self.detached = False

    def create_script(self, source, **kwargs):
        self.sources.append(source)
        return _Script(self.messages)

    def detach(self):
        self.detached = True


def test_combined_observation_runs_one_session():
    """Observação combinada carrega fase nativa + Java uma única vez."""
    dm = mock.MagicMock()
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    session = _Session()
    resumed = []
    with mock.patch("checks.combined.time.sleep"):
        frida, hooking = run_combined_observation(
            dm, session, 42, "com.example.app", 1, 0,
            on_resume=lambda: resumed.append(True),
        )
    assert resumed == [True]
    assert len(session.sources) == 2
    assert frida["vulnerable"] is True
    assert hooking["detected"] is False


def test_combined_observation_no_java():
    """--no-java carrega apenas a fase nativa."""
    dm = mock.MagicMock()
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    session = _Session()
    with mock.patch("checks.combined.time.sleep"):
        frida, hooking = run_combined_observation(
            dm, session, 42, "com.example.app", 1, 0,
            on_resume=lambda: None, no_java=True,
        )
    assert len(session.sources) == 1
    assert frida["java_skipped"] is True
    assert hooking["java_skipped"] is True


def test_combined_bypass_reuses_one_spawn():
    """Anti-hooking e SSL compartilham o mesmo spawn de bypass."""
    messages = [
        {"type": "send", "payload": {
            "type": "raspilot-hooking-bypass",
            "message": "neutralizado: Class.forName -> null",
        }},
        {"type": "send", "payload": {
            "type": "ssl-bypass-host", "host": "api.example",
        }},
        {"type": "send", "payload": {
            "type": "ssl-bypass",
            "message": "CertificatePinner.check bypass (api.example)",
        }},
    ]
    dm = mock.MagicMock()
    dm.spawn_app.return_value = _Session(messages)
    dm.last_spawn_pid = 42
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    with mock.patch("checks.combined.time.sleep"):
        hooking, ssl = run_combined_bypass(
            dm, "com.example.app", 1, mode="bypass"
        )
    dm.spawn_app.assert_called_once()
    assert hooking["success"] is True
    assert ssl["success"] is True
    assert ssl["intercepted_hosts"] == ["api.example"]
