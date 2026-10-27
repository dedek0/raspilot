"""Testes da observação/bypass combinados em sessão única."""

from __future__ import annotations

from unittest import mock

from checks.combined import _hooking_detection, run_combined_bypass, run_combined_observation


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
        messages = list(self.messages)
        if "var Java = bridge;" in source:
            # A camada Java e instalada de forma adiada: o script
            # sinaliza a prontidao depois do carregamento.
            messages.append({"type": "send", "payload": {
                "type": "raspilot-java-ready", "label": "fake"}})
        return _Script(messages)

    def detach(self):
        self.detached = True


# Marcadores estáveis de cada camada carregada. Verificar *o que* foi
# carregado é mais robusto do que contar scripts: a composição das
# camadas muda conforme o modo, mas o comportamento exigido não.
def _has(source, marker):
    return marker in source


def _count(session, marker):
    return sum(1 for src in session.sources if _has(src, marker))


def _java_sources(session):
    """Fontes carregadas com a bridge Java."""
    return [src for src in session.sources if _has(src, "var Java = bridge;")]


def test_combined_observation_runs_one_session():
    """Observação combinada carrega as camadas nativa e Java uma única vez."""
    dm = mock.MagicMock()
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    session = _Session()
    resumed = []
    with mock.patch("checks.combined.OBSERVATION_POLL_INTERVAL", 0.0):
        frida, hooking = run_combined_observation(
            dm, session, 42, "com.example.app", 1, 0,
            on_resume=lambda: resumed.append(True),
        )
    assert resumed == [True]
    # camada Java carregada uma única vez, com a bridge
    assert _count(session, "var Java = bridge;") == 1
    # a fase nativa carrega o mesmo script de detecção, sem a bridge
    assert _count(session, "frida-detection") == 2
    assert frida["vulnerable"] is True
    assert hooking["detected"] is False


def test_combined_observation_no_java():
    """--no-java não carrega a bridge Java."""
    dm = mock.MagicMock()
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    session = _Session()
    with mock.patch("checks.combined.OBSERVATION_POLL_INTERVAL", 0.0):
        frida, hooking = run_combined_observation(
            dm, session, 42, "com.example.app", 1, 0,
            on_resume=lambda: None, no_java=True,
        )
    assert _count(session, "var Java = bridge;") == 0
    assert frida["java_skipped"] is True
    assert hooking["java_skipped"] is True


def test_combined_observation_mode_detect_does_not_neutralize():
    """No modo detect a evasão fica desligada: a reação do app precisa
    acontecer para ser observada."""
    dm = mock.MagicMock()
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    session = _Session()
    with mock.patch("checks.combined.OBSERVATION_POLL_INTERVAL", 0.0):
        run_combined_observation(
            dm, session, 42, "com.example.app", 1, 0,
            on_resume=lambda: None, mode="detect",
        )
    assert _count(session, "auto-destruição neutralizada") == 0


def test_combined_observation_never_loads_the_evasion():
    """Observar a detecção exige que a reação do app possa acontecer.

    Com a evasão anti-Frida ativa, o app não enxerga os artefatos de
    instrumentação e a observação não observa nada — o check mediria a
    stealth da ferramenta, e não a proteção do app. A evasão pertence à
    etapa de bypass.
    """
    for mode in ("detect", "bypass", "stealth"):
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = []
        dm.baseline = None
        session = _Session()
        with mock.patch("checks.combined.OBSERVATION_POLL_INTERVAL", 0.0):
            run_combined_observation(
                dm, session, 42, "com.example.app", 1, 0,
                on_resume=lambda: None, mode=mode,
            )
        assert _count(session, "auto-destruição neutralizada") == 0, mode


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
    with mock.patch("checks.combined.OBSERVATION_POLL_INTERVAL", 0.0):
        hooking, ssl = run_combined_bypass(
            dm, "com.example.app", 1, mode="bypass"
        )
    dm.spawn_app.assert_called_once()
    assert hooking["success"] is True
    assert ssl["success"] is True
    assert ssl["intercepted_hosts"] == ["api.example"]


def test_combined_bypass_loads_java_layers_in_one_script():
    """Os scripts Java do bypass são carregados em um único script, o que
    compila a bridge uma vez só."""
    dm = mock.MagicMock()
    dm.spawn_app.return_value = _Session()
    dm.last_spawn_pid = 42
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    with mock.patch("checks.combined.OBSERVATION_POLL_INTERVAL", 0.0):
        run_combined_bypass(dm, "com.example.app", 1, mode="bypass")
    # uma única compilação da bridge
    java_sources = _java_sources(dm.spawn_app.return_value)
    assert len(java_sources) == 1
    # e as três camadas Java presentes no mesmo script
    assert "CertificatePinner" in java_sources[0]
    assert "kill-trace" in java_sources[0]


def test_combined_bypass_includes_the_verdict_hook_in_the_bundle():
    """O hook de veredito compartilha o bundle: bridge compilada uma vez."""
    dm = mock.MagicMock()
    dm.spawn_app.return_value = _Session()
    dm.last_spawn_pid = 42
    dm.is_app_alive.return_value = True
    dm.logcat_since.return_value = []
    dm.baseline = None
    with mock.patch("checks.combined.OBSERVATION_POLL_INTERVAL", 0.0):
        run_combined_bypass(dm, "com.example.app", 1, mode="bypass")
    java_sources = _java_sources(dm.spawn_app.return_value)
    assert len(java_sources) == 1
    assert "VERDICT_METHODS" in java_sources[0]
    # o catálogo do host substitui os placeholders do script
    assert "__RASPILOT_VERDICT_METHODS__" not in java_sources[0]


def test_hooking_death_without_hook_signal_is_not_attributed():
    """Morte causada por detecção de Frida não vira proteção anti-hook."""
    logcat = {
        "available": True,
        "death": {"kind": "crash", "detected": True},
        "crash_origin": "app",
        "categories": {"frida_agent_crash": 3},
        "security_signals": [
            {"category": "frida_agent_crash", "confidence": "low", "line": "agent"},
        ],
        "instrumentation_kill": False,
    }
    result = _hooking_detection(
        found=[],
        strong=[],
        weak=[],
        logcat=logcat,
        baseline={"available": True, "alive_at_end": True},
        died_after=5,
        app_alive=False,
        java_load_error=None,
        java_skipped=False,
        stealth_used=False,
        window=10,
    )
    assert result["detected"] is False
    assert result["death_classification"] == "unattributed_death"
    assert not any("frida_agent_crash" in item for item in result["detection_methods_found"])
