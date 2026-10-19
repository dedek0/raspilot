"""Testes do bootstrap nativo de stealth."""

from __future__ import annotations

from checks.stealth import (
    ANTI_FRIDA_BYPASS_SCRIPT,
    PROC_FILTER_SCRIPT,
    load_stealth,
    unload_stealth,
)


class _Script:
    def __init__(self):
        self.unloaded = False

    def on(self, event, cb):
        pass

    def load(self):
        pass

    def unload(self):
        self.unloaded = True


class _Session:
    def __init__(self):
        self.sources = []
        self.scripts = []

    def create_script(self, source, **kwargs):
        script = _Script()
        self.sources.append(source)
        self.scripts.append(script)
        return script


def test_load_stealth_is_native_only_and_returns_scripts():
    """Stealth carrega proc_filter + bypass nativo sem bridge Java."""
    session = _Session()
    loaded = load_stealth(
        session,
        replacements={"__RASPILOT_FRIDA_PORT__": "27999"},
    )
    assert len(loaded) == 2
    assert len(session.sources) == 2
    for source in session.sources:
        assert "var Java = bridge;" not in source
    assert any("syscall" in src and "TracerPid" in src for src in session.sources)
    assert any("pthread_setname_np" in src for src in session.sources)
    unload_stealth(loaded)
    assert all(script.unloaded for script in session.scripts)


def test_script_files_exist_and_cover_hardening():
    """Os scripts de stealth existem e cobrem readlink/ptrace/syscall."""
    import os

    assert os.path.isfile(PROC_FILTER_SCRIPT)
    assert os.path.isfile(ANTI_FRIDA_BYPASS_SCRIPT)
    with open(PROC_FILTER_SCRIPT, encoding="utf-8") as fh:
        source = fh.read()
    for marker in (
        "readlink", "readlinkat", "ptrace", "syscall", "TracerPid",
        "libloader64_v8", "libloader32_v7", "pthread_setname_np",
    ):
        assert marker in source, f"filtro ausente: {marker}"
