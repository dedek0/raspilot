"""Testes da camada de sessão e da retomada por etapas (fase 3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import main as mainmod
import service as service_mod
import sessions as sessions_mod
from service import RaspilotService, RunConfig, SessionStateError
from sessions import SessionBusy, SessionNotFound, SessionStore


class FakeDevice:
    """DeviceManager mínimo para o serviço, sem adb/Frida reais."""

    def __init__(self, serial: str = "SER1"):
        self.device_id = serial
        self.frida_port = 27999
        self.baseline = {"available": False, "reason": "mock"}
        self._logcat_available = False
        self.shell_calls = []

    def connect_adb(self):
        return True

    def get_device_info(self):
        return {
            "serial": self.device_id,
            "model": "Pixel 7",
            "android_version": "14",
            "sdk": "34",
            "abi": "arm64-v8a",
            "is_rooted_shell": False,
            "root_via_su": False,
        }

    def setup_frida_server(self):
        return True

    def start_logcat_capture(self):
        return False

    def stop_logcat_capture(self):
        return None

    def logcat_mark(self):
        return 0

    def run_app_baseline(self, package, window=5):
        return self.baseline

    def run_shell(self, command, timeout=20):
        self.shell_calls.append(command)
        return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

    def spawn_app(self, package, resume=True):
        return object()

    def get_app_pid(self, package):
        return 123

    def resume_app(self):
        return None

    def is_app_alive(self, pid):
        return True

    def remove_frida_server(self):
        return None

    def _detect_abi(self):
        return "arm64-v8a"


def _config(tmp_path, **kwargs):
    defaults = dict(
        package="com.example.app",
        output_dir=str(tmp_path / "out"),
        static_engine="off",
        hook_method="frida",
        emulator_method="frida",
        window=1,
    )
    defaults.update(kwargs)
    return RunConfig(**defaults)


def _fake_results(svc):
    """Substitui o pipeline por resultados determinísticos."""
    svc.reporter.collect(
        "anti_root",
        {
            "is_rooted": False,
            "evaluated_vectors": ["su"],
            "positive_vectors": [],
            "protection_detected": True,
            "bypass_successful": True,
        },
    )
    svc.reporter.collect(
        "anti_frida",
        {
            "vulnerable": True,
            "frida_present": True,
            "app_detection": {"detected": False},
        },
    )


# ----------------------------------------------------------------------
# Store
# ----------------------------------------------------------------------
def test_store_lifecycle_and_atomic_session_json(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app", {"mode": "bypass"})

    path = Path(state.directory) / "session.json"
    assert path.is_file()
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["session_id"] == state.session_id
    assert doc["schema_version"] == sessions_mod.SESSION_SCHEMA

    loaded = store.load(state.session_id)
    assert loaded.package == "com.example.app"
    assert loaded.config["mode"] == "bypass"
    assert [item.session_id for item in store.list()] == [state.session_id]

    with pytest.raises(SessionNotFound):
        store.load("nao-existe")


def test_prune_keeps_last_15(tmp_path, monkeypatch):
    clock = {"value": 0}

    def fake_now():
        clock["value"] += 1
        return f"2026-01-01T00:00:{clock['value']:02d}+00:00"

    monkeypatch.setattr(sessions_mod, "_now", fake_now)
    store = SessionStore(str(tmp_path / "sessions"), keep=15)
    ids = [store.create("com.example.app").session_id for _ in range(20)]

    remaining = {item.session_id for item in store.list()}
    assert len(remaining) == 15
    assert not remaining & set(ids[:5])
    assert set(ids[-15:]) <= remaining


def test_lock_is_exclusive_per_device(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    with store.lock("device:SER1"):
        with pytest.raises(SessionBusy):
            with store.lock("device:SER1"):
                pass
    # Liberado, pode ser reutilizado.
    with store.lock("device:SER1"):
        pass


def test_resources_catalog_uses_stable_uris(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    state.results = {"anti_root": {}}
    resources = store.resources(state)
    base = f"raspilot://sessions/{state.session_id}"
    assert "raspilot://sessions" in resources
    assert f"{base}/report.json" in resources
    assert f"{base}/static.json" in resources
    assert f"{base}/checks/anti_root.json" in resources


# ----------------------------------------------------------------------
# Serviço
# ----------------------------------------------------------------------
def test_static_stage_persists_profile_and_apk_identity(tmp_path, monkeypatch):
    profile = {
        "available": True,
        "engine": "builtin",
        "apk": {"sha256": "abc123", "names": ["base.apk"]},
        "summary": {"vectors": {}},
    }
    monkeypatch.setattr(
        service_mod, "build_static_profile", lambda *a, **k: profile
    )
    config = _config(tmp_path, stage="static", apk="/tmp/app.apk")
    store = SessionStore(str(tmp_path / "sessions"))
    svc = RaspilotService.create(config, store=store)
    result = svc.run_static()

    assert result.profile == profile
    state = store.load(svc.state.session_id)
    assert state.stage == "static"
    assert state.static == profile
    assert state.apk["sha256"] == "abc123"
    session_dir = Path(state.directory)
    assert json.loads((session_dir / "static.json").read_text()) == profile


def test_bypass_requires_detect_in_same_session(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    config = _config(tmp_path, stage="bypass", session_id=state.session_id)
    svc = RaspilotService.resume(config, store=store, device=FakeDevice())
    with pytest.raises(SessionStateError, match="detect"):
        svc.run_dynamic()


def test_resume_uses_saved_static_profile(tmp_path, monkeypatch):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    state.stage = "static"
    state.static = {
        "available": True,
        "apk": {"sha256": "same"},
        "summary": {"vectors": {}},
    }
    store.save(state)

    monkeypatch.setattr(
        service_mod,
        "build_static_profile",
        lambda *a, **k: pytest.fail("não deveria refazer o estático"),
    )
    monkeypatch.setattr(service_mod, "apk_digest", lambda paths: "same")
    config = _config(
        tmp_path, stage="detect", apk="/tmp/app.apk",
        static_engine="builtin", session_id=state.session_id,
    )
    svc = RaspilotService.resume(config, store=store, device=FakeDevice())
    svc._ensure_static_current()
    assert svc.static_profile == state.static


def test_apk_change_invalidates_dynamic_results(tmp_path, monkeypatch):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    state.stage = "detect"
    state.static = {
        "available": True,
        "apk": {"sha256": "old"},
        "summary": {"vectors": {}},
    }
    state.results = {"anti_root": {"is_rooted": False}}
    store.save(state)

    new_profile = {
        "available": True,
        "apk": {"sha256": "new"},
        "summary": {"vectors": {}},
    }
    monkeypatch.setattr(service_mod, "apk_digest", lambda paths: "new")
    monkeypatch.setattr(
        service_mod, "build_static_profile", lambda *a, **k: new_profile
    )
    config = _config(
        tmp_path, stage="detect", apk="/tmp/app.apk",
        static_engine="builtin", session_id=state.session_id,
    )
    svc = RaspilotService.resume(config, store=store, device=FakeDevice())
    svc._ensure_static_current()

    assert svc.static_profile == new_profile
    assert svc.state.results == {}
    assert svc.state.stage == "static"
    assert svc.state.invalidations


def test_detect_then_bypass_resumes_without_static(tmp_path, monkeypatch):
    state = SessionStore(str(tmp_path / "sessions")).create("com.example.app")
    store = SessionStore(str(tmp_path / "sessions"))
    state.stage = "static"
    state.static = {
        "available": True,
        "apk": {"sha256": "same"},
        "summary": {"vectors": {}},
    }
    store.save(state)

    monkeypatch.setattr(
        service_mod,
        "build_static_profile",
        lambda *a, **k: pytest.fail("não deveria refazer o estático"),
    )
    monkeypatch.setattr(
        RaspilotService, "_static_matches_device", lambda self: True
    )

    def fake_checks(svc):
        svc.reporter.collect(
            "anti_root",
            {"mode": svc.config.mode, "is_rooted": False,
             "evaluated_vectors": [], "positive_vectors": []},
        )

    monkeypatch.setattr(RaspilotService, "_run_checks", fake_checks)

    config = _config(
        tmp_path, stage="detect", session_id=state.session_id,
        static_engine="builtin",
    )
    svc = RaspilotService.resume(config, store=store, device=FakeDevice())
    svc.run_detection()
    assert svc.state.stage == "detect"
    assert svc.state.results["anti_root"]["mode"] == "detect"

    svc.run_bypass()
    assert svc.state.stage == "bypass"
    assert svc.state.results["anti_root"]["mode"] == "bypass"
    assert not svc.state.invalidations


def test_cli_detect_then_bypass_reuses_saved_static(tmp_path, monkeypatch):
    """Fluxo CLI real: static → detect → bypass sem refazer o estático."""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk")
    profile = {
        "available": True,
        "engine": "builtin",
        "apk": {"sha256": "same"},
        "summary": {"vectors": {}},
    }
    monkeypatch.setattr(
        service_mod, "build_static_profile", lambda *a, **k: profile
    )
    monkeypatch.setattr(
        service_mod, "DeviceManager", lambda **kwargs: FakeDevice()
    )
    monkeypatch.setattr(
        RaspilotService, "_run_checks",
        lambda self: _fake_results(self),
    )

    out = tmp_path / "out"
    rc = mainmod.main([
        "--package", "com.example.app",
        "--stage", "static", "--apk", str(apk),
        "--output-dir", str(out), "--static-engine", "builtin",
    ])
    assert rc == 0
    state = SessionStore().list()[0]

    common = [
        "--session", state.session_id,
        "--output-dir", str(out),
        "--hook-method", "frida", "--emulator-method", "frida",
        "--static-engine", "builtin",
    ]
    assert mainmod.main(["--stage", "detect", *common]) == 0
    assert store_stage(state.session_id) == "detect"

    # A partir daqui, refazer o estático seria um bug.
    monkeypatch.setattr(
        service_mod, "build_static_profile",
        lambda *a, **k: pytest.fail("estático refeito no bypass"),
    )
    monkeypatch.setattr(service_mod, "apk_digest", lambda paths: "same")
    assert mainmod.main(["--stage", "bypass", *common]) == 0
    final = SessionStore().load(state.session_id)
    assert final.stage == "bypass"
    assert set(final.results) == {"anti_root", "anti_frida"}
    assert not final.invalidations


def store_stage(session_id: str) -> str:
    """Atalho de teste para a etapa persistida."""
    return SessionStore().load(session_id).stage


def test_full_run_persists_session_and_report(tmp_path, monkeypatch):
    monkeypatch.setattr(RaspilotService, "_run_checks", _fake_results)
    config = _config(tmp_path, stage="full")
    store = SessionStore(str(tmp_path / "sessions"))
    svc = RaspilotService.create(
        config, store=store, device=FakeDevice()
    )
    result = svc.run_dynamic()

    state = store.load(state_id := svc.state.session_id)
    session_dir = Path(state.directory)
    assert state.stage == "full"
    assert state.status == "succeeded"
    assert state.device["serial"] == "SER1"
    assert set(state.results) == {"anti_root", "anti_frida"}
    assert (session_dir / "report.json").is_file()
    assert (session_dir / "summary.json").is_file()
    assert (session_dir / "report.html").is_file()
    assert (session_dir / "checks" / "anti_root.json").is_file()
    assert state.reports["report_json"].endswith("report.json")
    assert result.json_path and Path(result.json_path).is_file()
    assert state_id


def test_report_stage_regenerates_without_device(tmp_path, monkeypatch):
    monkeypatch.setattr(RaspilotService, "_run_checks", _fake_results)
    config = _config(tmp_path, stage="full")
    store = SessionStore(str(tmp_path / "sessions"))
    svc = RaspilotService.create(
        config, store=store, device=FakeDevice()
    )
    svc.run_dynamic()
    state = store.load(svc.state.session_id)
    original = json.loads(
        (Path(state.directory) / "report.json").read_text(encoding="utf-8")
    )

    # Serviço sem device algum, só com o estado salvo.
    report_config = _config(tmp_path, stage="report", session_id=state.session_id)
    report_svc = RaspilotService.resume(report_config, store=store)
    result = report_svc.generate_report()

    assert Path(result.json_path).is_file()
    assert Path(result.html_path).is_file()
    doc = json.loads(Path(result.json_path).read_text(encoding="utf-8"))
    assert doc["metadata"]["package"] == "com.example.app"
    assert doc["metadata"]["timestamp"] == original["metadata"]["timestamp"]
    assert set(doc["summary"]) == {"anti_root", "anti_frida"}
    assert "static_profile" not in doc or isinstance(
        doc["static_profile"], dict
    )


def test_async_run_updates_state(tmp_path, monkeypatch):
    monkeypatch.setattr(RaspilotService, "_run_checks", _fake_results)
    config = _config(tmp_path, stage="full")
    store = SessionStore(str(tmp_path / "sessions"))
    svc = RaspilotService.create(
        config, store=store, device=FakeDevice()
    )
    future = svc.run_async()
    future.result(timeout=30)
    state = store.load(svc.state.session_id)
    assert state.status == "succeeded"
    assert state.stage == "full"
