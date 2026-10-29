"""Contrato das ferramentas session-aware (pré-MCP), sem device real."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import service as service_mod
from mcp_api import (
    RaspilotTools,
    ToolConfirmationRequired,
    ToolDeviceRequired,
    ToolError,
    ToolInvalidState,
    ToolNotFound,
    ToolTimeout,
    safe_call,
)
from service import RaspilotService, RunConfig
from sessions import SessionConfirmationError, SessionStore


class FakeDevice:
    """DeviceManager mínimo: sem adb/Frida, com resultados determinísticos."""

    def __init__(self, serial: str = "SER1"):
        self.device_id = serial
        self.frida_port = 27999
        self.baseline = {"available": False, "reason": "mock"}
        self._logcat_available = False

    def connect_adb(self):
        return True

    def get_device_info(self):
        return {
            "serial": self.device_id,
            "model": "Pixel 7",
            "android_version": "14",
            "sdk": "34",
            "abi": "arm64-v8a",
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


def _fake_checks(svc):
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


def _factory(store):
    def build(config, session_store, resume):
        if resume:
            return RaspilotService.resume(
                config, store=session_store, device=FakeDevice()
            )
        return RaspilotService.create(
            config, store=session_store, device=FakeDevice()
        )

    return build


def test_iniciar_e_aguardar_com_service_mockado(tmp_path, monkeypatch):
    monkeypatch.setattr(RaspilotService, "_run_checks", _fake_checks)
    store = SessionStore(str(tmp_path / "sessions"))
    tools = RaspilotTools(
        store=store, service_factory=_factory(store), run_timeout=30
    )

    started = tools.iniciar_avaliacao(
        "com.example.app", device_id="SER1", stage="full"
    )
    assert started["status"] == "running"
    assert started["device"] == "SER1"
    assert started["session_id"]

    final = tools.aguardar(started["session_id"], timeout=20)
    assert final["status"] == "succeeded"
    assert final["session_id"] == started["session_id"]
    assert final["device"]["serial"] == "SER1"
    assert final["checks"]["anti_root"]["outcome"] == "ok"
    assert final["report_json"].endswith("report.json")
    assert final["summary_json"].endswith("summary.json")
    assert final["error_code"] is None


def test_iniciar_exige_device_explicito(tmp_path, monkeypatch):
    monkeypatch.delenv("RASPILOT_DEVICE", raising=False)
    tools = RaspilotTools(store=SessionStore(str(tmp_path / "sessions")))
    with pytest.raises(ToolDeviceRequired):
        tools.iniciar_avaliacao("com.example.app")


def test_iniciar_rejeita_stage_bypass_e_check_desconhecido(tmp_path):
    tools = RaspilotTools(
        store=SessionStore(str(tmp_path / "sessions")), device_id="SER1"
    )
    with pytest.raises(ToolError) as excinfo:
        tools.iniciar_avaliacao("com.example.app", stage="bypass")
    assert "bypass" in str(excinfo.value)

    with pytest.raises(ToolError):
        tools.iniciar_avaliacao(
            "com.example.app", stage="full", skip=["nao_existe"]
        )


def test_status_e_listar_sessoes(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    tools = RaspilotTools(store=store, device_id="SER1")

    payload = tools.status(state.session_id)
    assert payload["status"] == "pending"
    listed = tools.listar_sessoes()
    assert listed["total"] == 1
    assert listed["sessions"][0]["session_id"] == state.session_id

    with pytest.raises(ToolNotFound):
        tools.status("nao-existe")


def test_cancelar_sessao_pendente(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    tools = RaspilotTools(store=store, device_id="SER1")

    result = tools.cancelar(state.session_id)
    assert result["cancel_requested"] is True
    assert store.load(state.session_id).cancel_requested is True


def test_aguardar_timeout(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    state.status = "running"
    state.progress = {"pid": os.getpid(), "heartbeat_at": state.updated_at}
    store.save(state)
    tools = RaspilotTools(store=store, device_id="SER1")

    with pytest.raises(ToolTimeout):
        tools.aguardar(state.session_id, timeout=0.2, poll=0.05)


def test_relatorio_json_summary_e_paths(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    state = store.create("com.example.app")
    doc = {"metadata": {"session_id": state.session_id}, "summary": {}}
    summary = {"anti_root": {"status": "OK"}}
    report_json = store.write_json(state, "report.json", doc)
    summary_json = store.write_json(state, "summary.json", summary)
    state.reports = {
        "report_json": str(report_json),
        "summary_json": str(summary_json),
    }
    store.save(state)
    tools = RaspilotTools(store=store, device_id="SER1")

    payload = tools.obter_relatorio(state.session_id)
    assert payload["document"]["metadata"]["session_id"] == state.session_id
    assert tools.obter_resumo(state.session_id)["document"] == summary
    paths = tools.obter_relatorio(state.session_id, format="paths")
    assert paths["reports"]["summary_json"] == str(summary_json)

    with pytest.raises(ToolError):
        tools.obter_relatorio(state.session_id, format="xml")

    fresh = store.create("com.example.outro")
    with pytest.raises(ToolInvalidState):
        tools.obter_relatorio(fresh.session_id, format="summary")


def test_repack_em_duas_etapas_e_token_de_uso_unico(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    config = RunConfig(
        package="com.example.app",
        device_id="SER1",
        stage="detect",
        output_dir=str(tmp_path / "out"),
        state_dir=str(tmp_path / "sessions"),
        static_engine="off",
    )
    svc = RaspilotService.create(config, store=store, device=FakeDevice())
    svc.state.device = {"serial": "SER1"}
    store.save(svc.state)
    tools = RaspilotTools(
        store=store, service_factory=_factory(store), device_id="SER1"
    )

    planning = tools.testar_repack(svc.state.session_id, variants=["dex"])
    assert planning["status"] == "confirmation_required"
    assert planning["destructive"] is True
    token = planning["confirmation_token"]
    assert token

    with pytest.raises(ToolConfirmationRequired):
        tools.testar_repack(svc.state.session_id, confirmation="token-errado")

    # O token continua pendente após uma tentativa inválida.
    state = store.load(svc.state.session_id)
    payload = store.confirm_action(
        state, token, action="repack", device="SER1"
    )
    assert payload["variants"] == ["dex"]
    assert payload["destructive"] is True

    with pytest.raises(SessionConfirmationError):
        store.confirm_action(state, token, action="repack", device="SER1")


def test_repack_executa_apos_confirmacao(tmp_path, monkeypatch):
    import checks.tamper_repack as repack_mod

    class FakeRepack:
        def __init__(self, *args, **kwargs):
            self.kwargs = kwargs

        def run(self):
            return {
                "tamper_detected": True,
                "bypass_successful": False,
                "variants": ["dex"],
                "skipped_reason": None,
            }

    monkeypatch.setattr(repack_mod, "RepackTester", FakeRepack)

    store = SessionStore(str(tmp_path / "sessions"))
    config = RunConfig(
        package="com.example.app",
        device_id="SER1",
        stage="detect",
        output_dir=str(tmp_path / "out"),
        state_dir=str(tmp_path / "sessions"),
        static_engine="off",
    )
    svc = RaspilotService.create(config, store=store, device=FakeDevice())
    svc.state.device = {"serial": "SER1"}
    store.save(svc.state)
    tools = RaspilotTools(
        store=store, service_factory=_factory(store), device_id="SER1"
    )

    plan = tools.testar_repack(svc.state.session_id, variants=["dex"])
    result = tools.testar_repack(
        svc.state.session_id,
        confirmation=plan["confirmation_token"],
        timeout=30,
    )

    assert result["status"] == "succeeded"
    assert result["checks"]["anti_tampering"]["outcome"] == "ok"
    assert result["reports"]["report_json"]
    assert store.load(svc.state.session_id).pending_action is None


def test_safe_call_devolve_codigo_estavel():
    def explode():
        raise ToolNotFound("sumiu")

    payload = safe_call(explode)
    assert payload["ok"] is False
    assert payload["code"] == "session_not_found"
    assert "sumiu" in payload["message"]
