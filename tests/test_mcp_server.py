"""Servidor MCP universal: tools e recursos sobre sessões."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from mcp_api import RaspilotTools
from mcp_server import create_server
from sessions import SessionStore


def _payload(result) -> dict:
    return json.loads(result.content[0].text)


def _run(coro):
    return asyncio.run(coro)


def _server(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    tools = RaspilotTools(store=store, device_id="SER1", run_timeout=5)
    return store, create_server(tools)


def test_lists_tools_and_resource_templates(tmp_path):
    _, server = _server(tmp_path)

    async def check():
        tools = await server.list_tools()
        names = {tool.name for tool in tools}
        assert "raspilot_start_assessment" in names
        assert "raspilot_status" in names
        assert "raspilot_run_check" in names
        assert "raspilot_test_repack" in names
        templates = await server.list_resource_templates()
        uris = {item.uri_template for item in templates}
        assert "raspilot://sessions/{session_id}/session.json" in uris
        assert "raspilot://sessions/{session_id}/checks/{check}.json" in uris

    _run(check())


def test_status_and_session_resources(tmp_path):
    store, server = _server(tmp_path)
    state = store.create("com.example.app")
    store.write_json(state, "summary.json", {"anti_root": {"status": "OK"}})
    store.write_json(state, "report.json", {"metadata": {"session_id": state.session_id}})
    store.write_json(state, "checks/anti_root.json", {"is_rooted": False})
    state.reports = {
        "report_json": str(store.path(state, "report.json")),
        "summary_json": str(store.path(state, "summary.json")),
    }
    store.save(state)

    async def check():
        payload = _payload(
            await server.call_tool(
                "raspilot_status", {"session_id": state.session_id}
            )
        )
        assert payload["ok"] is True
        assert payload["status"] == "pending"
        assert payload["session_id"] == state.session_id

        session = await server.read_resource(
            f"raspilot://sessions/{state.session_id}/session.json"
        )
        assert json.loads(session[0].content)["session_id"] == state.session_id

        summary = await server.read_resource(
            f"raspilot://sessions/{state.session_id}/summary.json"
        )
        assert json.loads(summary[0].content)["anti_root"]["status"] == "OK"

        check_json = await server.read_resource(
            f"raspilot://sessions/{state.session_id}/checks/anti_root.json"
        )
        assert json.loads(check_json[0].content)["is_rooted"] is False

    _run(check())


def test_tool_errors_are_structured(tmp_path, monkeypatch):
    monkeypatch.delenv("RASPILOT_DEVICE", raising=False)
    store, server = _server(tmp_path)
    tool = RaspilotTools(store=store, device_id=None)
    server = create_server(tool)

    async def check():
        missing_device = _payload(
            await server.call_tool(
                "raspilot_start_assessment",
                {"package_name": "com.example.app"},
            )
        )
        assert missing_device["ok"] is False
        assert missing_device["code"] == "device_required"

        not_found = _payload(
            await server.call_tool(
                "raspilot_status", {"session_id": "nao-existe"}
            )
        )
        assert not_found["ok"] is False
        assert not_found["code"] == "session_not_found"

        bad_check = _payload(
            await server.call_tool(
                "raspilot_run_check",
                {"session_id": "nao-existe", "check": "nao_existe"},
            )
        )
        assert bad_check["ok"] is False
        assert bad_check["code"] == "invalid_argument"

    _run(check())


def test_wait_timeout_is_structured(tmp_path):
    store, server = _server(tmp_path)
    state = store.create("com.example.app")
    state.status = "running"
    state.progress = {"pid": os.getpid(), "heartbeat_at": state.updated_at}
    store.save(state)

    async def check():
        payload = _payload(
            await server.call_tool(
                "raspilot_wait",
                {"session_id": state.session_id, "timeout": 0.2, "poll": 0.05},
            )
        )
        assert payload["ok"] is False
        assert payload["code"] == "timeout"

    _run(check())


def test_repack_two_step_token(tmp_path):
    store, server = _server(tmp_path)
    state = store.create("com.example.app")
    state.device = {"serial": "SER1"}
    store.save(state)

    async def check():
        planning = _payload(
            await server.call_tool(
                "raspilot_test_repack",
                {"session_id": state.session_id, "variants": ["dex"]},
            )
        )
        assert planning["ok"] is True
        assert planning["status"] == "confirmation_required"
        token = planning["confirmation_token"]
        assert token

        bad = _payload(
            await server.call_tool(
                "raspilot_test_repack",
                {"session_id": state.session_id, "confirmation": "errado"},
            )
        )
        assert bad["ok"] is False
        assert bad["code"] in ("confirmation_required", "invalid_confirmation")

    _run(check())
