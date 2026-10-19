"""Testes do cache local de APKs."""

from __future__ import annotations

from unittest import mock

from checks.apk_utils import pull_apk


def _dm(pulled):
    dm = mock.MagicMock()
    dm.run_shell.return_value = {
        "ok": True,
        "rc": 0,
        "stdout": "package:/data/app/base.apk\npackage:/data/app/split.apk",
        "stderr": "",
    }

    def fake_pull(cmd, timeout=300):
        pulled.append(cmd)
        with open(cmd[2], "wb") as fh:
            fh.write(b"apk")
        return "ok"

    dm._run_adb.side_effect = fake_pull
    return dm


def test_second_pull_uses_cache(tmp_path, monkeypatch):
    """O segundo pull do mesmo pacote/versão não baixa de novo."""
    monkeypatch.setenv("RASPILOT_CACHE_DIR", str(tmp_path / "cache"))
    pulled = []
    dm = _dm(pulled)

    first = pull_apk(dm, "com.example.app", str(tmp_path / "tmp1"))
    second = pull_apk(dm, "com.example.app", str(tmp_path / "tmp2"))

    assert len(first) == 2
    assert first == second
    assert len(pulled) == 2


def test_cache_can_be_disabled(tmp_path, monkeypatch):
    """RASPILOT_APK_CACHE=0 força novo download."""
    monkeypatch.setenv("RASPILOT_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("RASPILOT_APK_CACHE", "0")
    pulled = []
    dm = _dm(pulled)

    pull_apk(dm, "com.example.app", str(tmp_path / "tmp1"))
    pull_apk(dm, "com.example.app", str(tmp_path / "tmp2"))
    assert len(pulled) == 4
