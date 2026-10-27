"""Testes do teste de repack do APK."""

from __future__ import annotations

import zipfile
from unittest import mock

import pytest

from checks import tamper_repack as repack


class FakeDM:
    """DeviceManager mínimo para o fluxo de repack."""

    def __init__(self):
        self.installed = 0
        self.uninstalled = 0
        self.launches = 0

    def run_shell(self, command, timeout=20):
        return {"ok": True, "stdout": "", "stderr": ""}

    def logcat_mark(self):
        return 0

    def get_app_pid(self, package):
        return 123

    def wait_for_app_ready(self, package, timeout=2, pid=None):
        return True

    def is_app_alive(self, pid):
        return True

    def drive_ui(self, package, taps=3, timeout=90):
        return {"ok": True}

    def _run_adb(self, args, timeout=300):
        if args and args[0] == "uninstall":
            self.uninstalled += 1
        else:
            self.installed += 1
        return "Success"


def _obs(label, usable=True):
    return {
        "label": label,
        "pid": 123,
        "alive": usable,
        "foreground": usable,
        "usable": usable,
        "died_after": None if usable else 2,
        "logcat": {},
    }


class TestAssetVariant:
    def test_add_asset(self, tmp_path):
        source = tmp_path / "base.apk"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"manifest")
            archive.writestr("classes.dex", b"dex")
        output = tmp_path / "asset.apk"
        ok, error = repack._add_asset(str(source), str(output))
        assert ok, error
        with zipfile.ZipFile(output) as archive:
            assert repack.ASSET_NAME in archive.namelist()
            assert archive.read(repack.ASSET_NAME) == repack.ASSET_CONTENT
            assert "classes.dex" in archive.namelist()


class TestVariants:
    def test_all_expands_to_content_variants(self):
        tester = repack.RepackTester(object(), "com.example.app", variants=("all",))
        assert tester.variants == [
            "asset", "dex", "resource", "manifest", "gadget"
        ]


class TestGadget:
    def test_inject_libs_and_config(self, tmp_path):
        source = tmp_path / "base.apk"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"manifest")
        gadget = tmp_path / "libgadget.so"
        gadget.write_bytes(b"GADGET")
        output = tmp_path / "gadget.apk"
        ok, error = repack._inject_gadget_libs(
            str(source), str(output), str(gadget), "arm64-v8a", 27043
        )
        assert ok, error
        with zipfile.ZipFile(output) as archive:
            assert archive.read("lib/arm64-v8a/libgadget.so") == b"GADGET"
            config = archive.read("lib/arm64-v8a/libgadget.config.so")
        assert b'"port": 27043' in config
        assert b'"on_load": "resume"' in config

    def test_resolve_gadget_for_abi(self, tmp_path, monkeypatch):
        gadget = tmp_path / "custom-arm64.so"
        gadget.write_bytes(b"G")
        monkeypatch.setattr(
            repack.glob, "glob",
            lambda pattern: [str(gadget)] if "arm64" in pattern else [],
        )
        resolved, error = repack._resolve_gadget(None, "arm64-v8a")
        assert resolved == str(gadget)
        assert not error

    def test_resolve_gadget_rejects_unknown_abi(self):
        resolved, error = repack._resolve_gadget(None, "mips")
        assert resolved is None
        assert "ABI" in error


class TestInterpret:
    def _tester(self, variants=("asset", "dex")):
        return repack.RepackTester(
            FakeDM(), "com.example.app", variants=variants
        )

    def test_vulnerable_when_all_content_variants_survive(self):
        result = self._tester()._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "asset": _obs("asset"),
                "dex": _obs("dex"),
            },
            {},
        )
        assert result["status_hint"] == "FALHOU"
        assert result["tamper_detected"] is False
        assert result["bypass_successful"] is True
        assert result["attribution"] == "none"

    def test_detected_when_content_variant_dies(self):
        result = self._tester()._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "asset": _obs("asset"),
                "dex": _obs("dex", usable=False),
            },
            {},
        )
        assert result["status_hint"] == "OK"
        assert result["tamper_detected"] is True
        assert result["bypass_successful"] is False
        assert result["attribution"] == "content"

    def test_signature_control_death_is_detection(self):
        result = self._tester()._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned", usable=False),
                "rebuilt": _obs("rebuilt"),
                "asset": _obs("asset", usable=False),
            },
            {},
        )
        assert result["status_hint"] == "OK"
        assert result["attribution"] == "signature/content"

    def test_rebuild_control_death_is_tooling(self):
        result = self._tester()._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt", usable=False),
                "dex": _obs("dex", usable=False),
            },
            {},
        )
        assert result["status_hint"] == "SKIP"
        assert result["attribution"] == "tooling"
        assert result["tamper_detected"] is None

    def test_resigned_alive_without_focus_is_inconclusive(self):
        resigned = _obs("resigned", usable=False)
        resigned["alive"] = True
        result = self._tester()._interpret(
            {
                "original": _obs("original"),
                "resigned": resigned,
                "rebuilt": _obs("rebuilt"),
                "asset": _obs("asset"),
            },
            {},
        )
        assert result["status_hint"] == "SKIP"
        assert result["attribution"] == "inconclusive"

    def test_content_alive_without_focus_is_inconclusive(self):
        asset = _obs("asset", usable=False)
        asset["alive"] = True
        result = self._tester()._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "asset": asset,
            },
            {},
        )
        assert result["status_hint"] == "SKIP"
        assert result["attribution"] == "inconclusive"

    def test_gadget_loaded_but_not_connected_is_inconclusive(self):
        gadget = _obs("gadget")
        gadget["gadget_loaded"] = True
        gadget["gadget_connected"] = False
        result = self._tester(("gadget",))._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "gadget": gadget,
            },
            {},
        )
        assert result["status_hint"] == "SKIP"
        assert result["attribution"] == "inconclusive"

    def test_gadget_without_load_is_inconclusive(self):
        gadget = _obs("gadget")
        gadget["gadget_loaded"] = False
        gadget["gadget_connected"] = False
        result = self._tester(("gadget",))._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "gadget": gadget,
            },
            {},
        )
        assert result["status_hint"] == "SKIP"
        assert result["attribution"] == "inconclusive"

    def test_gadget_loaded_is_bypass(self):
        gadget = _obs("gadget")
        gadget["gadget_loaded"] = True
        gadget["gadget_connected"] = True
        result = self._tester(("gadget",))._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "gadget": gadget,
            },
            {},
        )
        assert result["status_hint"] == "FALHOU"
        assert result["bypass_successful"] is True

    def test_gadget_control_death_is_detection(self):
        control = _obs("gadget-control", usable=False)
        control["alive"] = False
        result = self._tester(("gadget",))._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "gadget-control": control,
            },
            {},
        )
        assert result["status_hint"] == "OK"
        assert result["attribution"] == "content"
        assert result["tamper_detected"] is True

    def test_gadget_death_without_load_is_payload_failure(self):
        gadget = _obs("gadget", usable=False)
        gadget["alive"] = False
        gadget["gadget_loaded"] = False
        gadget["gadget_connected"] = False
        result = self._tester(("gadget",))._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "gadget": gadget,
            },
            {},
        )
        assert result["status_hint"] == "SKIP"
        assert result["attribution"] == "payload"
        assert result["tamper_detected"] is None

    def test_gadget_death_after_load_is_detection(self):
        gadget = _obs("gadget", usable=False)
        gadget["alive"] = False
        gadget["gadget_loaded"] = True
        gadget["gadget_connected"] = True
        result = self._tester(("gadget",))._interpret(
            {
                "original": _obs("original"),
                "resigned": _obs("resigned"),
                "rebuilt": _obs("rebuilt"),
                "gadget": gadget,
            },
            {},
        )
        assert result["status_hint"] == "OK"
        assert result["attribution"] == "content"
        assert result["tamper_detected"] is True

    def test_original_not_usable_is_inconclusive(self):
        result = self._tester()._interpret(
            {"original": _obs("original", usable=False)}, {}
        )
        assert result["status_hint"] == "SKIP"
        assert result["tamper_detected"] is None


class TestRunFlow:
    def _tester(self, tmp_path):
        return repack.RepackTester(
            FakeDM(),
            "com.example.app",
            output_dir=str(tmp_path),
            variants=("asset", "dex"),
            allow_reinstall=True,
            keep_artifacts=True,
        )

    def test_full_matrix_and_restore(self, tmp_path, monkeypatch):
        tester = self._tester(tmp_path)
        observations = iter([
            _obs("original"),
            _obs("resigned"),
            _obs("rebuilt"),
            _obs("asset"),
            _obs("dex", usable=False),
        ])
        installed = []
        monkeypatch.setattr(repack, "_keystore", lambda *a, **k: ("/tmp/k.jks", ""))
        monkeypatch.setattr(
            repack, "_find_tool", lambda name, env_var=None: f"/tmp/{name}"
        )
        monkeypatch.setattr(repack.shutil, "which", lambda name: "/tmp/apktool")
        monkeypatch.setattr(repack, "_signature", lambda *a, **k: "cert")
        monkeypatch.setattr(tester, "_apks", lambda dest: ["/tmp/base.apk"])
        monkeypatch.setattr(
            tester, "_build",
            lambda *a, **k: (
                {
                    "resigned": ["/tmp/resigned.apk"],
                    "rebuilt": ["/tmp/rebuilt.apk"],
                    "asset": ["/tmp/asset.apk"],
                    "dex": ["/tmp/dex.apk"],
                },
                {},
            ),
        )
        monkeypatch.setattr(tester, "_observe", lambda label: next(observations))
        monkeypatch.setattr(tester, "_installer_name", lambda: "com.android.vending")
        monkeypatch.setattr(
            tester, "_install", lambda apks, replace=True: (installed.append(apks), (True, "ok"))[1]
        )
        monkeypatch.setattr(tester, "_uninstall", lambda: (True, "ok"))
        result = tester.run()
        assert result["tamper_detected"] is True
        assert result["bypass_successful"] is False
        assert result["status_hint"] == "OK"
        assert result["probe_method"] == "repack"
        assert result["restore"]["ok"] is True
        assert any("/tmp/base.apk" in item for item in installed)

    def test_requires_reinstall_permission(self, tmp_path):
        tester = repack.RepackTester(
            FakeDM(), "com.example.app", output_dir=str(tmp_path)
        )
        result = tester.run()
        assert result["status_hint"] == "SKIP"
        assert "--tamper-allow-reinstall" in result["skipped_reason"]
