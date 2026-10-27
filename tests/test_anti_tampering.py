"""Testes do check de anti-tampering (estático + sonda em memória)."""

from __future__ import annotations

from unittest import mock

import pytest

from checks.anti_tampering import AntiTamperingCheck
from reporter import Reporter


class FakeDevice:
    """DeviceManager mínimo para os testes do check."""

    baseline = None
    logcat_mark = None


def _profile(present: bool = True, confidence: str = "high") -> dict:
    return {
        "available": True,
        "engine": "asc",
        "version": "0.1.2",
        "classes_count": 10,
        "vectors": {
            "tamper": {
                "present": present,
                "confidence": confidence,
                "findings": (
                    [
                        {
                            "kind": "method",
                            "evidence": "PackageManager.checkSignatures",
                            "owner": "app",
                        }
                    ]
                    if present
                    else []
                ),
                "owners": {"app": 1} if present else {},
                "app_evidence": present,
            }
        },
        "coverage": {"tamper": {"possible_gaps": []}},
    }


class TestStaticDetection:
    def test_uses_static_profile(self):
        check = AntiTamperingCheck(FakeDevice())
        result = check.detect_static(
            "com.example.app", static_profile=_profile()
        )
        assert result["tamper_detected"] is True
        assert result["static_detected"] is True
        assert result["confidence"] == "high"
        assert result["evidence"] == ["PackageManager.checkSignatures"]
        assert result["owners"] == {"app": 1}

    def test_empty_profile_falls_back_to_apk(self, monkeypatch):
        check = AntiTamperingCheck(FakeDevice())
        monkeypatch.setattr(
            "checks.anti_tampering.pull_apk", lambda *a, **k: ["/tmp/app.apk"]
        )
        monkeypatch.setattr(
            "checks.anti_tampering.scan_apk",
            lambda *a, **k: {"tamper": ["GET_SIGNATURES"]},
        )
        profile = _profile(present=False)
        profile["vectors"] = {}
        result = check.detect_static(
            "com.example.app", static_profile=profile
        )
        assert result["tamper_detected"] is True
        assert result["evidence"] == ["GET_SIGNATURES"]

    def test_apk_unavailable(self, monkeypatch):
        check = AntiTamperingCheck(FakeDevice())
        monkeypatch.setattr(
            "checks.anti_tampering.pull_apk", lambda *a, **k: []
        )
        result = check.detect_static("com.example.app")
        assert result["tamper_detected"] is False
        assert result["error"]


class TestMemoryProbe:
    def _check(self) -> AntiTamperingCheck:
        return AntiTamperingCheck(FakeDevice())

    def test_tamper_crash_means_detected(self, monkeypatch):
        check = self._check()
        monkeypatch.setattr(
            check,
            "_phase",
            lambda package, window, tamper: {
                "app_alive": not tamper,
                "tamper_installed": tamper,
                "messages": ["checkSignatures -> SIGNATURE_MISMATCH"] if tamper else [],
                "error": None,
            },
        )
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["tamper_detected"] is True
        assert result["bypass_successful"] is False

    def test_surviving_tamper_is_vulnerable(self, monkeypatch):
        check = self._check()
        monkeypatch.setattr(
            check,
            "_phase",
            lambda package, window, tamper: {
                "app_alive": True,
                "tamper_installed": tamper,
                "messages": ["getPackageInfo signatures -> alterado"] if tamper else [],
                "error": None,
            },
        )
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["tamper_detected"] is False
        assert result["bypass_successful"] is True

    def test_control_death_is_inconclusive(self, monkeypatch):
        check = self._check()
        monkeypatch.setattr(
            check,
            "_phase",
            lambda package, window, tamper: {
                "app_alive": False,
                "tamper_installed": False,
                "messages": [],
                "error": None,
            },
        )
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["tamper_detected"] is None
        assert result["bypass_successful"] is None

    def test_probe_not_installed_is_inconclusive(self, monkeypatch):
        check = self._check()

        def phase(package, window, tamper):
            return {
                "app_alive": True,
                "tamper_installed": not tamper,
                "messages": [],
                "error": None,
            }

        monkeypatch.setattr(check, "_phase", phase)
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["tamper_detected"] is None
        assert "não exercitou" in result["skipped_reason"]


class TestRunAll:
    def _check(self, monkeypatch, dynamic=None, static=True):
        check = AntiTamperingCheck(FakeDevice())
        monkeypatch.setattr(
            check,
            "detect_static",
            lambda *a, **k: {
                "tamper_detected": static,
                "static_detected": static,
                "types": ["method"],
                "evidence": ["PackageManager.checkSignatures"] if static else [],
                "confidence": "high" if static else "none",
                "owners": {},
                "app_evidence": static,
                "asc": {"engine": "asc"} if static else None,
                "details": "",
            },
        )
        if dynamic is not None:
            monkeypatch.setattr(check, "probe_in_memory", lambda *a, **k: dynamic)
        return check

    def test_bypass_won(self, monkeypatch):
        check = self._check(
            monkeypatch,
            dynamic={
                "tamper_detected": False,
                "bypass_successful": True,
                "probe_method": "frida",
                "control_alive": True,
                "tamper_alive": True,
                "details": "app sobreviveu",
            },
        )
        result = check.run_all(
            static_profile=_profile(), package_name="com.example.app"
        )
        assert result["status_hint"] == "FALHOU"
        assert result["bypass_successful"] is True
        assert result["protection_detected"] is True

    def test_detection_resisted(self, monkeypatch):
        check = self._check(
            monkeypatch,
            dynamic={
                "tamper_detected": True,
                "bypass_successful": False,
                "probe_method": "frida",
                "control_alive": True,
                "tamper_alive": False,
                "details": "app morreu",
            },
        )
        result = check.run_all(
            static_profile=_profile(), package_name="com.example.app"
        )
        assert result["status_hint"] == "OK"
        assert result["tamper_detected"] is True
        assert result["app_detection"]["detected"] is True

    def test_detect_mode_skips_probe(self, monkeypatch):
        check = self._check(monkeypatch)
        check.mode = "detect"
        result = check.run_all(
            static_profile=_profile(), package_name="com.example.app"
        )
        assert result["bypass_successful"] is None
        assert result["status_hint"] == "SKIP"
        assert "modo detect" in result["bypass_skipped_reason"]

    def test_static_method_skips_probe(self, monkeypatch):
        check = self._check(monkeypatch)
        check.method = "static"
        result = check.run_all(
            static_profile=_profile(), package_name="com.example.app"
        )
        assert result["bypass_successful"] is None
        assert "método static" in result["bypass_skipped_reason"]


class TestReporter:
    def _report(self, result: dict) -> dict:
        reporter = Reporter(
            device_info={"serial": "SER"},
            package_name="com.example.app",
        )
        reporter.collect("anti_tampering", result)
        return reporter.generate_json()["summary"]["anti_tampering"]

    def test_detected_and_resisted(self):
        summary = self._report(
            {
                "tamper_detected": True,
                "static_detected": True,
                "bypass_successful": False,
                "bypass_method": "frida",
                "static_analysis": {"engine": "asc", "owners": {"app": 1}},
            }
        )
        assert summary["status"] == "OK"
        assert summary["detection"]["status"] == "detected"
        assert summary["bypass"]["status"] == "resisted"
        assert summary["tamper_detected"] is True

    def test_survived_is_bypass_won(self):
        summary = self._report(
            {
                "tamper_detected": False,
                "static_detected": True,
                "bypass_successful": True,
                "bypass_method": "frida",
                "static_analysis": {"engine": "asc"},
            }
        )
        assert summary["status"] == "FALHOU"
        assert summary["detection"]["status"] == "not_detected"
        assert summary["bypass"]["status"] == "bypassed"

    def test_static_only_is_skipped(self):
        summary = self._report(
            {
                "tamper_detected": None,
                "static_detected": True,
                "bypass_successful": None,
                "status_hint": "SKIP",
                "bypass_skipped_reason": "modo detect: sonda dinâmica não executada",
                "static_analysis": {"engine": "asc"},
            }
        )
        assert summary["status"] == "SKIP"
        assert summary["detection"]["status"] == "indicated"
        assert summary["bypass"]["status"] == "not_exercised"
        assert summary["skip_reason"]

    def test_without_evidence_is_not_applicable_bypass(self):
        summary = self._report(
            {
                "tamper_detected": None,
                "static_detected": False,
                "bypass_successful": None,
                "status_hint": "SKIP",
            }
        )
        assert summary["status"] == "SKIP"
        assert summary["detection"]["status"] == "inconclusive"
        assert summary["bypass"]["status"] == "not_applicable"


class FakeModuleManager:
    """Gerenciador de módulo mínimo para os testes da fase module."""

    def __init__(self, mode_results):
        self.mode_results = mode_results

    def detect(self):
        return {"available": True}

    def run_phase(self, config, window=12, interact=False):
        result = self.mode_results[config.tamper]
        return {"ok": True, "run": result, "error": None}


class TestModuleProbe:
    def test_uses_module_and_detects_tamper(self):
        manager = FakeModuleManager({
            "observe": {
                "app_alive_at_end": True,
                "observed": [
                    {"method": "getPackageInfo", "detail": "com.example.app"}
                ],
                "neutralized": [],
                "module_ready": True,
            },
            "bypass": {
                "app_alive_at_end": False,
                "observed": [],
                "neutralized": [
                    {"method": "getPackageInfo", "detail": "com.example.app"}
                ],
                "module_ready": True,
            },
        })
        check = AntiTamperingCheck(FakeDevice(), xposed=manager)
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["probe_method"] == "module"
        assert result["tamper_detected"] is True
        assert result["bypass_successful"] is False
        assert result["control_alive"] is True

    def test_surviving_module_tamper_is_vulnerable(self):
        manager = FakeModuleManager({
            "observe": {
                "app_alive_at_end": True,
                "observed": [{"method": "getPackageInfo", "detail": "x"}],
                "neutralized": [],
                "module_ready": True,
            },
            "bypass": {
                "app_alive_at_end": True,
                "observed": [],
                "neutralized": [{"method": "getPackageInfo", "detail": "x"}],
                "module_ready": True,
            },
        })
        check = AntiTamperingCheck(FakeDevice(), xposed=manager)
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["probe_method"] == "module"
        assert result["tamper_detected"] is False
        assert result["bypass_successful"] is True

    def test_module_without_signature_access_is_inconclusive(self):
        manager = FakeModuleManager({
            "observe": {
                "app_alive_at_end": True,
                "observed": [],
                "neutralized": [],
                "module_ready": True,
            },
            "bypass": {
                "app_alive_at_end": True,
                "observed": [],
                "neutralized": [],
                "module_ready": True,
            },
        })
        check = AntiTamperingCheck(FakeDevice(), xposed=manager)
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["tamper_detected"] is None
        assert "não exercitou" in result["skipped_reason"]

    def test_module_evidence_overrides_missing_ready(self):
        manager = FakeModuleManager({
            "observe": {
                "app_alive_at_end": True,
                "observed": [{"method": "getPackageInfo", "detail": "x"}],
                "neutralized": [],
                "module_ready": False,
                "error": "o módulo não foi carregado",
            },
            "bypass": {
                "app_alive_at_end": True,
                "observed": [],
                "neutralized": [{"method": "getPackageInfo", "detail": "x"}],
                "module_ready": False,
                "error": "o módulo não foi carregado",
            },
        })
        check = AntiTamperingCheck(FakeDevice(), xposed=manager)
        result = check.probe_in_memory("com.example.app", window=1)
        assert result["bypass_successful"] is True


class TestRepackIntegration:
    def test_repack_result_maps_to_two_verdicts(self, monkeypatch):
        check = AntiTamperingCheck(
            FakeDevice(), method="repack", allow_reinstall=True
        )
        monkeypatch.setattr(
            check, "detect_static",
            lambda *a, **k: {
                "tamper_detected": True,
                "static_detected": True,
                "types": ["method"],
                "evidence": ["checkSignatures"],
                "confidence": "high",
                "owners": {"app": 1},
                "app_evidence": True,
                "asc": {"engine": "asc"},
                "details": "",
            },
        )
        monkeypatch.setattr(
            "checks.tamper_repack.RepackTester.run",
            lambda self: {
                "tamper_detected": True,
                "bypass_successful": False,
                "probe_method": "repack",
                "status_hint": "OK",
                "verdict_reason": "conteúdo alterado bloqueado",
                "control_alive": True,
                "tamper_alive": False,
                "observations": {
                    "original": {"label": "original", "usable": True},
                    "resigned": {"label": "resigned", "usable": True},
                    "asset": {"label": "asset", "usable": False},
                },
            },
        )
        result = check.run_all(
            static_profile=_profile(), package_name="com.example.app"
        )
        assert result["status_hint"] == "OK"
        assert result["bypass_method"] == "repack"
        assert result["tamper_detected"] is True
        assert result["bypass_successful"] is False
        assert result["app_detection"]["variants_detected"] == ["asset"]


def test_execution_log_includes_repack_controls():
    reporter = Reporter(
        device_info={"serial": "SER"},
        package_name="com.example.app",
    )
    reporter.collect("anti_tampering", {
        "tamper_detected": False,
        "static_detected": True,
        "bypass_successful": True,
        "bypass_method": "repack",
        "status_hint": "FALHOU",
        "bypass_details": {
            "probe_method": "repack",
            "observations": {
                "original": {"label": "original", "alive": True,
                             "foreground": True, "usable": True},
                "resigned": {"label": "resigned", "alive": True,
                             "foreground": True, "usable": True},
                "asset": {"label": "asset", "alive": True,
                          "foreground": True, "usable": True},
            },
        },
    })
    doc = reporter.generate_json()
    repack_steps = [
        step for step in doc["execution_log"]
        if step["check"] == "anti_tampering" and step["phase"] == "repack"
    ]
    assert len(repack_steps) == 3
    assert {step["action"] for step in repack_steps} == {
        "Observar o APK original",
        "Instalar o controle re-assinado sem alteração",
        "Instalar variante com asset marcador",
    }
