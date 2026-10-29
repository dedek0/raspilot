"""Testes do check de proxy/VPN (estático, dinâmico e bypass)."""

from __future__ import annotations

import zipfile

from checks.anti_proxy import AntiProxyCheck
from reporter import Reporter


def _make_apk(path, blobs: dict) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in blobs.items():
            archive.writestr(name, data)
    return str(path)


class FakeXposed:
    """Gerenciador de módulo fake com evidência pré-definida."""

    def __init__(self, evidence, lines=None):
        self.evidence = evidence
        self.lines = list(lines or [])
        self.calls = []

    def detect(self):
        return {"available": True, "name": "fake"}

    def run_phase(self, config, window=12, interact=False):
        self.calls.append(config)
        return {
            "ok": True,
            "run": {
                "pid": 123,
                "app_alive_at_end": True,
                "evidence": self.evidence,
                "lines": self.lines,
                "module_ready": True,
            },
            "error": None,
        }


def test_static_detects_proxy_and_vpn_signatures(tmp_path):
    apk = _make_apk(tmp_path / "app.apk", {
        "classes.dex": b"...http.proxyHost...android.net.VpnService...",
        "AndroidManifest.xml": b"manifest",
    })
    result = AntiProxyCheck(object()).detect_static(
        "com.example.app", apk_path=apk
    )
    assert result["static_detected"] is True
    assert result["confidence"] == "high"
    assert "proxy_strings" in result["types"]
    assert any("http.proxyHost" in item for item in result["evidence"])


def test_static_clean_apk_is_not_detected(tmp_path):
    apk = _make_apk(tmp_path / "clean.apk", {
        "classes.dex": b"hello world",
        "AndroidManifest.xml": b"manifest",
    })
    result = AntiProxyCheck(object()).detect_static(
        "com.example.app", apk_path=apk
    )
    assert result["static_detected"] is False
    assert result["confidence"] == "none"


def test_module_probe_parses_proxy_queries():
    evidence = [
        {
            "kind": "observe", "channel": "proxy:proxy",
            "method": "ProxySelector.select", "detail": "https://example.test",
        },
        {
            "kind": "spoof", "channel": "proxy:proxy",
            "method": "System.getProperty", "detail": "http.proxyHost=127.0.0.1",
        },
    ]
    check = AntiProxyCheck(
        object(), method="module", xposed=FakeXposed(evidence)
    )
    result = check.attempt_module_probe("com.example.app", window=1)
    assert result["detected"] is True
    assert result["strong_signals"]
    assert result["channels"]["proxy"]
    # A consulta forte conta como detecção, mas não é uma reação do app.
    assert result["reaction_observed"] is False
    assert result["query_only"] is True
    assert "sem reação" in result["details"]


def test_module_probe_marks_observed_threat_as_reaction():
    evidence = [
        {
            "kind": "observe", "channel": "proxy:vpn",
            "method": "NetworkCapabilities.hasTransport", "detail": "TRANSPORT_VPN",
        },
    ]
    lines = [
        "10-29 13:00:00.000 123 456 I C6Bank: vpn detected: blocking access"
    ]
    check = AntiProxyCheck(
        object(), method="module", xposed=FakeXposed(evidence, lines=lines)
    )
    result = check.attempt_module_probe("com.example.app", window=1)
    assert result["detected"] is True
    assert result["reaction_observed"] is True
    assert result["query_only"] is False
    assert result["details"].startswith("app reagiu")


def test_module_bypass_reports_success_with_masked_channel():
    evidence = [
        {
            "kind": "observe", "channel": "proxy:vpn",
            "method": "NetworkCapabilities.hasTransport", "detail": "TRANSPORT_VPN",
        },
        {
            "kind": "mask", "channel": "proxy:vpn",
            "method": "NetworkCapabilities.hasTransport", "detail": "TRANSPORT_VPN=false",
        },
    ]
    check = AntiProxyCheck(
        object(), method="module", xposed=FakeXposed(evidence)
    )
    result = check.attempt_module_bypass("com.example.app", window=1)
    assert result["success"] is True
    assert result["masked_channels"]
    assert result["evidence_strength"] == "masked"
    assert result["tls_neutralized"] == 0


def test_module_bypass_records_tls_layer():
    evidence = [
        {
            "kind": "neutralize", "channel": "tls",
            "method": "SSLContext.init", "detail": "trust manager permissivo",
        },
        {
            "kind": "neutralize", "channel": "tls",
            "method": "Conscrypt.Platform.checkServerTrusted",
            "detail": "validação ignorada",
        },
    ]
    check = AntiProxyCheck(
        object(), method="module", xposed=FakeXposed(evidence)
    )
    result = check.attempt_module_bypass("com.example.app", window=1)
    assert result["tls_neutralized"] == 2
    assert "SSLContext.init" in result["tls_methods"]
    assert "Conscrypt.Platform.checkServerTrusted" in result["tls_methods"]


def _clean_profile():
    return {
        "available": True,
        "engine": "builtin",
        "vectors": {
            "proxy": {
                "present": False,
                "confidence": "none",
                "findings": [],
                "total": 0,
                "sources": [],
                "owners": {},
                "techniques": [],
                "app_evidence": False,
            }
        },
        "coverage": {
            "proxy": {
                "bypass_hooks": [],
                "possible_gaps": [],
                "static_present": False,
            }
        },
    }


def test_run_all_detect_mode_skips_bypass():
    detection = {
        "detected": True,
        "detection_methods_found": ["ProxySelector.select: consulta"],
        "strong_signals": ["ProxySelector.select: consulta"],
        "weak_signals": [],
        "channels": {"proxy": ["ProxySelector.select: consulta"]},
        "app_alive_at_end": True,
        "observed": True,
        "observation_status": "ok",
    }
    check = AntiProxyCheck(object(), mode="detect")
    result = check.run_all(
        "com.example.app",
        precomputed_detection=detection,
        static_profile=_clean_profile(),
    )
    assert result["protection_detected"] is True
    assert result["bypass_successful"] is None
    assert result["status_hint"] == "SKIP"
    assert "detect" in result["bypass_skipped_reason"]


def test_run_all_bypass_success_is_falhou():
    detection = {
        "detected": True,
        "detection_methods_found": ["ProxySelector.select: consulta"],
        "strong_signals": ["ProxySelector.select: consulta"],
        "weak_signals": [],
        "channels": {"proxy": ["ProxySelector.select: consulta"]},
        "app_alive_at_end": True,
        "observed": True,
        "observation_status": "ok",
    }
    bypass = {
        "success": True,
        "blocked": False,
        "app_alive_at_end": True,
        "masked_channels": ["ProxySelector.select: NO_PROXY"],
        "exposed_channels": [],
        "evidence_strength": "masked",
    }
    check = AntiProxyCheck(object(), mode="bypass")
    result = check.run_all(
        "com.example.app",
        precomputed_detection=detection,
        precomputed_bypass=bypass,
        static_profile=_clean_profile(),
    )
    assert result["bypass_successful"] is True
    assert result["status_hint"] == "FALHOU"
    assert result["proxy_detected"] is True


def test_reporter_anti_proxy_verdicts_and_log():
    result = {
        "protection_detected": True,
        "proxy_detected": True,
        "vpn_detected": False,
        "bypass_successful": True,
        "bypass_method": "module",
        "probe_method": "module",
        "protection_sources": ["static_apk", "dynamic", "module"],
        "static_detection": {
            "static_detected": True,
            "confidence": "high",
            "evidence": ["[proxy_strings] http.proxyHost"],
        },
        "static_analysis": {
            "engine": "asc", "owners": {"app": 1},
            "app_evidence": True, "coverage": {"possible_gaps": []},
        },
        "app_detection": {
            "detected": True,
            "detection_methods_found": ["ProxySelector.select: consulta"],
            "strong_signals": ["ProxySelector.select: consulta"],
            "weak_signals": [],
            "channels": {"proxy": ["ProxySelector.select: consulta"]},
            "app_alive_at_end": True,
            "observed": True,
            "observation_status": "ok",
        },
        "bypass_details": {
            "success": True,
            "masked_channels": ["ProxySelector.select: NO_PROXY"],
            "exposed_channels": [],
            "evidence_strength": "masked",
        },
        "evidence_strength": "masked",
        "status_hint": "FALHOU",
        "verdict_reason": "proteção de proxy contornada",
    }
    reporter = Reporter(
        device_info={}, package_name="com.example.app",
    )
    reporter.collect("anti_proxy", result)
    doc = reporter.generate_json()
    summary = doc["summary"]["anti_proxy"]
    assert summary["status"] == "FALHOU"
    assert summary["proxy_detected"] is True
    assert summary["detection"]["status"] == "detected"
    assert summary["bypass"]["status"] == "bypassed"
    phases = {
        step["phase"]: step
        for step in doc["execution_log"]
        if step["check"] == "anti_proxy"
    }
    assert phases["static"]["outcome"] == "detected"
    assert phases["detection"]["outcome"] == "detected"
    assert phases["bypass"]["outcome"] == "success"
