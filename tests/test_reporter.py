"""Testes do Reporter — schema JSON, semântica de status e HTML."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

from device_manager import TOOL_NAME, TOOL_VERSION
from reporter import SCHEMA_VERSION, Reporter

DEVICE = {
    "serial": "EMULATOR01",
    "model": "sdk_gphone64_x86_64",
    "android_version": "14",
    "sdk": "34",
    "abi": "x86_64",
    "is_rooted_shell": False,
}

# Resultados fixture por check (cenário: root sim, frida sim, emulador sim, ssl bypassou).
RESULTS = {
    "anti_root": {
        "is_rooted": True,
        "confidence": "high",
        "positive_vectors": ["magisk"],
        "checks": {"magisk": {"detected": True, "evidence": ["package: com.topjohnwu.magisk"]}},
        "timestamp": "2026-10-14T12:00:00+00:00",
    },
    "anti_frida": {
        "vulnerable": True,
        "frida_present": True,
        "frida_pid": 1234,
        "checks": {"frida_processes": {"detected": True}},
        "app_detection": {"detection_methods_found": [], "vulnerable": True},
        "timestamp": "2026-10-14T12:00:01+00:00",
    },
    "anti_emulator": {
        "is_emulator": True,
        "emulator_type": "qemu_avd",
        "confidence": "high",
        "checks": {},
        "timestamp": "2026-10-14T12:00:02+00:00",
    },
    "ssl_pinning": {
        "pinning_detected": True,
        "pinning_type": "okhttp",
        "bypass_successful": True,
        "evidence": ["[okhttp] CertificatePinner"],
        "bypass_details": {"success": True, "intercepted_hosts": ["api.x.com"]},
        "timestamp": "2026-10-14T12:00:03+00:00",
    },
    "anti_hooking": {
        "protection_detected": True,
        "bypass_successful": True,
        "hook_frameworks_present": True,
        "checks": {"hook_framework_packages": {"detected": False}},
        "static_detection": {"static_detected": True, "primary": "xposed"},
        "app_detection": {"detected": True, "strong_signals": ["Class.forName: XposedBridge"]},
        "bypass_details": {"success": True, "effective_logs": ["neutralizado: Class.forName -> null"]},
        "timestamp": "2026-10-14T12:00:04+00:00",
    },
}


def _reporter() -> Reporter:
    """Monta um Reporter fixo com os resultados fixture."""
    rep = Reporter(device_info=DEVICE, package_name="com.example.app")
    rep.timestamp = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
    for name, result in RESULTS.items():
        rep.collect(name, result)
    return rep


class TestGenerateJson:
    """Schema do relatório JSON."""

    def test_schema_snapshot(self):
        """O documento segue exatamente o schema esperado (snapshot)."""
        doc = _reporter().generate_json()
        expected = {
            "metadata": {
                "schema_version": SCHEMA_VERSION,
                "tool_name": TOOL_NAME,
                "tool_version": TOOL_VERSION,
                "timestamp": "2026-10-14T12:00:00+00:00",
                "device": DEVICE,
                "package": "com.example.app",
            },
            "summary": {
                "anti_root": {
                    "status": "FALHOU", "is_rooted": True, "confidence": "high",
                },
                "anti_frida": {
                    "status": "FALHOU", "vulnerable": True, "frida_present": True,
                },
                "anti_emulator": {
                    "status": "FALHOU", "is_emulator": True,
                    "emulator_type": "qemu_avd", "confidence": "high",
                },
                "ssl_pinning": {
                    "status": "FALHOU", "pinning_detected": True,
                    "pinning_type": "okhttp", "bypass_successful": True,
                },
                "anti_hooking": {
                    "status": "FALHOU", "protection_detected": True,
                    "bypass_successful": True, "hook_frameworks_present": True,
                },
            },
            "details": RESULTS,
        }
        assert doc == expected

    def test_json_serializable(self):
        """O documento é 100% serializável em JSON."""
        doc = _reporter().generate_json()
        parsed = json.loads(json.dumps(doc))
        assert parsed["metadata"]["package"] == "com.example.app"

    def test_status_ok_when_protection_wins(self):
        """Anti-frida que bloqueou o Frida => status OK."""
        rep = Reporter(device_info=DEVICE, package_name="pkg")
        rep.collect("anti_frida", {"vulnerable": False, "frida_present": True})
        summary = rep.generate_json()["summary"]
        assert summary["anti_frida"]["status"] == "OK"

    def test_status_anti_emulator(self):
        """Emulador detectado => FALHOU; dispositivo físico => OK."""
        rep = Reporter(device_info=DEVICE, package_name="pkg")
        rep.collect("anti_emulator", {"is_emulator": True, "emulator_type": "qemu_avd"})
        assert rep.generate_json()["summary"]["anti_emulator"]["status"] == "FALHOU"

        rep2 = Reporter(device_info=DEVICE, package_name="pkg")
        rep2.collect("anti_emulator", {"is_emulator": False})
        assert rep2.generate_json()["summary"]["anti_emulator"]["status"] == "OK"

    def test_status_error_when_check_fails(self):
        """Check com error => status ERROR."""
        rep = Reporter(device_info=DEVICE, package_name="pkg")
        rep.collect("anti_root", {"error": "adb offline"})
        assert rep.generate_json()["summary"]["anti_root"]["status"] == "ERROR"

    def test_status_skip(self):
        """Check pulado => status SKIP."""
        rep = Reporter(device_info=DEVICE, package_name="pkg")
        rep.collect("ssl_pinning", {"skipped": True})
        assert rep.generate_json()["summary"]["ssl_pinning"]["status"] == "SKIP"

    def test_ssl_na_when_no_pinning(self):
        """Sem pinning (bypass None) => status N/A."""
        rep = Reporter(device_info=DEVICE, package_name="pkg")
        rep.collect("ssl_pinning", {
            "pinning_detected": False, "pinning_type": "none",
            "bypass_successful": None,
        })
        assert rep.generate_json()["summary"]["ssl_pinning"]["status"] == "N/A"

    def test_status_anti_hooking(self):
        """Regras do anti_hooking: sem proteção/bypassou => FALHOU; resistiu => OK."""
        rep = Reporter(device_info=DEVICE, package_name="pkg")
        rep.collect("anti_hooking", {
            "protection_detected": False, "bypass_successful": None,
        })
        assert rep.generate_json()["summary"]["anti_hooking"]["status"] == "FALHOU"

        rep2 = Reporter(device_info=DEVICE, package_name="pkg")
        rep2.collect("anti_hooking", {
            "protection_detected": True, "bypass_successful": False,
        })
        assert rep2.generate_json()["summary"]["anti_hooking"]["status"] == "OK"

        rep3 = Reporter(device_info=DEVICE, package_name="pkg")
        rep3.collect("anti_hooking", {
            "protection_detected": True, "bypass_successful": True,
        })
        assert rep3.generate_json()["summary"]["anti_hooking"]["status"] == "FALHOU"

        # Proteção presente com bypass não avaliado é etapa que não rodou
        # (SKIP), e não ausência de aplicabilidade (N/A).
        rep4 = Reporter(device_info=DEVICE, package_name="pkg")
        rep4.collect("anti_hooking", {
            "protection_detected": True, "bypass_successful": None,
        })
        summary4 = rep4.generate_json()["summary"]["anti_hooking"]
        assert summary4["status"] == "SKIP"
        assert summary4["skip_reason"]

    def test_status_anti_hooking_error(self):
        """Anti-hooking com error no topo => ERROR (bypass/observação falhou)."""
        rep = Reporter(device_info=DEVICE, package_name="pkg")
        rep.collect("anti_hooking", {
            "protection_detected": True, "bypass_successful": None,
            "error": "bypass: spawn falhou",
        })
        assert rep.generate_json()["summary"]["anti_hooking"]["status"] == "ERROR"


class TestGenerateHtml:
    """Renderização do template HTML."""

    def test_html_contains_brand_and_status(self):
        """HTML contém a marca RASPilot e os badges de status."""
        html = _reporter().generate_html()
        assert "RASPilot" in html
        assert "Piloto Automático de Auditoria RASP" in html
        assert "FALHOU" in html
        assert "com.example.app" in html

    def test_html_escapes_package(self):
        """Package name hostil é escapado no HTML."""
        rep = Reporter(device_info=DEVICE, package_name="<script>alert(1)</script>")
        html = rep.generate_html()
        assert "<script>alert(1)</script>" not in html

    def test_html_includes_json_blob(self):
        """O JSON completo está embutido (escapado) para consumo por LLMs."""
        html = _reporter().generate_html()
        assert "tool_name" in html
        assert "anti_root" in html
        assert "bypass_successful" in html


class TestSave:
    """Persistência dos relatórios."""

    def test_save_writes_both_files(self, tmp_path):
        """Salva .json e .html com nome <pkg>_<timestamp>."""
        rep = Reporter(
            device_info=DEVICE, package_name="com.example.app",
            output_dir=str(tmp_path),
        )
        for name, result in RESULTS.items():
            rep.collect(name, result)
        json_path, html_path = rep.save()

        assert os.path.isfile(json_path)
        assert os.path.isfile(html_path)
        assert json_path.endswith(".json") and html_path.endswith(".html")
        assert "com.example.app_" in json_path

        with open(json_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        assert doc["summary"]["anti_root"]["status"] == "FALHOU"

    def test_slug_sanitizes_package(self):
        """Pacotes exóticos viram slug seguro (pontos preservados)."""
        assert Reporter._slug("com.foo/bar baz") == "com.foo_bar_baz"
        assert Reporter._slug("///") == "app"


def test_anti_frida_inconclusive_is_error():
    """Resultado inconclusivo (vulnerable=None) vira ERROR, não OK."""
    rep = Reporter(device_info=DEVICE, package_name="pkg")
    rep.collect("anti_frida", {
        "vulnerable": None,
        "frida_present": True,
        "app_detection": {"observation_status": "crashed"},
    })
    summary = rep.generate_json()["summary"]["anti_frida"]
    assert summary["status"] == "ERROR"
    assert summary["error"]
