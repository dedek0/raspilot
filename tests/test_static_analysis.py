"""Testes da camada de análise estática do APK.

Cobrem o adaptador do ASC, o cache, o fallback por assinaturas e a
integração conservadora com os checks (N/A x FALHOU).
"""

from __future__ import annotations

import json
import zipfile
from unittest import mock

import pytest

from checks.anti_frida import AntiFridaCheck
from checks.anti_hooking import AntiHookingCheck
from checks.anti_root import AntiRootCheck
from checks.ssl_pinning import SSLPinningCheck
from checks.static import (
    build_static_profile,
    merge_pinning_detection,
    merge_signature_detection,
    vector_view,
)
from checks.static.engine import AscEngine, parse_findrefs
from reporter import Reporter


def _make_apk(path, blobs):
    """Cria um APK zip mínimo com as entradas informadas."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in blobs.items():
            archive.writestr(name, data)
    return str(path)


def _profile(vector, present=True, findings=None, confidence="high"):
    """Perfil estático mínimo para testes de integração."""
    findings = findings or [
        {
            "vector": vector,
            "source": "asc",
            "kind": "string_ref",
            "value": "x",
            "evidence": f"Lcom/x;->check referencia x ({vector})",
            "confidence": confidence,
            "class": "Lcom/x;",
            "method": "check",
            "label": "checagem",
        }
    ]
    return {
        "available": True,
        "engine": "asc",
        "version": "0.1.2.post3",
        "package": "com.example.app",
        "vectors": {
            vector: {
                "present": present,
                "confidence": confidence if present else "none",
                "findings": findings if present else [],
                "total": len(findings) if present else 0,
                "sources": ["asc"],
                "techniques": ["checagem"] if present else [],
            }
        },
        "coverage": {
            vector: {
                "bypass_hooks": ["hook"],
                "possible_gaps": ["possível checagem nativa"] if present else [],
                "static_present": present,
            }
        },
        "manifest": {"available": True, "package": "com.example.app"},
        "rasp_sdks": [],
        "classes_count": 1,
        "summary": {
            "available": True,
            "engine": "asc",
            "vectors_present": [vector] if present else [],
            "vectors": {},
        },
        "limitations": [],
        "errors": [],
        "timestamp": "2026-10-26T00:00:00+00:00",
        "cached": False,
    }


class TestAscParsing:
    """Parsing da saída textual do ASC."""

    def test_parse_findrefs_method(self):
        stdout = (
            "classes.dex | Lcom/x;->check | matched=(frida)\n"
            "classes2.dex | Lcom/y;->run | matched=(/proc/self/maps)\n"
        )
        hits = parse_findrefs(stdout)
        assert hits[0]["class"] == "Lcom/x;"
        assert hits[0]["method"] == "check"
        assert hits[1]["dex"] == "classes2.dex"

    def test_parse_findrefs_extends(self):
        stdout = "classes.dex | Lcom/x; extends Lcom/y;\n"
        hits = parse_findrefs(stdout)
        assert hits[0]["class"] == "Lcom/x;"
        assert hits[0]["method"] == ""

    def test_parse_findrefs_ignores_noise(self):
        assert parse_findrefs("sem separador\n\n") == []


class TestAscCache:
    """Cache em disco e memoização do adaptador."""

    def test_cache_avoids_second_subprocess(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RASPILOT_STATIC_CACHE_DIR", str(tmp_path / "cache"))
        apk = _make_apk(tmp_path / "app.apk", {"classes.dex": b"dex"})
        engine = AscEngine(cache=True)
        engine._execute = mock.Mock(
            return_value={
                "ok": True,
                "rc": 0,
                "stdout": "<manifest package=\"com.x\"/>",
                "stderr": "",
                "cmd": [],
                "cached": False,
            }
        )
        first = engine.get_manifest(apk)
        second = engine.get_manifest(apk)
        assert first["ok"] is True
        assert second["cached"] is True
        engine._execute.assert_called_once()

    def test_timeout_is_reported_not_raised(self, tmp_path, monkeypatch):
        apk = _make_apk(tmp_path / "app.apk", {"classes.dex": b"dex"})
        engine = AscEngine(cache=False)
        with mock.patch(
            "checks.static.engine.subprocess.run",
            side_effect=__import__("subprocess").TimeoutExpired("droidasc", 1),
        ):
            result = engine.get_manifest(apk)
        assert result["ok"] is False
        assert "timeout" in result["stderr"]


class TestProfileBuilding:
    """Construção do perfil com ASC e com fallback."""

    def test_builtin_profile_detects_signatures(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RASPILOT_STATIC_CACHE", "0")
        apk = _make_apk(
            tmp_path / "app.apk",
            {
                "classes.dex": (
                    b"frida okhttp3/CertificatePinner magisk "
                    b"de.robv.android.xposed.XposedBridge"
                ),
            },
        )
        profile = build_static_profile(
            None, "com.example.app", apk_path=apk, engine="builtin"
        )
        assert profile["available"] is True
        assert profile["engine"] == "builtin"
        assert profile["vectors"]["frida"]["present"] is True
        assert profile["vectors"]["root"]["present"] is True
        assert profile["vectors"]["hooking"]["present"] is True
        assert profile["vectors"]["pinning"]["present"] is True
        assert profile["manifest"]["available"] is False
        assert any("ASC indisponível" in item for item in profile["limitations"])

    def test_frida_signature_does_not_become_hooking(self, tmp_path, monkeypatch):
        """A assinatura do Frida pertence ao vetor frida, não ao anti-hook."""
        monkeypatch.setenv("RASPILOT_STATIC_CACHE", "0")
        apk = _make_apk(
            tmp_path / "app.apk", {"classes.dex": b"gum-js-loop libfrida"}
        )
        profile = build_static_profile(
            None, "com.example.app", apk_path=apk, engine="builtin"
        )
        assert profile["vectors"]["frida"]["present"] is True
        assert profile["vectors"]["hooking"]["present"] is False

    def test_asc_profile_uses_manifest_classes_and_refs(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RASPILOT_STATIC_CACHE", "0")
        apk = _make_apk(tmp_path / "app.apk", {"classes.dex": b"dex"})

        class FakeAsc:
            version = "0.1.2.post3"

            def __init__(self, *args, **kwargs):
                pass

            def get_manifest(self, path, timeout=None):
                return {
                    "ok": True,
                    "stdout": (
                        '<manifest package="com.example.app">'
                        '<application android:debuggable="true" '
                        'android:networkSecurityConfig="@xml/nsc"/>'
                        "</manifest>"
                    ),
                    "stderr": "",
                    "rc": 0,
                    "cmd": [],
                    "cached": False,
                }

            def list_classes(self, path, prefix=None, timeout=None):
                return {
                    "ok": True,
                    "stdout": (
                        "Lde/robv/android/xposed/XposedBridge;\n"
                        "Lcom/scottyab/rootbeer/RootBeer;\n"
                    ),
                    "stderr": "",
                    "rc": 0,
                    "cmd": [],
                    "cached": False,
                }

            def parse_classes(self, result):
                return [
                    line.strip()
                    for line in (result.get("stdout") or "").splitlines()
                    if line.strip()
                ]

            def find_refs_parsed(
                self,
                path,
                kind,
                value=None,
                class_name=None,
                fuzzy_class=False,
                timeout=None,
            ):
                if kind == "string" and value and "frida" in value:
                    return {
                        "ok": True,
                        "hits": [
                            {
                                "dex": "classes.dex",
                                "class": "Lcom/example/Check;",
                                "method": "run",
                                "matched": "(frida)",
                                "raw": "x",
                            }
                        ],
                        "error": None,
                    }
                return {"ok": True, "hits": [], "error": None}

        monkeypatch.setattr("checks.static.profile.AscEngine", FakeAsc)
        monkeypatch.setattr("checks.static.profile.asc_available", lambda: True)
        profile = build_static_profile(
            None, "com.example.app", apk_path=apk, engine="asc"
        )
        assert profile["engine"] == "asc"
        assert profile["manifest"]["debuggable"] is True
        assert profile["manifest"]["network_security_config"] == "@xml/nsc"
        assert profile["classes_count"] == 2
        assert profile["vectors"]["hooking"]["present"] is True
        assert profile["vectors"]["root"]["present"] is True
        frida = profile["vectors"]["frida"]["findings"]
        assert any(item["method"] == "run" for item in frida)

    def test_unavailable_without_apk(self, monkeypatch):
        monkeypatch.setenv("RASPILOT_STATIC_CACHE", "0")
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        profile = build_static_profile(dm, "com.example.app", engine="builtin")
        assert profile["available"] is False
        assert "APK" in (profile["summary"].get("error") or "")


class TestHelpers:
    """Funções de merge usadas pelos checks."""

    def test_vector_view_none_when_unavailable(self):
        assert vector_view(None, "frida") is None
        assert vector_view({"available": False}, "frida") is None
        assert vector_view(_profile("frida"), "root") is None

    def test_merge_signature_detection(self):
        merged = merge_signature_detection(
            {"static_detected": False, "evidence": [], "types": []},
            vector_view(_profile("hooking"), "hooking"),
        )
        assert merged["static_detected"] is True
        assert merged["asc_available"] is True
        assert merged["evidence"]

    def test_merge_pinning_detection_overrides_error(self):
        merged = merge_pinning_detection(
            {"pinning_detected": False, "type": "none", "error": "sem APK"},
            vector_view(_profile("pinning"), "pinning"),
        )
        assert merged["pinning_detected"] is True
        assert "error" not in merged
        assert merged["type"] in (
            "okhttp", "trustkit", "network_security_config", "native", "asc"
        )

    def test_weak_pinning_evidence_is_not_pinning(self):
        """Flutter/Conscrypt sem indicador forte não viram pinning."""
        merged = merge_pinning_detection(
            {"pinning_detected": False, "type": "none", "evidence": []},
            vector_view(
                _profile("pinning", confidence="low"), "pinning"
            ),
        )
        assert merged["pinning_detected"] is False
        assert merged["asc_weak_only"] is True


class TestAntiFridaStaticVerdict:
    """O perfil estático separa 'sem proteção' de 'bypass venceu'."""

    @staticmethod
    def _run(profile):
        dm = mock.MagicMock()
        check = AntiFridaCheck(dm)
        detection = {
            "vulnerable": True,
            "detected": False,
            "observation_status": "observed",
            "detection_methods_found": [],
            "strong_signals": [],
            "weak_signals": [],
            "app_alive_at_end": True,
            "session_unsafe": False,
        }
        with mock.patch.object(
            check, "check_frida_processes", return_value={"detected": True}
        ), mock.patch.object(
            check, "check_frida_ports", return_value={"detected": False}
        ), mock.patch.object(
            check, "check_frida_threads", return_value={"detected": False}
        ), mock.patch.object(
            check, "check_frida_libraries", return_value={"detected": False}
        ):
            return check.run_all(
                None,  # type: ignore[arg-type]
                pid=1,
                app_detection=detection,
                static_profile=profile,
            )

    def test_no_protection_becomes_na(self):
        result = self._run(_profile("frida", present=False))
        assert result["vulnerable"] is None
        assert result["status_hint"] == "N/A"
        assert result["protection_detected"] is False
        status, summary = Reporter._status_for("anti_frida", result)
        assert status == "N/A"
        assert summary["static_present"] is False

    def test_static_protection_keeps_vulnerable_true(self):
        result = self._run(_profile("frida", present=True))
        assert result["vulnerable"] is True
        assert result["status_hint"] is None
        assert result["protection_detected"] is True
        status, _summary = Reporter._status_for("anti_frida", result)
        assert status == "FALHOU"

    def test_medium_confidence_reference_is_not_protection(self):
        """Uma referência genérica a Frida não vira 'proteção detectada'."""
        result = self._run(_profile("frida", present=True, confidence="medium"))
        assert result["vulnerable"] is None
        assert result["status_hint"] == "N/A"
        assert result["protection_detected"] is False

    def test_without_profile_keeps_legacy_verdict(self):
        result = self._run(None)
        assert result["vulnerable"] is True
        assert result["status_hint"] is None


class TestCheckStaticIntegration:
    """Os checks reaproveitam o perfil sem alterar falsamente o veredito."""

    def test_anti_hooking_uses_profile(self):
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        dm.run_shell_root.return_value = dm.run_shell.return_value
        check = AntiHookingCheck(dm, mode="detect")
        detection = {
            "detected": False,
            "detection_methods_found": [],
            "strong_signals": [],
            "weak_signals": [],
            "app_alive_at_end": True,
            "session_unsafe": False,
        }
        result = check.run_all(
            "com.example.app",
            precomputed_detection=detection,
            static_profile=_profile("hooking"),
        )
        assert result["static_detection"]["static_detected"] is True
        assert result["protection_detected"] is True
        assert result["static_analysis"]["engine"] == "asc"
        assert result["bypass_successful"] is None

    def test_anti_root_keeps_device_verdict_and_adds_app_detection(self):
        dm = mock.MagicMock()
        dm.run_shell.return_value = {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        dm.run_shell_root.return_value = dm.run_shell.return_value
        result = AntiRootCheck(dm).run_all(static_profile=_profile("root"))
        assert result["is_rooted"] is False
        assert result["app_root_detection"]["present"] is True
        assert result["static_analysis"]["vector"] == "root"

    def test_ssl_uses_profile_when_builtin_scan_misses(self):
        dm = mock.MagicMock()
        check = SSLPinningCheck(dm, mode="detect")
        with mock.patch.object(
            check,
            "detect_pinning",
            return_value={"pinning_detected": False, "type": "none", "evidence": []},
        ):
            result = check.run_all(
                "com.example.app", static_profile=_profile("pinning")
            )
        assert result["pinning_detected"] is True
        assert result["bypass_successful"] is None
        assert result["static_analysis"]["present"] is True

    def test_ssl_weak_native_evidence_is_skipped(self):
        """Evidência fraca + lacuna nativa não pode virar N/A."""
        profile = _profile("pinning", confidence="low")
        profile["coverage"]["pinning"]["possible_gaps"] = [
            "possível checagem nativa/fora da camada Java (indício: boringssl)"
        ]
        check = SSLPinningCheck(mock.MagicMock(), mode="detect")
        result = check.run_all("com.example.app", static_profile=profile)
        assert result["pinning_suspected"] is True
        assert result["status_hint"] == "SKIP"
        status, summary = Reporter._status_for("ssl_pinning", result)
        assert status == "SKIP"
        assert summary["pinning_suspected"] is True

    def test_ssl_weak_evidence_runs_probe(self):
        """Com evidência fraca, o bypass vira probe de tráfego TLS."""
        profile = _profile("pinning", confidence="low")
        profile["coverage"]["pinning"]["possible_gaps"] = [
            "possível checagem nativa/fora da camada Java (indício: boringssl)"
        ]
        check = SSLPinningCheck(mock.MagicMock(), mode="bypass")
        probe = {
            "success": True,
            "intercepted_hosts": ["api.example"],
            "evidence_strength": "host",
            "app_alive_at_end": True,
        }
        with mock.patch.object(check, "attempt_bypass", return_value=probe) as attempt:
            result = check.run_all("com.example.app", static_profile=profile)
        attempt.assert_called_once()
        assert attempt.call_args.kwargs["window"] >= 20
        assert attempt.call_args.kwargs.get("interact") is True
        assert result["tls_observed"] is True
        assert result["intercepted_hosts"] == ["api.example"]
        assert result["pinning_detected"] is False
        assert result["status_hint"] == "SKIP"
        status, summary = Reporter._status_for("ssl_pinning", result)
        assert status == "SKIP"
        assert summary["tls_observed"] is True
