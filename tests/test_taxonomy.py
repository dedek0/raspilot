"""Testes da taxonomia de artefatos e da atribuição de origem."""

from __future__ import annotations

from checks.taxonomy import (
    classify_marker,
    is_app_evidence,
    marker_owner,
    owner_counts,
    token_match,
)


class TestClassifyMarker:
    """Frida, hook e debug não podem compartilhar o mesmo rótulo."""

    def test_frida_is_not_hooking(self):
        assert classify_marker("/data/local/tmp/frida-server") == "frida"
        assert classify_marker("gum-js-loop") == "frida"
        assert classify_marker("libfrida.so") == "frida"

    def test_hook_frameworks(self):
        assert classify_marker("de.robv.android.xposed.XposedBridge") == "hooking"
        assert classify_marker("org.lsposed.lspd") == "hooking"
        assert classify_marker("SandHook") == "hooking"

    def test_root_and_emulator(self):
        assert classify_marker("com.topjohnwu.magisk") == "root"
        assert classify_marker("ro.kernel.qemu") == "emulator"
        assert classify_marker("CertificatePinner") == "pinning"

    def test_unknown(self):
        assert classify_marker("com.example.analytics") is None

    def test_token_boundary(self):
        assert token_match("com.example.fridaplayer", "frida") is False
        assert token_match("/data/local/tmp/frida-server", "frida") is True
        assert token_match("de.robv.android.xposed.XposedBridge", "xposed") is True


class TestOwner:
    """A origem evita tratar biblioteca empacotada como proteção do app."""

    def test_app_package(self):
        assert marker_owner("Lcom/acme/app/Main;", "com.acme.app") == "app"

    def test_rasp_sdk(self):
        assert marker_owner("Lcom/promon/security/Checker;") == "rasp_sdk"

    def test_framework(self):
        assert marker_owner("Lde/robv/android/xposed/XposedBridge;") == "framework"

    def test_third_party_and_library(self):
        assert marker_owner("Lcom/appsflyer/internal/AFf1iSDK;") == "third_party_sdk"
        assert marker_owner("Lokhttp3/CertificatePinner;") == "library"

    def test_obfuscated_is_kept_as_unknown(self):
        owner = marker_owner("La1b2c3/d4e5f6/Check;")
        assert owner == "unknown"
        assert is_app_evidence(owner) is True

    def test_owner_counts(self):
        counts = owner_counts(["app", "app", "library", "unknown"])
        assert counts == {"app": 2, "library": 1, "unknown": 1}
