"""Testes do analisador de logcat (evidências independentes de RASP)."""

from __future__ import annotations

from unittest import mock

from logcat_analyzer import (
    analyze_logcat,
    analyze_since,
    format_evidence,
    get_logcat_mark,
)


class TestAnalyzeLogcat:
    """Classificação de morte, segurança e TLS no logcat."""

    def test_death_signal_and_security_signal(self):
        """SIGKILL junto de mensagem de segurança vira reação do RASP."""
        lines = [
            "10-16 10:00:00.000  1234  1234 I com.app : detected frida-server",
            "10-16 10:00:01.000   857   857 I Zygote  : Process 1234 exited due to signal 9",
        ]
        res = analyze_logcat(lines, package="com.app", pid=1234)
        assert res["available"] is True
        assert res["death"]["detected"] is True
        assert res["death"]["signal"] == "SIGKILL"
        assert res["has_rasp_evidence"] is True
        assert any(s["category"] == "frida" for s in res["security_signals"])
        assert res["suggestions"]

    def test_crash_without_security_is_not_rasp(self):
        """Crash nativo sem mensagem de segurança não é evidência RASP."""
        lines = [
            "10-16 10:00:00.000  1234  1234 F libc    : Fatal signal 11 (SIGSEGV), "
            "pid 1234 (com.app)",
        ]
        res = analyze_logcat(lines, package="com.app", pid=1234)
        assert res["death"]["detected"] is True
        assert res["death"]["kind"] == "crash"
        assert res["has_rasp_evidence"] is False
        assert any("crash" in s for s in res["suggestions"])

    def test_generic_security_from_other_app_is_ignored(self):
        """Termo genérico de outro app não conta sem citar o alvo."""
        lines = [
            "10-16 10:00:00.000  9999  9999 I OtherApp: security detected threat",
        ]
        res = analyze_logcat(lines, package="com.app", pid=1234)
        assert res["security_signals"] == []
        assert res["has_rasp_evidence"] is False

    def test_tls_errors_are_captured(self):
        """Erros de certificado/pinning são reportados separadamente."""
        lines = [
            "10-16 10:00:00.000  1234  1234 E com.app : SSLHandshakeException: "
            "Certificate pinning failure",
        ]
        res = analyze_logcat(lines, package="com.app", pid=1234)
        assert res["tls_errors"]
        assert res["has_rasp_evidence"] is True
        assert any("TLS" in s for s in res["suggestions"])

    def test_unavailable_when_no_lines(self):
        """Sem linhas o resultado é explicitamente indisponível."""
        res = analyze_logcat([], package="com.app", pid=1)
        assert res["available"] is False
        assert res["summary"] == "logcat indisponível"

    def test_target_lines_are_captured(self):
        """Linhas que citam o pacote ficam disponíveis para o relatório."""
        lines = ["10-16 10:00:00.000  1234  1234 I com.app : starting"]
        res = analyze_logcat(lines, package="com.app", pid=1234)
        assert res["target_lines"] == ["10-16 10:00:00.000 1234 1234 I com.app : starting"]


class TestHelpers:
    """Helpers tolerantes a DeviceManager fake."""

    def test_get_logcat_mark_missing_api(self):
        """DeviceManager sem logcat_mark devolve None."""
        assert get_logcat_mark(object()) is None

    def test_get_logcat_mark_invalid_value(self):
        """Valor não inteiro é descartado."""
        dm = mock.MagicMock()
        dm.logcat_mark.return_value = "x"
        assert get_logcat_mark(dm) is None

    def test_analyze_since_handles_missing_api(self):
        """Sem logcat_since o resultado fica indisponível, sem exceção."""
        res = analyze_since(object(), None, package="com.app", pid=1)
        assert res["available"] is False

    def test_analyze_since_filters_non_list(self):
        """Retorno inesperado da API não quebra a análise."""
        dm = mock.MagicMock()
        dm.logcat_since.return_value = "not-a-list"
        res = analyze_since(dm, 1, package="com.app")
        assert res["available"] is False

    def test_format_evidence(self):
        """Evidências formatadas incluem morte, segurança e TLS."""
        analysis = {
            "death": {"detected": True, "kind": "kill", "signal": "SIGKILL",
                      "evidence": ["am_kill"]},
            "security_signals": [{"category": "frida", "line": "frida found"}],
            "tls_errors": ["SSLHandshakeException"],
        }
        evidence = format_evidence(analysis)
        assert any("logcat_death" in e for e in evidence)
        assert any("logcat_frida" in e for e in evidence)
        assert any("logcat_tls" in e for e in evidence)
