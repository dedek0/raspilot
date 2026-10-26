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


class TestPidScopedAttribution:
    """Atribuição de linha por pid: instância residual não contamina a fase.

    Uma instância anterior do mesmo app pode continuar rodando em
    segundo plano (spawn anterior sem force-stop) e logar com o mesmo
    package name. A linha dela tem pid de emissor diferente do alvo — e
    não deve sustentar veredito da fase observada.
    """

    def test_stale_instance_line_is_not_attributed(self):
        """Linha de outro processo do mesmo pacote não entra como evidência."""
        lines = [
            # instância residual (fase anterior) detectando frida
            "10-16 10:00:01.000 4242 4242 I RASP: frida-server detected",
            # instância observada na fase atual
            "10-16 10:00:02.000 5678 5678 I RASP: frida-server detected",
        ]
        res = analyze_logcat(lines, package="com.app", pid=5678)
        frida = [s for s in res["security_signals"] if s["category"] == "frida"]
        assert frida, "a linha do processo observado deve ser mantida"
        assert all(s["line"].split()[3] == "5678" for s in frida), frida

    def test_stale_instance_death_is_not_attributed(self):
        """Morte da instância residual não vira morte da fase atual."""
        lines = [
            "10-16 10:00:03.000 1520 1570 I ActivityManager: "
            "Process com.app (pid 4242) has died",
        ]
        res = analyze_logcat(lines, package="com.app", pid=5678)
        assert res["death"]["detected"] is False

    def test_system_kill_of_target_pid_is_kept(self):
        """am_kill do sistema citando o pid alvo continua sendo evidência."""
        lines = [
            "10-16 10:00:03.000 1520 1570 W ActivityManager: "
            "Killing 5678:com.app/10008 (adj 0): root detected",
        ]
        res = analyze_logcat(lines, package="com.app", pid=5678)
        assert res["death"]["detected"] is True

    def test_message_of_target_pid_is_kept(self):
        """Tombstone/exit do Zygote citando o pid alvo no corpo conta."""
        lines = [
            # emissor é o Zygote (1520), mas o corpo cita o pid alvo
            "10-16 10:00:01.000 1520 1570 I Zygote  : Process 5678 exited "
            "due to signal 9",
        ]
        res = analyze_logcat(lines, package="com.app", pid=5678)
        assert res["death"]["detected"] is True
        assert res["death"]["signal"] == "SIGKILL"

    def test_app_own_line_without_pid_in_body_is_kept(self):
        """Linha emitida pelo próprio processo alvo conta mesmo sem corpo."""
        lines = [
            "10-16 10:00:02.000 5678 5678 I SomeTag: running checks",
        ]
        res = analyze_logcat(lines, package="com.app", pid=5678)
        assert res["target_lines"]

    def test_without_pid_the_package_still_matches(self):
        """Sem pid conhecido, o critério por pacote é mantido."""
        lines = [
            "10-16 10:00:01.000 4242 4242 I SecurityService: "
            "com.app reports frida-server detected",
        ]
        res = analyze_logcat(lines, package="com.app")
        assert any(s["category"] == "frida" for s in res["security_signals"])
        assert res["target_lines"]


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
