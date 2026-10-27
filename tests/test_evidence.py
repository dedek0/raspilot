"""Testes de regressão do modelo de evidência.

Cobrem os casos em que o veredito era sustained por evidência fraca:
linha de logcat do sistema, termo genérico sem verbo de detecção, log
de framework do operador e morte sem causa atribuível.
"""

from __future__ import annotations

from unittest import mock

from checks.anti_hooking import AntiHookingCheck
from logcat_analyzer import analyze_logcat, classify_failure

PKG = "com.example.app"
PID = 4242


def _line(tag: str, message: str, pid: int = PID) -> str:
    return f"10-16 10:00:00.000 {pid} {pid} I {tag}: {message}"


class TestEvidenceTiering:
    """Só evidência de confiança alta sustenta um veredito."""

    def test_system_log_line_is_not_a_detection(self):
        """Uma linha de log do sistema não é reação do app à instrumentação."""
        analysis = analyze_logcat(
            [_line("adbd", "jdwp connection from 12345")], PKG, PID
        )
        assert analysis["has_rasp_evidence"] is False
        assert analysis["context_signals"], "o termo deve ficar como contexto"
        assert not any(
            s["confidence"] == "high" for s in analysis["security_signals"]
        )

    def test_generic_term_without_detection_verb_is_context(self):
        """"root cause" em um log de app não é detecção de root."""
        analysis = analyze_logcat(
            [_line(PKG, "Root cause: java.lang.NullPointerException")], PKG, PID
        )
        assert analysis["has_rasp_evidence"] is False
        assert analysis["context_signals"], "o termo deve ficar como contexto"

    def test_generic_term_with_detection_verb_is_a_detection(self):
        """"xposed detected" é reação do app."""
        analysis = analyze_logcat(
            [_line(PKG, "detected xposed framework")], PKG, PID
        )
        assert analysis["has_rasp_evidence"] is True

    def test_specific_artifact_is_a_detection(self):
        """Um artefato de instrumentação citado é evidência direta."""
        analysis = analyze_logcat(
            [_line(PKG, "module libfrida-agent.so loaded")], PKG, PID
        )
        assert analysis["has_rasp_evidence"] is True

    def test_operator_framework_log_is_not_app_protection(self):
        """Log de framework de hooking do operador não é proteção do app."""
        analysis = analyze_logcat(
            [_line("Vector", "Loading Vector/Xposed for com.example.app")], PKG, PID
        )
        categories = {s["category"] for s in analysis["security_signals"]}
        assert any(c.startswith("operator:") for c in categories), (
            "o log do framework do operador deve ser marcado como tal"
        )
        assert analysis["has_rasp_evidence"] is False

    def test_vendor_sdk_log_is_a_detection(self):
        """Log de um SDK de RASP conhecido é reação do app."""
        analysis = analyze_logcat(
            [_line("SecShell", "integrity check failed")], PKG, PID
        )
        assert analysis["vendor_signals"], "o log do vendor deve ser sinalizado"
        assert analysis["has_rasp_evidence"] is True

    def test_tls_taxonomy_covers_real_failures(self):
        """Falhas reais de TLS são reconhecidas."""
        for message in (
            "javax.net.ssl.SSLHandshakeException: Chain validation failed",
            "Unable to find valid certification path to requested target",
            "okhttp3.internal.tls.OkHostnameVerifier: hostname api.x not verified",
            "javax.net.ssl.CertificateVerifyException: pinning failed",
        ):
            analysis = analyze_logcat([_line(PKG, message)], PKG, PID)
            assert analysis["tls_errors"], f"não reconhecida: {message}"


class TestDeathClassification:
    """Morte sem causa atribuível não vira detecção."""

    def test_process_death_without_colon_is_detected(self):
        """A mensagem de morte do ActivityManager não tem dois-pontos."""
        analysis = analyze_logcat(
            ["10-16 10:00:00.000 900 900 I ActivityManager: "
             f"Process {PKG} (pid {PID}) has died"], PKG, PID
        )
        assert analysis["death"]["detected"] is True

    def test_unclassified_death_is_not_a_rasp_reaction(self):
        """Uma morte sem sinal de segurança é instrumentação, não RASP."""
        analysis = analyze_logcat(
            [_line("libc", "Fatal signal 11 (SIGSEGV), code 1 in tid 4242")],
            PKG, PID,
        )
        failure = classify_failure(analysis, None)
        assert failure["is_rasp"] is False
        assert failure["kind"] in ("instrumentation_crash", "unknown_death")

    def test_crash_after_healthy_baseline_is_a_rasp_reaction(self):
        """App estável sozinho que morre instrumentado bloqueou a auditoria."""
        analysis = analyze_logcat(
            [_line("libc", "Fatal signal 11 (SIGSEGV), code 1 in tid 4242")],
            PKG, PID,
        )
        failure = classify_failure(
            analysis, {"available": True, "alive_at_end": True}
        )
        assert failure["kind"] == "rasp_reaction"
        assert failure["is_rasp"] is True

    def test_crash_after_dead_baseline_stays_inconclusive(self):
        """App que já morre no baseline não é reação à instrumentação."""
        analysis = analyze_logcat(
            [_line("libc", "Fatal signal 11 (SIGSEGV), code 1 in tid 4242")],
            PKG, PID,
        )
        failure = classify_failure(
            analysis, {"available": True, "alive_at_end": False}
        )
        assert failure["kind"] == "baseline_death"
        assert failure["is_rasp"] is False


class TestCrashOrigin:
    """A origem da queda distingue a proteção do app da falha da tool."""

    FRAMES_INSTRUMENTATION = [
        "10-16 10:00:00.000 999 999 F DEBUG   :       #00 pc 00000000002f9b88  "
        "/apex/com.android.art/lib64/libart.so (art::Monitor::MonitorExit(...)+120)",
        "10-16 10:00:00.000 999 999 F DEBUG   :       #01 pc 00000000002faf60  "
        "/apex/com.android.art/lib64/libart.so (artJniUnlockObject+56)",
        "10-16 10:00:00.000 999 999 F DEBUG   :       #02 pc 00000000002fb484  "
        "/apex/com.android.art/lib64/libart.so (artQuickGenericJniEndTrampoline+804)",
    ]

    FRAMES_APP = [
        "10-16 10:00:00.000 999 999 F DEBUG   :       #00 pc 0000000000012345  "
        "/data/app/~~abc==/com.app-xyz/lib/arm64/libguard.so (guard_check+32)",
        "10-16 10:00:00.000 999 999 F DEBUG   :       #01 pc 0000000000012346  "
        "/data/app/~~abc==/com.app-xyz/lib/arm64/libguard.so (guard_abort+16)",
    ]

    def _lines(self, frames):
        header = (
            "10-16 10:00:00.000 999 999 F DEBUG   : pid: 4242, tid: 4243, "
            "name: worker  >>> com.app <<<"
        )
        return [header] + frames

    def test_artifact_of_the_agent_is_the_instrumentation(self):
        """Queda dentro do agente do Frida é falha da ferramenta."""
        analysis = analyze_logcat(self._lines(self.FRAMES_INSTRUMENTATION), PKG, PID)
        assert analysis["crash_origin"] == "instrumentation"

    def test_crash_in_the_app_code_is_the_app(self):
        """Queda no código do próprio app é reação do app."""
        analysis = analyze_logcat(self._lines(self.FRAMES_APP), PKG, PID)
        assert analysis["crash_origin"] == "app"

    def test_no_backtrace_is_unknown(self):
        """Sem backtrace não há como atribuir a origem."""
        analysis = analyze_logcat([_line("libc", "Fatal signal 11")], PKG, PID)
        assert analysis["crash_origin"] == "unknown"

    def test_instrumentation_crash_is_not_a_rasp_reaction(self):
        """Queda da instrumentação não credita proteção ao app."""
        lines = self._lines(self.FRAMES_INSTRUMENTATION) + [
            _line("libc", "Fatal signal 11 (SIGSEGV), code 1 in tid 4242"),
        ]
        analysis = analyze_logcat(lines, PKG, PID)
        failure = classify_failure(
            analysis, {"available": True, "alive_at_end": True}
        )
        assert failure["kind"] == "instrumentation_crash"
        assert failure["is_rasp"] is False

    def test_backtrace_frames_are_not_read_as_detection(self):
        """Citar "frida-agent" no backtrace não é detecção do app."""
        lines = self._lines([
            "10-16 10:00:00.000 999 999 F DEBUG   :       #00 pc 0000000000012345  "
            "/memfd:frida-agent-64.so (deleted) (gum_js_loop+32)",
        ])
        analysis = analyze_logcat(lines, PKG, PID)
        assert analysis["categories"].get("frida") is None


class TestHookingVerdict:
    """O veredito de anti-hooking ignora evidência fraca."""

    def _run(self, lines):
        dm = mock.MagicMock()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = lines
        check = AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            return check.check_hook_detection_in_app(
                mock.MagicMock(), window=2, pid=PID, package_name=PKG,
                logcat_mark=0,
            )

    def test_system_log_does_not_create_protection(self):
        res = self._run([_line("adbd", "jdwp connection from 12345")])
        assert res["detected"] is False
        assert res["strong_signals"] == []

    def test_generic_app_log_does_not_create_protection(self):
        res = self._run([_line(PKG, "lifecycle hook failed for Activity")])
        assert res["detected"] is False


class TestBypassEvidence:
    """Evidência de bypass exige checagem exercitada, não hook instalado."""

    def _run(self, messages):
        from checks.anti_hooking import AntiHookingCheck

        dm = mock.MagicMock()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = []
        dm.baseline = None
        check = AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            return check.attempt_bypass("com.example.app", window=1)

    def test_hook_installed_alone_is_not_evidence(self, monkeypatch):
        """"hookado" prova instrumentação ativa, não app enganado."""
        import checks.anti_hooking as mod

        msgs = [
            {"type": "send", "payload": {
                "type": "raspilot-hooking-bypass",
                "message": "libc.strstr hookado",
            }},
            {"type": "send", "payload": {
                "type": "raspilot-hooking-bypass",
                "message": "anti_hooking_bypass.js carregado",
            }},
        ]

        class _Script:
            def __init__(self):
                self._cb = None

            def on(self, event, cb):
                self._cb = cb

            def load(self):
                for m in msgs:
                    self._cb(m, None)

            def unload(self):
                pass

        class _Session:
            def create_script(self, source, **kwargs):
                return _Script()

            def detach(self):
                pass

        dm = mock.MagicMock()
        dm.spawn_app.return_value = _Session()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = []
        dm.baseline = None
        check = mod.AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.attempt_bypass("com.example.app", window=1)
        assert res["bypass_logs"], "os logs do script devem ser coletados"
        assert res["effective_logs"] == []
        assert res["success"] is None
        assert "não exercitado" in res["skipped_reason"]

    def test_exercised_check_is_evidence(self):
        """Uma checagem do app neutralizada é evidência de bypass."""
        import checks.anti_hooking as mod

        msgs = [
            {"type": "send", "payload": {
                "type": "bypass-evidence",
                "message": "neutralizado: Class.forName('de.robv.android.xposed.XposedBridge')",
            }},
        ]

        class _Script:
            def __init__(self):
                self._cb = None

            def on(self, event, cb):
                self._cb = cb

            def load(self):
                for m in msgs:
                    self._cb(m, None)

            def unload(self):
                pass

        class _Session:
            def create_script(self, source, **kwargs):
                return _Script()

            def detach(self):
                pass

        dm = mock.MagicMock()
        dm.spawn_app.return_value = _Session()
        dm.is_app_alive.return_value = True
        dm.logcat_since.return_value = []
        dm.baseline = None
        check = mod.AntiHookingCheck(dm)
        with mock.patch("checks.anti_hooking.OBSERVATION_POLL_INTERVAL", 0.0):
            res = check.attempt_bypass("com.example.app", window=1)
        assert res["effective_logs"], "a checagem exercitada é evidência"
        assert res["success"] is True


class TestAgentCrashIsNotProtection:
    """O crash do agente de instrumentação não é proteção do app."""

    def test_agent_crash_alone_does_not_detect_frida(self):
        from checks.combined import _frida_detection, _hooking_detection

        logcat = {
            "available": True,
            "agent_terminated": True,
            "categories": {},
            "security_signals": [{
                "category": "frida_agent_crash",
                "confidence": "low",
                "line": "F app: runtime.cc:769 /memfd:frida-agent-64.so (deleted)",
            }],
            "death": {"detected": False, "kind": None},
        }
        frida = _frida_detection(
            found=[], logcat=logcat, baseline=None, died_after=None,
            app_alive=True, java_load_error=None, java_skipped=False,
            stealth_used=False, window=5,
        )
        assert frida["vulnerable"] is None, (
            "a quebra do agente torna a observação inconclusiva"
        )
        assert frida["observation_status"] == "error"

        hooking = _hooking_detection(
            found=[], strong=[], weak=[], logcat=logcat, baseline=None,
            died_after=None, app_alive=True, java_load_error=None,
            java_skipped=False, stealth_used=False, window=5,
        )
        assert hooking["detected"] is False
        assert hooking["weak_signals"] == []
        assert "frida_agent_crash" not in " ".join(
            hooking["detection_methods_found"]
        )


class TestVendorSignalScope:
    """Sinal de vendor só vale quando a linha pertence ao alvo."""

    def test_system_line_mentioning_a_vendor_is_not_a_detection(self):
        """Linha de serviço do sistema não é reação do app."""
        analysis = analyze_logcat(
            ["10-19 16:56:26.430 27799 27799 D BoundBrokerSvc: onUnbind: "
             "Intent { act=com.google.android.gms.safetynet.service.START "
             "pkg=com.google.android.gms }"],
            PKG, PID,
        )
        assert analysis["vendor_signals"] == []
        assert analysis["has_rasp_evidence"] is False

    def test_vendor_line_in_the_target_process_is_a_detection(self):
        """O mesmo log, vindo do processo alvo, é reação do app."""
        analysis = analyze_logcat(
            [_line("SecShell", "integrity check failed")], PKG, PID
        )
        assert analysis["vendor_signals"]
        assert analysis["has_rasp_evidence"] is True
