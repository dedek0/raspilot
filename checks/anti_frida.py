"""RASPilot — Verificação Anti-Frida.

Verifica (a) a presença do Frida no dispositivo (processos, portas,
bibliotecas e threads do frida-server/gadget) e (b) se o app alvo
implementa mecanismos de detecção de Frida em runtime. O veredito
``vulnerable`` indica se o app **falhou** em bloquear o Frida.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional

from checks.stealth import load_stealth, unload_stealth
from logcat_analyzer import (
    HIGH_CONFIDENCE_CATEGORIES,
    analyze_since,
    classify_failure,
    format_detection_signals,
    format_evidence,
)
from script_loader import (
    enumerate_module_names,
    load_script,
    load_script_file,
    safe_detach,
    safe_unload,
)

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_frida")

# Portas padrão do frida-server (27042 principal, 27043 session).
FRIDA_PORTS = (27042, 27043)

# Portas em hex como aparecem em /proc/net/tcp (uppercase, big-endian).
FRIDA_PORTS_HEX = ("69A2", "69A3")

# Rastreio de quem mata o processo (mesmo script do anti-hooking/SSL).
KILL_TRACE_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "kill_trace.js"
)

# Nomes de threads típicas do Frida/GumJS.
FRIDA_THREAD_NAMES = ("gum-js-loop", "gmain", "pool-frida", "frida-agent")

# Strings que um app anti-frida costuma procurar.
FRIDA_KEYWORDS = ("frida", "gum-js-loop", "gadget", "libfrida")

# Script de OBSERVAÇÃO (não bypass): registra chamadas de detecção do app
# (File.exists em paths Frida, Runtime.exec com 'frida', strstr/strcmp em
# libc procurando 'frida') e as envia ao host via send().
DETECTION_SCRIPT = """
'use strict';

// Quando true, apenas os hooks Java são instalados (segunda fase, após o
// resume). Quando false, apenas os hooks nativos (primeira fase, sem
// bridge Java, rápida o suficiente para não estourar o start timeout).
var RASPILOT_JAVA_ONLY = (typeof __RASPILOT_JAVA_ONLY__ !== 'undefined')
    ? __RASPILOT_JAVA_ONLY__
    : false;

var detections = [];

function reportDetection(method, detail) {
    detections.push(method + ': ' + detail);
    send({ type: 'frida-detection', method: method, detail: detail });
}

// Falha de instalação de um hook de observação (diagnóstico — não conta
// como detecção pelo app).
function reportHookError(msg) {
    send({ type: 'frida-detection-error', message: msg });
}

function looksLikeFrida(str) {
    try {
        if (str === null || str === undefined) { return false; }
        return ('' + str).toLowerCase().indexOf('frida') !== -1;
    } catch (e) { return false; }
}

// Native: strstr/strcmp em libc buscando 'frida' (técnica clássica).
if (!RASPILOT_JAVA_ONLY) {
['strstr', 'strcmp'].forEach(function (name) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    if (name === 'strstr') {
                        var needle = args[1].readCString();
                        if (looksLikeFrida(needle)) {
                            reportDetection('native_' + name, 'needle=' + needle);
                        }
                    } else {
                        if (looksLikeFrida(args[0].readCString()) ||
                            looksLikeFrida(args[1].readCString())) {
                            reportDetection('native_' + name, 'comparação com string frida');
                        }
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});

// Native: connect() para portas Frida — anti-frida por "port scan"
// local, técnica comum que não usa strings 'frida'. Inclui as portas
// clássicas e a porta stealth configurada no host.
var RASPILOT_FRIDA_PORT = __RASPILOT_FRIDA_PORT__;
var FRIDA_SCAN_PORTS = [27042, 27043, RASPILOT_FRIDA_PORT];

try {
    var connectPtr = raspilotFindExport('libc.so', 'connect');
    if (connectPtr !== null) {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                try {
                    var sa = args[1];
                    var family = sa.readU16();
                    // AF_INET (2) e AF_INET6 (10).
                    if (family === 2 || family === 10) {
                        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        if (FRIDA_SCAN_PORTS.indexOf(port) !== -1) {
                            reportDetection('native_connect', 'porta ' + port);
                        }
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    }
} catch (e) { reportHookError('instalação de connect falhou: ' + e); }

// Native: open/openat de paths contendo 'frida'.
['open', 'openat', 'openat64'].forEach(function (name) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var pathPtr = (name === 'open') ? args[0] : args[1];
                    var path = pathPtr.readCString();
                    if (looksLikeFrida(path)) {
                        reportDetection('native_' + name, path);
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});

['access', 'stat', 'stat64', 'lstat', 'faccessat', 'faccessat2'].forEach(function (name) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var path = args[0].readCString();
                    if (looksLikeFrida(path)) {
                        reportDetection('native_' + name, path);
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});
}

function installJavaHooks() {
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = '' + this.getAbsolutePath();
            if (looksLikeFrida(path)) {
                reportDetection('File.exists', path);
            }
            return this.exists();
        };
    } catch (e) { /* Java indisponível */ }

    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (looksLikeFrida(cmd)) {
                reportDetection('Runtime.exec', '' + cmd);
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArr) {
            var joined = '';
            try { joined = cmdArr.join(' '); } catch (e) { joined = '' + cmdArr; }
            if (looksLikeFrida(joined)) {
                reportDetection('Runtime.exec[]', joined);
            }
            return this.exec(cmdArr);
        };
    } catch (e) { /* Java indisponível */ }

    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command();
            var joined = '';
            try { joined = cmd.toArray().join(' '); } catch (e) { joined = '' + cmd; }
            if (looksLikeFrida(joined)) {
                reportDetection('ProcessBuilder.start', joined);
            }
            return this.start();
        };
    } catch (e) { /* Java indisponível */ }
}

// A instalação é adiada: o carregamento do script precisa retornar antes
// que o agente limite o tempo de carga do script.
// Na fase nativa a bridge Java não existe, então os hooks Java ficam
// de fora.
if (RASPILOT_JAVA_ONLY) {
    if (typeof raspilotDeferJava === 'function') {
        raspilotDeferJava(installJavaHooks, 'anti-frida-detect');
    } else if (typeof raspilotPerformJava === 'function') {
        raspilotPerformJava(installJavaHooks);
    } else if (typeof Java !== 'undefined' && Java.available) {
        Java.perform(installJavaHooks);
    }
}

// Relata o snapshot final para o host quando solicitado.
rpc.exports = {
    getdetections: function () { return detections; }
};
"""


def _now_iso() -> str:
    """Retorna o timestamp atual em ISO8601 (UTC).

    Returns:
        Ex: ``'2026-10-14T18:00:00+00:00'``.
    """
    return datetime.now(timezone.utc).isoformat()


class AntiFridaCheck:
    """Verifica presença de Frida e detecção de Frida pelo app alvo."""

    def __init__(
        self, dm: "DeviceManager", mode: str = "bypass", no_java: bool = False
    ) -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
            mode: ``detect``, ``bypass`` ou ``stealth``.
            no_java: Se True, não tenta carregar hooks Java.
        """
        self.dm = dm
        self.mode = mode
        self.no_java = no_java

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _frida_port(self) -> int:
        """Retorna a porta real do frida-server configurada no host."""
        value = getattr(self.dm, "frida_port", None)
        return int(value) if isinstance(value, int) else 27999

    def _frida_ports(self) -> tuple:
        """Portas a procurar: clássicas + porta stealth real (sem duplicar)."""
        ports = list(FRIDA_PORTS)
        real = self._frida_port()
        if real not in ports:
            ports.append(real)
        return tuple(ports)

    def _script_replacements(self, java_only: bool = False) -> Dict[str, str]:
        """Placeholders de configuração injetados nos scripts Frida."""
        return {
            "__RASPILOT_FRIDA_PORT__": str(self._frida_port()),
            "__RASPILOT_FRIDA_PORT_HEX__": f"{self._frida_port():04X}",
            "__RASPILOT_JAVA_ONLY__": "true" if java_only else "false",
        }

    def _baseline(self) -> Optional[dict]:
        """Retorna o baseline somente se ele for um dict válido."""
        value = getattr(self.dm, "baseline", None)
        return value if isinstance(value, dict) else None

    # ------------------------------------------------------------------
    # Vetores de dispositivo
    # ------------------------------------------------------------------
    def check_frida_processes(self) -> dict:
        """Detecta processos do Frida no dispositivo (``ps -A | grep frida``).

        Procura por ``frida-server``, ``frida-helper`` e ``gum-js-loop``.

        Returns:
            Dict com ``detected``, ``evidence`` (linhas) e ``details``.
        """
        res = self.dm.run_shell("ps -A 2>/dev/null | grep -i frida")
        evidence = [
            line.strip()
            for line in res["stdout"].splitlines()
            if "frida" in line.lower() or "gum-js" in line.lower()
        ]
        if not res["ok"] and res["stderr"]:
            return {
                "detected": False,
                "evidence": [],
                "details": "ps/grep indisponível",
                "error": res["stderr"],
            }
        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Processos Frida ativos: {evidence}" if detected
                else "Nenhum processo Frida detectado via ps"
            ),
        }
        logger.debug("check_frida_processes: detected=%s", detected)
        return result

    def check_frida_ports(self) -> dict:
        """Detecta as portas padrão do frida-server (27042/27043).

        Usa ``netstat``/``ss`` quando disponíveis e faz fallback para a
        leitura de ``/proc/net/tcp`` e ``/proc/net/tcp6``.

        Returns:
            Dict com ``detected``, ``evidence`` e ``details``.
        """
        evidence: List[str] = []
        ports = self._frida_ports()
        hex_ports = [f"{port:04X}" for port in ports]

        def _has_port(line: str) -> bool:
            # Casa ":27042" exato (evita falso positivo em portas efêmeras
            # que contenham o número como substring).
            return any(f":{port}" in line for port in ports)

        # 1) netstat (quando instalado).
        res = self.dm.run_shell("netstat -tlnp 2>/dev/null")
        if res["ok"]:
            for line in res["stdout"].splitlines():
                if _has_port(line):
                    evidence.append(f"netstat: {line.strip()}")

        # 2) ss (substituto moderno do netstat).
        if not evidence:
            res = self.dm.run_shell("ss -tlnp 2>/dev/null")
            if res["ok"]:
                for line in res["stdout"].splitlines():
                    if _has_port(line):
                        evidence.append(f"ss: {line.strip()}")

        # 3) Fallback: /proc/net/tcp(.6) — porta em hex uppercase.
        if not evidence:
            for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
                res = self.dm.run_shell(f"cat {proc_file} 2>/dev/null")
                if not res["ok"]:
                    continue
                for line in res["stdout"].splitlines()[1:]:
                    upper = line.upper()
                    for hex_port in hex_ports:
                        if f":{hex_port}" in upper:
                            evidence.append(f"{proc_file}: {line.strip()}")
                            break

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "ports_checked": list(ports),
            "details": (
                f"Portas Frida abertas: {evidence}" if detected
                else f"Nenhuma porta Frida ({ports}) aberta"
            ),
        }
        logger.debug("check_frida_ports: detected=%s", detected)
        return result

    @staticmethod
    def _enumerate_module_names(sess: object) -> List[str]:
        """Lista os nomes dos módulos carregados no processo da sessão.

        Delega a :func:`script_loader.enumerate_module_names` (compartilhado
        com o Anti-Hooking): ``session.enumerate_modules()`` quando existir
        e, no Frida 17+ (onde esse método não existe), injeta o script de
        enumeração e lê a lista via RPC.

        Args:
            sess: Sessão Frida ativa.

        Returns:
            Lista com os nomes dos módulos (possivelmente vazia).

        Raises:
            Exception: erros do Frida propagam ao chamador.
        """
        return enumerate_module_names(sess)

    def check_frida_libraries(
        self, pid: int, session: Optional[object] = None
    ) -> dict:
        """Enumera módulos do processo alvo procurando por libs do Frida.

        Args:
            pid: PID do processo alvo.
            session: Sessão Frida ativa (opcional). Se ausente, tenta
                anexar via ``DeviceManager``.

        Returns:
            Dict com ``detected``, ``evidence`` (nomes de módulos) e
            ``details``. Em erro de attach/enumeração: ``detected=False``
            + ``error``.
        """
        sess = session
        attached_here = False
        if sess is None:
            try:
                f = self.dm._require_frida()
                device = self.dm._frida_device()
                sess = device.attach(pid)
                attached_here = True
            except Exception as exc:
                return {
                    "detected": False,
                    "evidence": [],
                    "details": "Não foi possível anexar para enumerar módulos",
                    "error": str(exc),
                }

        evidence: List[str] = []
        try:
            for name in self._enumerate_module_names(sess):
                if any(k in name.lower() for k in FRIDA_KEYWORDS):
                    evidence.append(name)
        except Exception as exc:
            return {
                "detected": False,
                "evidence": [],
                "details": "enumerate_modules falhou",
                "error": str(exc),
            }
        finally:
            if attached_here:
                try:
                    sess.detach()
                except Exception:
                    logger.debug("Falha ao detach da sessão temporária", exc_info=True)

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Módulos Frida carregados no processo: {evidence}" if detected
                else "Nenhum módulo Frida carregado no processo alvo"
            ),
        }
        logger.debug("check_frida_libraries: detected=%s", detected)
        return result

    def check_frida_threads(self, pid: int) -> dict:
        """Compara nomes de threads do processo com assinaturas Frida.

        Lê ``/proc/<pid>/task/*/comm`` no dispositivo e procura por
        ``gum-js-loop``, ``gmain``, ``pool-frida`` e ``frida-agent``.

        Returns:
            Dict com ``detected``, ``evidence`` e ``details``.
        """
        runner = getattr(self.dm, "run_shell_root", None)
        res = (
            runner(f"cat /proc/{pid}/task/*/comm 2>/dev/null")
            if callable(runner)
            else self.dm.run_shell(f"cat /proc/{pid}/task/*/comm 2>/dev/null")
        )
        if not res["ok"] and not res["stdout"]:
            return {
                "detected": False,
                "evidence": [],
                "details": f"Não foi possível ler threads do pid {pid}",
                "error": res["stderr"] or f"rc={res['rc']}",
            }

        evidence = [
            line.strip()
            for line in res["stdout"].splitlines()
            if any(t in line.lower() for t in FRIDA_THREAD_NAMES)
        ]
        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Threads Frida no processo: {evidence}" if detected
                else "Nenhuma thread Frida conhecida no processo"
            ),
        }
        logger.debug("check_frida_threads: detected=%s", detected)
        return result

    # ------------------------------------------------------------------
    # Detecção pelo app
    # ------------------------------------------------------------------
    def check_frida_detection_in_app(
        self,
        session: object,
        on_script_loaded: Optional[object] = None,
        window: int = 12,
        pid: Optional[int] = None,
        package_name: Optional[str] = None,
        logcat_mark: Optional[int] = None,
    ) -> dict:
        """Observa se o app alvo executa detecção de Frida em runtime.

        Injeta um script de observação que intercepta (sem bloquear)
        ``File.exists`` em paths Frida, ``Runtime.exec``/``ProcessBuilder``
        com strings 'frida', ``strstr``/``strcmp`` em libc, ``connect``
        nas portas Frida, ``open``/``openat`` e ``access``/``stat`` de
        paths Frida, coletando as chamadas pela janela de observação.
        Também carrega o ``kill_trace.js`` e correlaciona o logcat para
        distinguir reação do RASP de crash causado pela instrumentação.

        Args:
            session: Sessão Frida ativa sobre o app alvo.
            on_script_loaded: Callback chamado logo após ``script.load()`` —
                usado pelo pipeline para ``resume`` de spawn suspenso, de
                modo que os hooks estejam ativos antes do código do app.
            window: Janela de observação em segundos.
            pid: PID do processo alvo (para monitorar se o app morre).
            package_name: Package name do alvo (filtro do logcat).
            logcat_mark: Marcador de logcat tirado antes do spawn.

        Returns:
            Dict com ``detection_methods_found``, ``vulnerable``,
            ``app_alive_at_end``, ``observation_status``, ``death_cause``,
            ``death_classification``, ``baseline`` e ``logcat``.
        """
        found: List[str] = []
        script = None
        java_script = None
        kill_script = None
        java_load_error: Optional[str] = None
        stealth_loaded: List[tuple] = []
        resumed = False
        died_after: Optional[int] = None
        try:

            def on_message(message, data):  # noqa: ANN001 - assinatura frida
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "frida-detection-error":
                        # Diagnóstico do próprio script (hook não instalou) —
                        # não é uma detecção pelo app.
                        logger.warning(
                            "Hook de observação frida não instalou: %s",
                            payload.get("message"),
                        )
                        return
                    if payload.get("type") == "app-kill":
                        entry = "app_kill: " + payload.get("message", "")
                        if entry not in found:
                            found.append(entry)
                            logger.info("App encerrou via kill trace -> %s", entry)
                        return
                    method = payload.get("method", "?")
                    detail = payload.get("detail", "")
                    entry = f"{method}: {detail}"
                    if entry not in found:
                        found.append(entry)
                        logger.info("App executou detecção de Frida -> %s", entry)
                elif message.get("type") == "error":
                    logger.debug("Erro no script de detecção: %s", message.get("description"))

            if self.mode == "stealth":
                stealth_loaded = load_stealth(
                    session,
                    on_message=on_message,
                    replacements=self._script_replacements(),
                    include_proc_filter=True,
                )
            # Fase 1 (antes do resume): hooks nativos, sem bridge Java.
            # Rápido o suficiente para não estourar o start timeout.
            script = load_script(
                session,
                DETECTION_SCRIPT,
                on_message=on_message,
                name="raspilot-detect-native",
                replacements=self._script_replacements(java_only=False),
                with_java_bridge=False,
                load_timeout=5.0,
            )
            if on_script_loaded is not None:
                on_script_loaded()
                resumed = True
            # Fase 2 (após o resume): hooks Java. A bridge carrega com o
            # app rodando, sem risco de start timeout.
            if self.no_java:
                java_load_error = None
            else:
                try:
                    java_script = load_script(
                        session,
                        DETECTION_SCRIPT,
                        on_message=on_message,
                        name="raspilot-detect-java",
                        replacements=self._script_replacements(java_only=True),
                        with_java_bridge=True,
                        load_timeout=5.0,
                    )
                except Exception as exc:
                    java_load_error = str(exc)
                    logger.warning(
                        "Hooks Java de observação não carregaram: %s", exc
                    )
                    # Sessão degradada: detach evita travar unload/detach futuros.
                    safe_detach(session)
            if java_load_error is None and not self.no_java:
                # O kill_trace é diagnóstico e usa Java: carregado por último.
                try:
                    kill_script = load_script_file(
                        session, KILL_TRACE_SCRIPT, on_message=on_message,
                        name="raspilot-kill-trace", load_timeout=3.0,
                    )
                except Exception:
                    logger.debug("kill_trace.js indisponível no anti-frida", exc_info=True)
            for elapsed in range(max(1, int(window))):
                time.sleep(1)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante a observação (~%ss)", pid, died_after
                    )
                    break
        except Exception as exc:
            logger.warning("Falha ao observar detecção de Frida no app", exc_info=True)
            logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
            baseline = self._baseline()
            failure = classify_failure(logcat, baseline)
            death_cause = None
            app_alive: Optional[bool] = None
            if pid is not None:
                try:
                    app_alive = self.dm.is_app_alive(pid)
                except Exception:
                    app_alive = None
            if app_alive is False:
                try:
                    death_cause = self.dm.capture_death_cause(
                        pid=pid, package=package_name
                    )
                except Exception:
                    logger.debug("Falha ao capturar morte na falha de script", exc_info=True)

            found: List[str] = []
            if failure.get("is_rasp"):
                found.extend(
                    format_detection_signals(
                        logcat, ("root", "frida", "debug", "integrity"), limit=4
                    )
                )
                for item in logcat.get("security_signals", []) or []:
                    if isinstance(item, dict) and item.get("category") == "frida_agent_crash":
                        found.append(f"frida_agent_crash: {item.get('line', '')}")
                        break
                found.append(
                    "app_terminated: sessão encerrada durante o carregamento "
                    "(reação do RASP)"
                )
                if death_cause:
                    found.append(f"app_kill_external: {death_cause.get('summary', '?')}")
                return {
                    "detection_methods_found": found,
                    "vulnerable": False,
                    "app_alive_at_end": app_alive,
                    "observed": True,
                    "observation_status": "rasp_reaction",
                    "death_cause": death_cause,
                    "death_classification": "rasp_reaction",
                    "baseline": baseline,
                    "logcat": logcat,
                    "logcat_evidence": format_evidence(logcat),
                    "details": (
                        "Sessão encerrada durante o carregamento com evidência de "
                        "segurança no logcat — reação do RASP"
                    ),
                }

            kind = str(failure.get("kind", "unknown"))
            status = "error" if kind in ("unknown", "unknown_death") else kind
            if kind == "start_timeout":
                error = (
                    "app morto por ActivityManager start timeout enquanto o script "
                    "era carregado (instrumentação); reduza o trabalho antes do resume"
                )
            elif kind == "baseline_death":
                error = "app encerrou no baseline sem instrumentação; observação inconclusiva"
            elif kind == "instrumentation_crash":
                error = (
                    "app encerrou por crash/ANR sem evidência de segurança no logcat "
                    "(possível crash da instrumentação)"
                )
            else:
                error = (
                    f"sessão encerrada antes da instalação dos hooks: {exc}"
                )
            return {
                "detection_methods_found": [],
                "vulnerable": None,
                "app_alive_at_end": app_alive,
                "observed": False,
                "observation_status": status,
                "death_cause": death_cause,
                "death_classification": kind,
                "baseline": baseline,
                "logcat": logcat,
                "logcat_evidence": format_evidence(logcat),
                "session_unsafe": True,
                "error": error,
            }
        finally:
            safe_unload(script)
            safe_unload(java_script)
            safe_unload(kill_script)
            unload_stealth(stealth_loaded)
            if not resumed and on_script_loaded is not None:
                # Garante que um spawn suspenso nunca fique travado.
                try:
                    on_script_loaded()
                except Exception:
                    logger.debug("Falha no resume de emergência", exc_info=True)

        logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
        baseline = self._baseline()
        baseline_died = bool(
            baseline and baseline.get("available") and baseline.get("alive_at_end") is False
        )
        # Rechecagem: o app pode ter morrido depois da janela (ex: durante
        # o carregamento Java que estourou timeout).
        if died_after is None and pid is not None:
            try:
                if not self.dm.is_app_alive(pid):
                    died_after = max(1, int(window))
                    logger.info("Processo %s morreu após a janela de observação", pid)
            except Exception:
                logger.debug("Falha na rechecagem de vida", exc_info=True)
        app_alive = died_after is None
        death_cause: Optional[dict] = None
        death_classification: Optional[str] = None
        observation_status = "ok"
        error: Optional[str] = None

        # Evidências de segurança vistas apenas no logcat (sem hooks).
        # Uma linha por categoria, para não inflar o resultado com um
        # stack trace inteiro do agente.
        for entry in format_detection_signals(
            logcat, ("root", "frida", "debug", "integrity"), limit=4
        ):
            if entry not in found:
                found.append(entry)
        if logcat.get("agent_terminated"):
            # O agente Frida foi derrubado dentro do processo (stack em
            # runtime.cc). Isso é falha da instrumentação, não prova de
            # que o app detectou o Frida: a observação fica inconclusiva.
            agent_line = None
            for item in logcat.get("security_signals", []) or []:
                if isinstance(item, dict) and item.get("category") == "frida_agent_crash":
                    agent_line = f"frida_agent_crash: {item.get('line', '')}"
                    break
            if app_alive:
                observation_status = "error"
                error = (
                    "o agente de instrumentação terminou dentro do processo "
                    "alvo; a observação é inconclusiva"
                )
                if agent_line:
                    found.append(agent_line)
            elif agent_line:
                found.append(agent_line)

        if app_alive and self.no_java and not found:
            observation_status = "native_only"
            error = (
                "hooks Java desativados (--no-java); a observação nativa não "
                "encontrou detecção de Frida"
            )
        elif app_alive and java_load_error and not found:
            observation_status = "error"
            error = (
                "hooks Java de observação não carregaram e nenhuma detecção "
                f"foi observada: {java_load_error}"
            )

        if not app_alive:
            try:
                death_cause = self.dm.capture_death_cause(
                    pid=pid, package=package_name
                )
            except Exception:
                logger.debug("Falha ao capturar causa da morte", exc_info=True)
            logcat_death = logcat.get("death") or {}
            logcat_rasp = any(
                category in (logcat.get("categories") or {})
                for category in HIGH_CONFIDENCE_CATEGORIES
            )
            kill_traced = any(item.startswith("app_kill") for item in found)

            if kill_traced:
                death_classification = "rasp_kill"
            elif baseline_died:
                # O app já morre sozinho sem instrumentação. Não dá para
                # isolar uma reação ao Frida — o resultado é inconclusivo.
                death_classification = "baseline_death"
                observation_status = "baseline_death"
                error = (
                    "app encerrou no baseline sem instrumentação; não é possível "
                    "isolar uma reação ao Frida"
                )
            elif logcat_rasp:
                death_classification = "rasp_reaction"
            elif logcat.get("available") and logcat_death.get("kind") in ("crash", "anr"):
                # Crash sem evidência de segurança: provavelmente da própria
                # instrumentação. Não pode virar "proteção OK" nem "vulnerável".
                death_classification = "instrumentation_crash"
                observation_status = "crashed"
                error = (
                    "app encerrou por crash/ANR sem evidência de segurança no logcat "
                    "(possível crash da instrumentação)"
                )
            else:
                # Sem logcat/baseline disponíveis: mantém o comportamento
                # conservador de tratar a morte como possível reação.
                death_classification = "unclassified_death"

            if death_classification in ("rasp_kill", "rasp_reaction", "unclassified_death"):
                found.append(
                    f"app_terminated: processo encerrou ~{died_after}s após resume "
                    f"({death_classification})"
                )
                if death_cause:
                    summary = death_cause.get("summary", "?")
                    entry = f"app_kill_external: {summary}"
                    if entry not in found:
                        found.append(entry)

        vulnerable = (
            None
            if observation_status in ("crashed", "baseline_death", "error", "native_only")
            else (not found)
        )
        result = {
            "detection_methods_found": found,
            "vulnerable": vulnerable,
            "app_alive_at_end": app_alive,
            "observed": True,
            "observation_status": observation_status,
            "death_cause": death_cause,
            "death_classification": death_classification,
            "baseline": baseline,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "java_load_error": java_load_error,
            "java_skipped": bool(self.no_java),
            "stealth_used": bool(stealth_loaded),
            "session_unsafe": bool(java_load_error),
            "details": (
                f"App detectou Frida via: {'; '.join(found)}" if found
                else "App não executou nenhuma detecção de Frida observada"
            ),
        }
        if error:
            result["error"] = error
        logger.info(
            "check_frida_detection_in_app: vulnerable=%s methods=%s death=%s",
            vulnerable, found, death_classification,
        )
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self,
        session: object,
        pid: int,
        on_script_loaded: Optional[object] = None,
        window: int = 12,
        package_name: Optional[str] = None,
        logcat_mark: Optional[int] = None,
        app_detection: Optional[dict] = None,
    ) -> dict:
        """Consolida presença de Frida e capacidade de detecção do app.

        ``vulnerable=True`` significa que o app **não** detectou/bloqueou
        o Frida (falha de RASP). ``vulnerable=False`` significa que o app
        possui detecção ativa (evidência registrada). ``vulnerable=None``
        com ``error`` significa observação inconclusiva (ex: crash da
        instrumentação), que o reporter mapeia para ``ERROR``.

        Args:
            session: Sessão Frida ativa sobre o app alvo.
            pid: PID do processo alvo.
            on_script_loaded: Callback de resume pós-load do script de
                observação (ver ``check_frida_detection_in_app``).
            window: Janela de observação em segundos.
            package_name: Package name do alvo (para logcat).
            logcat_mark: Marcador de logcat tirado antes do spawn.

        Returns:
            Dict com ``vulnerable`` (bool|None), ``frida_present``,
            ``checks`` (por vetor), ``app_detection`` (dict),
            ``baseline`` e ``timestamp`` (ISO8601).
        """
        # Observação primeiro: o app está suspenso desde o spawn. Instalar
        # os hooks nativos e retomar o quanto antes evita o start timeout
        # do ActivityManager. Os vetores de dispositivo rodam depois.
        if app_detection is None:
            app_detection = self.check_frida_detection_in_app(
                session,
                on_script_loaded=on_script_loaded,
                window=window,
                pid=pid,
                package_name=package_name,
                logcat_mark=logcat_mark,
            )
        checks = {
            "frida_processes": self.check_frida_processes(),
            "frida_ports": self.check_frida_ports(),
            "frida_threads": self.check_frida_threads(pid),
        }
        if app_detection.get("session_unsafe"):
            checks["frida_libraries"] = {
                "detected": False,
                "evidence": [],
                "details": "enumeração pulada: sessão Frida degradada",
                "skipped": True,
            }
        else:
            checks["frida_libraries"] = self.check_frida_libraries(pid, session=session)

        frida_present = any(res.get("detected") for res in checks.values())
        vulnerable = app_detection.get("vulnerable")

        result = {
            "vulnerable": vulnerable,
            "frida_present": frida_present,
            # O RASPilot sobe o frida-server por definição: presença de
            # Frida aqui é esperada (injetada pela ferramenta), não uma
            # descoberta sobre o ambiente.
            "frida_injected_by_tool": frida_present,
            "frida_pid": pid,
            "checks": checks,
            "app_detection": app_detection,
            "baseline": app_detection.get("baseline"),
            "timestamp": _now_iso(),
        }
        if app_detection.get("error"):
            result["error"] = str(app_detection["error"])
        logger.info(
            "Anti-Frida: vulnerable=%s frida_present=%s status=%s",
            vulnerable, frida_present, app_detection.get("observation_status"),
        )
        return result
