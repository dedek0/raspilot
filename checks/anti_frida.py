"""RASPilot — Verificação Anti-Frida.

Verifica (a) a presença do Frida no dispositivo (processos, portas,
bibliotecas e threads do frida-server/gadget) e (b) se o app alvo
implementa mecanismos de detecção de Frida em runtime. O veredito
``vulnerable`` indica se o app **falhou** em bloquear o Frida.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from script_loader import load_script

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_frida")

# Portas padrão do frida-server (27042 principal, 27043 session).
FRIDA_PORTS = (27042, 27043)

# Portas em hex como aparecem em /proc/net/tcp (uppercase, big-endian).
FRIDA_PORTS_HEX = ("69A2", "69A3")

# Nomes de threads típicas do Frida/GumJS.
FRIDA_THREAD_NAMES = ("gum-js-loop", "gmain", "pool-frida", "frida-agent")

# Strings que um app anti-frida costuma procurar.
FRIDA_KEYWORDS = ("frida", "gum-js-loop", "gadget", "libfrida")

# Script de OBSERVAÇÃO (não bypass): registra chamadas de detecção do app
# (File.exists em paths Frida, Runtime.exec com 'frida', strstr/strcmp em
# libc procurando 'frida') e as envia ao host via send().
DETECTION_SCRIPT = """
'use strict';

var detections = [];

function reportDetection(method, detail) {
    detections.push(method + ': ' + detail);
    send({ type: 'frida-detection', method: method, detail: detail });
}

function looksLikeFrida(str) {
    try {
        if (str === null || str === undefined) { return false; }
        return ('' + str).toLowerCase().indexOf('frida') !== -1;
    } catch (e) { return false; }
}

// Native: strstr/strcmp em libc buscando 'frida' (técnica clássica).
['strstr', 'strcmp'].forEach(function (name) {
    try {
        var addr = Module.findExportByName('libc.so', name);
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
    } catch (e) { /* módulo indisponível */ }
});

// Native: connect() para portas Frida (27042/27043) — anti-frida por
// "port scan" local, técnica comum que não usa strings 'frida'.
try {
    var connectPtr = Module.findExportByName('libc.so', 'connect');
    if (connectPtr !== null) {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                try {
                    var sa = args[1];
                    var family = sa.readU16();
                    if (family === 2) { // AF_INET
                        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        if (port === 27042 || port === 27043) {
                            reportDetection('native_connect', 'porta ' + port);
                        }
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    }
} catch (e) { /* libc indisponível */ }

// Native: open/openat de paths contendo 'frida'.
['open', 'openat', 'openat64'].forEach(function (name) {
    try {
        var addr = Module.findExportByName('libc.so', name);
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
    } catch (e) { /* módulo indisponível */ }
});

['access', 'stat', 'stat64', 'lstat', 'faccessat', 'faccessat2'].forEach(function (name) {
    try {
        var addr = Module.findExportByName('libc.so', name);
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
    } catch (e) { /* módulo indisponível */ }
});

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

if (typeof Java !== 'undefined' && Java.available) {
    Java.perform(installJavaHooks);
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

    def __init__(self, dm: "DeviceManager") -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
        """
        self.dm = dm

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

        # 1) netstat (quando instalado).
        res = self.dm.run_shell("netstat -tlnp 2>/dev/null")
        if res["ok"]:
            for line in res["stdout"].splitlines():
                if any(str(p) in line for p in FRIDA_PORTS):
                    evidence.append(f"netstat: {line.strip()}")

        # 2) ss (substituto moderno do netstat).
        if not evidence:
            res = self.dm.run_shell("ss -tlnp 2>/dev/null")
            if res["ok"]:
                for line in res["stdout"].splitlines():
                    if any(str(p) in line for p in FRIDA_PORTS):
                        evidence.append(f"ss: {line.strip()}")

        # 3) Fallback: /proc/net/tcp(.6) — porta em hex uppercase.
        if not evidence:
            for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
                res = self.dm.run_shell(f"cat {proc_file} 2>/dev/null")
                if not res["ok"]:
                    continue
                for line in res["stdout"].splitlines()[1:]:
                    upper = line.upper()
                    for hex_port in FRIDA_PORTS_HEX:
                        if f":{hex_port}" in upper:
                            evidence.append(f"{proc_file}: {line.strip()}")

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Portas Frida abertas: {evidence}" if detected
                else f"Nenhuma porta Frida ({FRIDA_PORTS}) aberta"
            ),
        }
        logger.debug("check_frida_ports: detected=%s", detected)
        return result

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
            ``details``. Em erro de attach: ``detected=False`` + ``error``.
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
            for mod in sess.enumerate_modules():
                name = mod.name.lower()
                if any(k in name for k in FRIDA_KEYWORDS):
                    evidence.append(mod.name)
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
        res = self.dm.run_shell(f"cat /proc/{pid}/task/*/comm 2>/dev/null")
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
    ) -> dict:
        """Observa se o app alvo executa detecção de Frida em runtime.

        Injeta um script de observação que intercepta (sem bloquear)
        ``File.exists`` em paths Frida, ``Runtime.exec``/``ProcessBuilder``
        com strings 'frida', ``strstr``/``strcmp`` em libc, ``connect``
        nas portas Frida, ``open``/``openat`` e ``access``/``stat`` de
        paths Frida, coletando as chamadas pela janela de observação.

        Durante a janela o processo é monitorado: se o app se encerrar
        (reação típica de RASP ao detectar ameaça), isso é registrado
        como evidência e o veredito passa a ser ``vulnerable=False``.

        Args:
            session: Sessão Frida ativa sobre o app alvo.
            on_script_loaded: Callback chamado logo após ``script.load()`` —
                usado pelo pipeline para ``resume`` de spawn suspenso, de
                modo que os hooks estejam ativos antes do código do app.
            window: Janela de observação em segundos.
            pid: PID do processo alvo (para monitorar se o app morre).

        Returns:
            Dict com ``detection_methods_found`` (lista legível),
            ``vulnerable`` (True se o app **não** detectou o Frida) e
            ``app_alive_at_end`` (bool).
        """
        found: List[str] = []
        script = None
        resumed = False
        died_after: Optional[int] = None
        try:

            def on_message(message, data):  # noqa: ANN001 - assinatura frida
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    method = payload.get("method", "?")
                    detail = payload.get("detail", "")
                    entry = f"{method}: {detail}"
                    if entry not in found:
                        found.append(entry)
                        logger.info("App executou detecção de Frida -> %s", entry)
                elif message.get("type") == "error":
                    logger.debug("Erro no script de detecção: %s", message.get("description"))

            script = load_script(
                session, DETECTION_SCRIPT, on_message=on_message, name="raspilot-detect"
            )
            if on_script_loaded is not None:
                on_script_loaded()
                resumed = True
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
            return {
                "detection_methods_found": [],
                "vulnerable": True,
                "app_alive_at_end": True,
                "error": str(exc),
            }
        finally:
            if script is not None:
                try:
                    script.unload()
                except Exception:
                    logger.debug("Falha ao unload do script de detecção", exc_info=True)
            if not resumed and on_script_loaded is not None:
                # Garante que um spawn suspenso nunca fique travado.
                try:
                    on_script_loaded()
                except Exception:
                    logger.debug("Falha no resume de emergência", exc_info=True)
        app_alive = died_after is None
        if not app_alive:
            found.append(f"app_terminated: processo encerrou ~{died_after}s após resume")
        vulnerable = not found  # app não detectou = falha de RASP
        result = {
            "detection_methods_found": found,
            "vulnerable": vulnerable,
            "app_alive_at_end": app_alive,
            "details": (
                f"App detectou Frida via: {'; '.join(found)}" if found
                else "App não executou nenhuma detecção de Frida observada"
            ),
        }
        logger.info(
            "check_frida_detection_in_app: vulnerable=%s methods=%s", vulnerable, found
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
    ) -> dict:
        """Consolida presença de Frida e capacidade de detecção do app.

        ``vulnerable=True`` significa que o app **não** detectou/bloqueou
        o Frida (falha de RASP). ``vulnerable=False`` significa que o app
        possui detecção ativa (evidência registrada).

        Args:
            session: Sessão Frida ativa sobre o app alvo.
            pid: PID do processo alvo.
            on_script_loaded: Callback de resume pós-load do script de
                observação (ver ``check_frida_detection_in_app``).
            window: Janela de observação em segundos.

        Returns:
            Dict com ``vulnerable`` (bool), ``frida_present`` (bool),
            ``checks`` (por vetor), ``app_detection`` (dict) e
            ``timestamp`` (ISO8601).
        """
        checks = {
            "frida_processes": self.check_frida_processes(),
            "frida_ports": self.check_frida_ports(),
            "frida_libraries": self.check_frida_libraries(pid, session=session),
            "frida_threads": self.check_frida_threads(pid),
        }
        app_detection = self.check_frida_detection_in_app(
            session, on_script_loaded=on_script_loaded, window=window, pid=pid
        )

        frida_present = any(res.get("detected") for res in checks.values())
        vulnerable = bool(app_detection.get("vulnerable", True))

        result = {
            "vulnerable": vulnerable,
            "frida_present": frida_present,
            "frida_pid": pid,
            "checks": checks,
            "app_detection": app_detection,
            "timestamp": _now_iso(),
        }
        logger.info(
            "Anti-Frida: vulnerable=%s frida_present=%s", vulnerable, frida_present
        )
        return result
