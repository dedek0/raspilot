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

from checks.static import vector_view
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

# Intervalo entre as consultas feitas durante a janela de observacao.
# Exposto como constante para que os testes nao dependam de esperar
# tempo real.
OBSERVATION_POLL_INTERVAL = 1.0


# Portas padrão do frida-server (27042 principal, 27043 session).
FRIDA_PORTS = (27042, 27043)

# Portas em hex como aparecem em /proc/net/tcp (uppercase, big-endian).
FRIDA_PORTS_HEX = ("69A2", "69A3")

# Rastreio de quem mata o processo (mesmo script do anti-hooking/SSL).
KILL_TRACE_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "kill_trace.js"
)

# Nomes de threads típicas do Frida/GumJS.
FRIDA_THREAD_NAMES = ("gum-js-loop", "pool-frida", "frida-agent")

# "gmain" é o loop principal do GLib: qualquer app que use uma
# biblioteca GLib tem uma thread com esse nome. Só vale como
# corroboração quando há outra thread de assinatura Frida no processo.
FRIDA_THREAD_WEAK_NAMES = ("gmain",)

# Strings que um app anti-frida costuma procurar.
FRIDA_KEYWORDS = ("frida", "gum-js-loop", "gadget", "libfrida")


def _contains_token(text: str, term: str) -> bool:
    """Indica se ``term`` aparece em ``text`` como token isolado.

    O casamento é por fronteira: o caractere anterior e o posterior
    precisam ser não alfanuméricos. Sem isso, o nome do pacote de um app
    que contém o termo (ex: "fridaplayer") casaria e viraria "detecção"
    do próprio app.

    Args:
        text: Texto já em minúsculas.
        term: Termo procurado, em minúsculas.

    Returns:
        True se o termo aparecer isolado no texto.
    """
    if not term:
        return False
    start = 0
    while True:
        idx = text.find(term, start)
        if idx == -1:
            return False
        before = text[idx - 1] if idx > 0 else ""
        after = text[idx + len(term)] if idx + len(term) < len(text) else ""
        if not (before.isalnum() or after.isalnum()):
            return True
        start = idx + 1

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

// Artefatos de instrumentação reconhecidos por nome.
//
// A comparação é feita por TOKEN (termo isolado por caracteres não
// alfanuméricos), e não por substring solta: o nome do pacote de um app
// pode conter o termo sem que o app esteja detectando o Frida — sem a
// fronteira, todo acesso do app a um arquivo próprio viraria
// "detecção".
var FRIDA_TOKENS = [
    'frida', 'libfrida', 'frida-agent', 'fridaagent', 'frida-gadget',
    'fridagadget', 'frida-server', 'gum-js', 'gum-js-loop', 'linjector',
    're.frida.server'
];

function isTokenBoundary(ch) {
    return ch === '' || !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'));
}

function containsToken(lower, term) {
    var idx = lower.indexOf(term);
    while (idx !== -1) {
        var before = idx === 0 ? '' : lower.charAt(idx - 1);
        var after = lower.charAt(idx + term.length);
        if (isTokenBoundary(before) && isTokenBoundary(after)) { return true; }
        idx = lower.indexOf(term, idx + 1);
    }
    return false;
}

function looksLikeFrida(str) {
    try {
        if (str === null || str === undefined) { return false; }
        var lower = ('' + str).toLowerCase();
        for (var i = 0; i < FRIDA_TOKENS.length; i++) {
            if (containsToken(lower, FRIDA_TOKENS[i])) { return true; }
        }
        return false;
    } catch (e) { return false; }
}

// Um byte é fronteira de token quando não é alfanumérico.
function isTokenByte(c) {
    if (c === 0) { return true; }
    var lower = (c >= 65 && c <= 90) ? (c + 32) : c;
    return !((lower >= 97 && lower <= 122) || (lower >= 48 && lower <= 57));
}

// Procura os tokens de instrumentação direto nos bytes do buffer.
//
// Montar a string caractere a caractere trava o app em função muito
// chamada: o custo quadrático da concatenação é o problema, e é
// exatamente o que o gancho de memcmp evita.
function bytesContainFrida(buffer) {
    if (buffer === null || buffer === undefined) { return false; }
    var bytes = new Uint8Array(buffer);
    var lower = [];
    for (var i = 0; i < bytes.length; i++) {
        var c = bytes[i];
        lower[i] = (c >= 65 && c <= 90) ? (c + 32) : c;
    }
    for (var k = 0; k < FRIDA_TOKENS.length; k++) {
        var needle = FRIDA_TOKENS[k];
        var limit = lower.length - needle.length;
        for (var p = 0; p <= limit; p++) {
            var match = true;
            for (var j = 0; j < needle.length; j++) {
                if (lower[p + j] !== needle.charCodeAt(j)) { match = false; break; }
            }
            if (!match) { continue; }
            var before = p === 0 ? 0 : lower[p - 1];
            var after = (p + needle.length < lower.length) ? lower[p + needle.length] : 0;
            if (isTokenByte(before) && isTokenByte(after)) { return true; }
        }
    }
    return false;
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
                    var a = args[0].readCString();
                    var b = args[1].readCString();
                    if (name === 'strstr') {
                        // (haystack, needle): o termo procurado é o
                        // segundo argumento.
                        if (looksLikeFrida(b)) {
                            reportDetection('native_' + name, 'needle=' + b);
                        }
                    } else if (looksLikeFrida(a) || looksLikeFrida(b)) {
                        // O lado que contém o termo é o needle real.
                        var hit = looksLikeFrida(a) ? a : b;
                        reportDetection('native_' + name, 'needle=' + hit);
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
                    // faccessat/faccessat2 recebem (dirfd, path, ...): o
                    // caminho é o segundo argumento, não o primeiro.
                    var path = args[name === 'faccessat' || name === 'faccessat2' ? 1 : 0].readCString();
                    if (looksLikeFrida(path)) {
                        reportDetection('native_' + name, path);
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});

// Native: memcmp — o app compara blocos de memória procurando o nome
// de um artefato de instrumentação. É uma técnica comum justamente
// por não deixar string literal no binário.
//
// O limite de tamanho mantém o custo baixo: comparação de blocos
// inteiros é o caso comum, e não é neles que mora o nome de um
// artefato.
try {
    var memcmpAddr = raspilotFindExport('libc.so', 'memcmp');
    if (memcmpAddr !== null) {
        Interceptor.attach(memcmpAddr, {
            onEnter: function (args) {
                try {
                    var n = args[2].toInt32();
                    if (n > 0 && n <= 64) {
                        if (bytesContainFrida(args[0].readByteArray(n)) ||
                                bytesContainFrida(args[1].readByteArray(n))) {
                            reportDetection('native_memcmp',
                                'buffer contém nome de artefato de instrumentação');
                        }
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    }
} catch (e) { reportHookError('instalação de memcmp falhou: ' + e); }
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
            "__RASPILOT_PACKAGE_NAME__": getattr(self.dm, "last_spawn_package", None) or "",
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
                lowered = name.lower()
                if any(_contains_token(lowered, k) for k in FRIDA_KEYWORDS):
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
        ``gum-js-loop``, ``pool-frida`` e ``frida-agent``.

        ``gmain`` é o loop do GLib e aparece em qualquer app que use
        uma biblioteca GLib — sozinho, ele não é evidência de nada, e
        por isso só corrobora quando outra thread de assinatura Frida
        está presente.

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

        names = [
            line.strip().lower()
            for line in res["stdout"].splitlines()
            if line.strip()
        ]
        specific = [n for n in names if any(t in n for t in FRIDA_THREAD_NAMES)]
        weak = [n for n in names if any(t in n for t in FRIDA_THREAD_WEAK_NAMES)]
        detected = bool(specific)
        evidence = list(specific)
        if detected:
            evidence.extend(weak)
        if detected:
            details = f"Threads Frida no processo: {evidence}"
        elif weak:
            details = (
                "Nenhuma thread Frida conhecida no processo "
                f"(thread genérica: {weak})"
            )
        else:
            details = "Nenhuma thread Frida conhecida no processo"
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": details,
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
                time.sleep(OBSERVATION_POLL_INTERVAL)
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
        baseline_healthy = bool(
            baseline and baseline.get("available") and baseline.get("alive_at_end") is True
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
                if baseline_healthy and logcat.get("crash_origin") != "instrumentation":
                    # O app sobreviveu sem instrumentação e morreu com ela:
                    # a instrumentação foi o gatilho. O app bloqueou a
                    # auditoria — que é o que uma proteção eficaz faz.
                    death_classification = "rasp_reaction"
                else:
                    # Sem baseline que prove que o app é estável sozinho,
                    # a causa da morte não pode ser atribuída.
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
    # Bypass (evasão ativa)
    # ------------------------------------------------------------------
    def attempt_bypass(self, package_name: str, window: int = 12) -> dict:
        """Tenta sobreviver à instrumentação com a evasão anti-Frida.

        A fase de observação mede se o app detecta o Frida. Esta fase
        responde outra pergunta: com os artefatos nativos ocultos antes
        do resume, o app continua vivo e deixa de reagir?

        A evasão é carregada **antes** do resume (``load_stealth``), para
        que os hooks de ``/proc``, strings e auto-destruição estejam
        ativos antes do código do app. O bypass não carrega o script de
        observação de detecção: ele mede a reação do app (morte/logcat e
        ações neutralizadas), não a mera chamada de comparação.

        Args:
            package_name: Package name do alvo.
            window: Janela de observação em segundos.

        Returns:
            Dict com ``success`` (bool|None), ``method``, ``app_alive_at_end``,
            ``neutralized``, ``bypass_logs``, ``detection_signals``,
            ``error`` e ``timestamp``.
        """
        if self.mode == "detect":
            return {
                "success": None,
                "method": "stealth",
                "skipped_reason": "modo detect: bypass anti-Frida não executado",
                "app_alive_at_end": None,
                "neutralized": [],
                "bypass_logs": [],
                "detection_signals": [],
                "timestamp": _now_iso(),
            }
        if not package_name:
            return {
                "success": None,
                "method": "stealth",
                "skipped_reason": "package name ausente",
                "app_alive_at_end": None,
                "neutralized": [],
                "bypass_logs": [],
                "detection_signals": [],
                "timestamp": _now_iso(),
            }

        neutralized: List[str] = []
        bypass_logs: List[str] = []
        detection_signals: List[str] = []
        script_errors: List[str] = []
        stealth_loaded: List[tuple] = []
        session = None
        pid: Optional[int] = None
        resumed = False
        error: Optional[str] = None
        kill_script = None
        logcat_mark = None
        try:
            marker = getattr(self.dm, "logcat_mark", None)
            if callable(marker):
                logcat_mark = marker()

            def on_message(message, data):  # noqa: ANN001 - assinatura frida
                if message.get("type") != "send":
                    return
                payload = message.get("payload", {})
                ptype = payload.get("type")
                text = str(payload.get("message") or payload.get("detail") or "")
                if ptype == "raspilot-bypass" and text:
                    if text not in bypass_logs:
                        bypass_logs.append(text)
                elif ptype == "raspilot-neutralized" and text:
                    if text not in neutralized:
                        neutralized.append(text)
                elif ptype == "frida-detection" and text:
                    if text not in detection_signals:
                        detection_signals.append(text)
                elif ptype in ("frida-detection-error", "raspilot-script-error"):
                    if text:
                        script_errors.append(text)

            session = self.dm.spawn_app(package_name, resume=False)
            pid = getattr(self.dm, "last_spawn_pid", None)
            if pid is None:
                pid = self.dm.get_app_pid(package_name)

            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=self._script_replacements(),
                include_proc_filter=True,
                load_native_frida=True,
            )
            # Um único script de observação de reação: se o app tentar se
            # matar, o kill_trace registra; a evasão deve impedir a morte.
            self.dm.resume_app()
            resumed = True
            if not self.no_java:
                try:
                    kill_script = load_script_file(
                        session,
                        KILL_TRACE_SCRIPT,
                        on_message=on_message,
                        name="raspilot-frida-bypass-killtrace",
                        load_timeout=3.0,
                    )
                except Exception:
                    kill_script = None
                    logger.debug("kill_trace indisponível no bypass anti-Frida", exc_info=True)
            for _ in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    break
            app_alive = None
            if pid is not None:
                try:
                    app_alive = bool(self.dm.is_app_alive(pid))
                except Exception:
                    app_alive = None
        except Exception as exc:
            error = str(exc)
            logger.warning("Bypass anti-Frida falhou", exc_info=True)
            app_alive = None
            kill_script = None
        finally:
            if not resumed:
                try:
                    self.dm.resume_app()
                except Exception:
                    logger.debug("Falha ao retomar app após bypass", exc_info=True)
            try:
                if kill_script is not None:
                    safe_unload(kill_script)
            except Exception:
                logger.debug("Falha ao descarregar kill_trace", exc_info=True)
            unload_stealth(stealth_loaded)
            safe_detach(session)

        logcat = {}
        if logcat_mark is not None:
            try:
                logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
            except Exception:
                logger.debug("Falha ao correlacionar logcat no bypass", exc_info=True)

        logcat_rasp = bool(
            (logcat.get("failure") or {}).get("is_rasp")
            if isinstance(logcat.get("failure"), dict)
            else logcat.get("is_rasp")
        )
        instrumentation_issue = bool(
            logcat.get("instrumentation_kill")
            or logcat.get("agent_terminated")
        )
        if error:
            success = None
            reason = f"bypass anti-Frida: {error}"
        elif app_alive is False:
            success = False
            reason = "app encerrou durante o bypass: a proteção resistiu à evasão"
        elif instrumentation_issue:
            success = None
            reason = "a instrumentação caiu durante o bypass; resultado inconclusivo"
        elif logcat_rasp:
            success = False
            reason = "logcat registrou reação de RASP durante o bypass"
        elif app_alive is True:
            success = True
            reason = (
                "app sobreviveu à evasão"
                + (" com ações neutralizadas" if neutralized else "")
            )
        else:
            success = None
            reason = "não foi possível confirmar o estado do app"

        result = {
            "success": success,
            "method": "stealth",
            "app_alive_at_end": app_alive,
            "neutralized": neutralized,
            "bypass_logs": bypass_logs,
            "detection_signals": detection_signals,
            "script_errors": script_errors,
            "logcat": logcat,
            "details": reason,
            "timestamp": _now_iso(),
        }
        if success is None:
            result["skipped_reason"] = reason
        if error:
            result["error"] = error
        logger.info(
            "Bypass anti-Frida: success=%s alive=%s neutralized=%s",
            success, app_alive, len(neutralized),
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
        static_profile: Optional[dict] = None,
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
            app_detection: Observação pré-calculada (opcional).
            static_profile: Perfil estático do APK (opcional). Quando
                disponível, distingue "app sem proteção anti-Frida" de
                "proteção existe, mas não foi observada".

        Returns:
            Dict com ``vulnerable`` (bool|None), ``frida_present``,
            ``checks`` (por vetor), ``app_detection`` (dict),
            ``static_detection``, ``protection_detected``,
            ``status_hint``, ``baseline`` e ``timestamp`` (ISO8601).
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

        # A análise estática responde "o APK contém checagem anti-Frida?".
        # Sem ela, o veredito antigo dizia "bypass venceu" para qualquer
        # app que não reagisse ao Frida — inclusive apps sem proteção.
        static_view = vector_view(static_profile, "frida")
        static_confidence = (static_view or {}).get("confidence")
        # Achados genéricos (ex: string "frida" em um nome de classe ou em
        # texto de UI) não bastam para afirmar que existe proteção anti-Frida.
        # Só evidência de alta confiança entra no veredito; medium/low fica
        # como contexto no relatório.
        static_present = bool(
            static_view
            and static_view.get("present")
            and static_confidence == "high"
        )
        detected_by_app = bool(app_detection.get("detected")) or (
            app_detection.get("vulnerable") is False
        )
        protection_detected = static_present or detected_by_app
        protection_sources = []
        if static_present:
            protection_sources.append(
                "static_asc"
                if (static_view or {}).get("engine") == "asc"
                else "static_apk"
            )
        if detected_by_app:
            protection_sources.append("dynamic")

        status_hint = None
        verdict_reason = None
        # Consistência: se o app executou uma checagem, a proteção
        # funcionou mesmo que um resultado pré-calculado diga o contrário.
        if detected_by_app and vulnerable is not None:
            vulnerable = False
        if vulnerable is True and not detected_by_app:
            if static_view is not None:
                if static_present:
                    verdict_reason = (
                        "proteção anti-Frida identificada no APK, mas o app "
                        "não reagiu na janela de observação"
                    )
                else:
                    # Nenhuma proteção no APK e nenhuma reação em runtime:
                    # não houve bypass a vencer. N/A é mais honesto que
                    # FALHOU (que significa "a proteção resistiu mal").
                    vulnerable = None
                    status_hint = "N/A"
                    verdict_reason = (
                        "nenhuma proteção anti-Frida identificada no APK e "
                        "nenhuma detecção observada em runtime"
                    )

        static_detection = {
            "static_detected": static_present,
            "available": static_view is not None,
            "confidence": (static_view or {}).get("confidence"),
            "types": sorted(
                {
                    item.get("kind")
                    for item in (static_view or {}).get("findings", [])
                    if item.get("kind")
                }
            ),
            "evidence": [
                item.get("evidence")
                for item in (static_view or {}).get("findings", [])
                if item.get("evidence")
            ],
            "details": (
                "assinaturas/classes anti-Frida no APK"
                if static_present
                else (
                    "apenas indícios de baixa/média confiança (não usados no veredito)"
                    if (static_view or {}).get("present")
                    else (
                        "nenhuma assinatura anti-Frida no APK"
                        if static_view is not None
                        else "análise estática não executada"
                    )
                )
            ),
        }
        if static_view is not None:
            static_detection["asc"] = static_view

        bypass_details: Optional[dict] = None
        bypass_successful: Optional[bool] = None
        bypass_skipped_reason: Optional[str] = None
        bypass_method = "stealth"
        if self.mode == "detect":
            bypass_skipped_reason = "modo detect: bypass anti-Frida não executado"
        elif not protection_detected:
            bypass_skipped_reason = "sem proteção anti-Frida identificada"
        elif package_name:
            bypass_details = self.attempt_bypass(package_name, window=window)
            bypass_method = str(bypass_details.get("method") or "stealth")
            if bypass_details.get("success") is None:
                bypass_skipped_reason = str(
                    bypass_details.get("skipped_reason")
                    or bypass_details.get("error")
                    or "bypass anti-Frida inconclusivo"
                )
            else:
                bypass_successful = bool(bypass_details.get("success"))
        else:
            bypass_skipped_reason = "package name ausente"

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
            "static_detection": static_detection,
            "protection_detected": protection_detected,
            "protection_sources": protection_sources,
            "bypass_successful": bypass_successful,
            "bypass_method": bypass_method,
            "bypass_details": bypass_details,
            "bypass_skipped_reason": bypass_skipped_reason,
            "status_hint": status_hint,
            "verdict_reason": verdict_reason,
            "baseline": app_detection.get("baseline"),
            "timestamp": _now_iso(),
        }
        if static_view is not None:
            result["static_analysis"] = {
                "engine": static_view.get("engine"),
                "version": static_view.get("version"),
                "vector": "frida",
                "present": static_present,
                "confidence": static_view.get("confidence"),
                "owners": static_view.get("owners") or {},
                "app_evidence": bool(static_view.get("app_evidence")),
                "coverage": static_view.get("coverage"),
            }
        if app_detection.get("error") and status_hint is None:
            result["error"] = str(app_detection["error"])
        logger.info(
            "Anti-Frida: vulnerable=%s frida_present=%s status=%s",
            vulnerable, frida_present, app_detection.get("observation_status"),
        )
        return result
