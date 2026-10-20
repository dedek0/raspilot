"""RASPilot — Verificação Anti-Hooking.

Audita se o app alvo possui proteção contra frameworks de hooking
(Xposed, LSPosed, EdXposed, Cydia Substrate e hooks inline como
SandHook, YAHFA, LSPlant, Whale e Dobby) e se essa proteção resiste a
um bypass real. O veredito ``protection_detected`` indica se o app
implementa checagens anti-hook; ``bypass_successful`` indica se o
``scripts/anti_hooking_bypass.js`` conseguiu neutralizá-las.

Fluxo (todos os vetores são independentes e consolidados em ``run_all``):

1. Vetores de dispositivo: pacotes de frameworks instalados, módulos em
   ``/data/adb`` (LSPosed/Riru) e libs de hook mapeadas no processo.
2. Detecção estática: assinaturas de frameworks anti-hook no APK.
3. Observação dinâmica: spawn com script que registra (sem bloquear) as
   checagens anti-hook executadas pelo app em runtime.
4. Bypass: novo spawn com ``scripts/anti_hooking_bypass.js`` que
   neutraliza as checagens observadas; o sucesso exige evidência real
   (e o app permanecendo vivo — morte durante o bypass significa que o
   RASP reagiu por outro vetor).

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from checks.apk_utils import pull_apk, scan_apk
from checks.stealth import PROC_FILTER_SCRIPT, load_stealth, unload_stealth
from rasp_vendors import VENDORS
from logcat_analyzer import (
    HIGH_CONFIDENCE_CATEGORIES,
    analyze_since,
    classify_failure,
    format_detection_signals,
    format_evidence,
    get_logcat_mark,
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

logger = logging.getLogger("raspilot.checks.anti_hooking")

# Intervalo entre as consultas feitas durante a janela de observacao.
# Exposto como constante para que os testes nao dependam de esperar
# tempo real.
OBSERVATION_POLL_INTERVAL = 1.0


# Caminho do script de bypass relativo à raiz do projeto.
HOOK_BYPASS_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "anti_hooking_bypass.js"
)

# Script de rastreio de morte do processo (quem chama exit/kill e com
# que pilha) — observado junto com o script anti-hook.
KILL_TRACE_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "kill_trace.js"
)

# Substrings que identificam frameworks de hooking nos packages instalados.
HOOK_PACKAGE_KEYWORDS = (
    "xposed",
    "lsposed",
    "riru",
    "substrate",
    "lspd",
    "taichi",
    "tai_chi",
)

# Substrings que identificam libs/módulos de frameworks de hooking.
# Frida/gadget ficam de fora de propósito: a detecção deles é papel do
# anti_frida e, nesta auditoria, o próprio RASPilot injeta o Frida.
HOOK_MODULE_KEYWORDS = (
    "xposed",
    "lsposed",
    "lspd",
    "edxposed",
    "edxp",
    "substrate",
    "sandhook",
    "yahfa",
    "lsplant",
    "whale",
    "dobby",
    "andhook",
    "riru",
    "epic",
    "xhook",
    "bytehook",
    "shadowhook",
)

# Assinaturas estáticas no APK: (tipo, [(needle_bytes, descrição), ...]).
# Ordem define a prioridade de evidências dentro de cada tipo.
STATIC_SIGNATURES: List[Tuple[str, List[Tuple[bytes, str]]]] = [
    ("xposed", [
        (b"de.robv.android.xposed", "pacote Xposed clássico"),
        (b"XposedBridge", "classe XposedBridge"),
        (b"IXposedHookLoadPackage", "interface IXposedHookLoadPackage"),
        (b"XC_MethodHook", "classe XC_MethodHook"),
        (b"XposedHelpers", "classe XposedHelpers"),
    ]),
    ("lsposed", [
        (b"org.lsposed", "pacote LSPosed"),
        (b"LSPosed", "string LSPosed"),
        (b"lspd", "serviço lspd do LSPosed"),
        (b"LSPlant", "framework de hook LSPlant"),
        (b"liblsplant", "lib lsplant"),
    ]),
    ("edxposed", [
        (b"edxposed", "string EdXposed"),
        (b"elderdrivers", "pacote elderdrivers (EdXposed)"),
        (b"edxp", "string edxp"),
    ]),
    ("substrate", [
        (b"com.saurik.substrate", "Cydia Substrate"),
        (b"libsubstrate", "lib do Substrate"),
        (b"Substrate", "string Substrate"),
    ]),
    ("inline_hook", [
        (b"SandHook", "framework SandHook"),
        (b"YAHFA", "framework YAHFA"),
        (b"libwhale", "framework Whale"),
        (b"libdobby", "framework Dobby"),
        (b"me.weishu.epic", "framework Epic"),
        (b"AndHook", "framework AndHook"),
        (b"shadowhook", "framework ShadowHook"),
        (b"libxhook", "framework xHook"),
        (b"libbytehook", "framework ByteHook"),
    ]),
    ("frida", [
        (b"re.frida.server", "path do frida-server embutido"),
        (b"gum-js-loop", "thread GumJS citada no código"),
        (b"libfrida", "referência a libfrida"),
        (b"linjector", "linjector do Frida"),
        (b"frida", "string 'frida' (anti-Frida embutido)"),
    ]),
]

# Assinaturas dos SDKs de RASP conhecidos, derivadas do catálogo.
# O nome do pacote é a assinatura mais estável de um SDK.
_VENDOR_SIGNATURES: List[Tuple[bytes, str]] = []
for _vendor in VENDORS:
    for _token in _vendor.tokens:
        if "." not in _token:
            continue
        _needle = _token.encode("utf-8")
        if any(existing[0] == _needle for existing in _VENDOR_SIGNATURES):
            continue
        _VENDOR_SIGNATURES.append((_needle, f"SDK de RASP {_vendor.name}"))

if _VENDOR_SIGNATURES:
    STATIC_SIGNATURES.append(("rasp_sdk", _VENDOR_SIGNATURES))

# Prioridade do tipo principal quando há várias assinaturas no APK.
STATIC_PRIORITY = ["xposed", "lsposed", "edxposed", "substrate", "inline_hook", "frida"]

# Métodos de observação considerados sinais FRACOS: leitura de
# /proc/.../maps, /proc/.../status, /proc/net/tcp (port-scan) e
# .../comm (nomes de threads) também tem uso legítimo (profiling,
# crash handlers, rede), então sozinhos não comprovam proteção anti-hook.
WEAK_DETECTION_METHODS = (
    "maps_scan",
    "status_scan",
    "net_scan",
    "comm_scan",
)

# Trechos de log do anti_hooking_bypass.js que comprovam que uma checagem
# anti-hook foi neutralizada em runtime (diferente de mero "hook instalado").
# Tipo de mensagem que carrega evidência real de bypass: a checagem do
# app foi exercitada e o resultado foi neutralizado. O simples "hook
# instalado" é diagnóstico e não sustenta o veredito.
BYPASS_EVIDENCE_TYPE = "bypass-evidence"
BYPASS_EVIDENCE_MARKERS = ("neutralizado", "bloqueado", "removido")

# Script de OBSERVAÇÃO (não bypass): registra as checagens anti-hook que o
# app executa (Class.forName de classes Xposed, File.exists em paths de
# frameworks, Runtime.exec com 'frida', buscas nativas strstr/strcmp por
# strings de frameworks, abertura de /proc/self/maps e stack traces com
# frames Xposed) e as envia ao host via send().
HOOK_DETECTION_SCRIPT = """
'use strict';

// true = apenas hooks Java (após o resume); false = apenas nativos
// (antes do resume, sem bridge Java, rápido).
var RASPILOT_JAVA_ONLY = (typeof __RASPILOT_JAVA_ONLY__ !== 'undefined')
    ? __RASPILOT_JAVA_ONLY__
    : false;

// Palavras-chave de frameworks de hooking que apps anti-hook procuram
// (em classes, paths, comandos e buscas nativas).
//
// Termos ambíguos ('whale', 'gadget') só casam quando aparecem como
// TOKEN isolado: "gadgets" ou "bluewhale" não são evidência de nada.
var HOOK_KEYWORDS = [
    'frida', 'libfrida', 'xposed', 'lsposed', 'lspd', 'edxposed', 'substrate',
    'sandhook', 'yahfa', 'lsplant', 'whale', 'dobby', 'riru', 'zygisk',
    'gadget', 'gum-js', 'linjector', 'andhook', 'shadowhook'
];

// Casa um termo como TOKEN, e não como substring solta.
//
// A comparação por substring transformava qualquer acesso do app a um
// arquivo próprio em "detecção" quando o nome do pacote continha o
// termo. A fronteira exige que o termo esteja isolado por caracteres
// não alfanuméricos.
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

function matchesHookFramework(str) {
    try {
        if (str === null || str === undefined) { return false; }
        var lower = ('' + str).toLowerCase();
        for (var i = 0; i < HOOK_KEYWORDS.length; i++) {
            if (containsToken(lower, HOOK_KEYWORDS[i])) { return true; }
        }
    } catch (e) { /* best-effort */ }
    return false;
}

// /proc/<pid>/maps, /proc/<pid>/status, /proc/net/tcp (port-scan das
// portas Frida) e .../comm (nomes de threads). Retorna o nome do método
// fraco ou null.
function procProbe(path) {
    try {
        var p = '' + path;
        if (p.indexOf('/proc/') !== 0) { return null; }
        if (p.indexOf('maps') !== -1) { return 'maps_scan'; }
        if (p.indexOf('status') !== -1) { return 'status_scan'; }
        if (p.indexOf('/net/tcp') !== -1) { return 'net_scan'; }
        if (p.indexOf('/comm') !== -1) { return 'comm_scan'; }
    } catch (e) { /* best-effort */ }
    return null;
}

function report(method, detail) {
    send({ type: 'hook-detection', method: method, detail: detail });
}

// Falha de instalação de um hook de observação (diagnóstico — não conta
// como detecção pelo app).
function reportHookError(msg) {
    send({ type: 'hook-detection-error', message: msg });
}

function observePath(api, path) {
    var probe = procProbe(path);
    if (probe !== null) { report(probe, path + ' via ' + api); return; }
    if (matchesHookFramework(path)) { report('native_' + api, path); }
}

// ----------------------------------------------------------------------
// Native — buscas por strings de frameworks (sem terminador garantido)
// ----------------------------------------------------------------------
if (!RASPILOT_JAVA_ONLY) {
['strstr', 'strcmp', 'strcasestr'].forEach(function (name) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var a = args[0].readCString();
                    var b = args[1].readCString();
                    if (matchesHookFramework(a) || matchesHookFramework(b)) {
                        report('native_' + name, 'needle=' + (b || a));
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});

// memcmp — varre o buffer pelas mesmas strings (comparações por tamanho,
// típicas de checagens anti-hook sem string literal no binário).
try {
    var memcmpAddr = raspilotFindExport('libc.so', 'memcmp');
    if (memcmpAddr !== null) {
        Interceptor.attach(memcmpAddr, {
            onEnter: function (args) {
                try {
                    var n = args[2].toInt32();
                    if (n > 0 && n < 4096) {
                        var bytes = new Uint8Array(args[0].readByteArray(n));
                        var s = '';
                        for (var i = 0; i < bytes.length; i++) {
                            var c = bytes[i];
                            s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ' ';
                        }
                        if (matchesHookFramework(s)) {
                            report('native_memcmp', 'buffer contém string de framework');
                        }
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    }
} catch (e) { reportHookError('instalação de hook nativo falhou: ' + e); }

// ----------------------------------------------------------------------
// Native — abertura/sondagem de paths (frameworks e /proc)
// ----------------------------------------------------------------------
['open', 'openat', 'openat64'].forEach(function (name) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var pathPtr = (name === 'open') ? args[0] : args[1];
                    observePath(name, pathPtr.readCString());
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});

['fopen', 'fopen64'].forEach(function (name) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try { observePath(name, args[0].readCString()); }
                catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});

['access', 'stat', 'stat64', 'lstat', 'faccessat', 'faccessat2'].forEach(function (name) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        var pathIndex = (name === 'faccessat' || name === 'faccessat2') ? 1 : 0;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try { observePath(name, args[pathIndex].readCString()); }
                catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { reportHookError('instalação de ' + name + ' falhou: ' + e); }
});

}

// ----------------------------------------------------------------------
// Java — checagens anti-hook clássicas
// ----------------------------------------------------------------------
function reportStackHit(source, frames) {
    try {
        if (frames === null || frames === undefined) { return; }
        for (var i = 0; i < frames.length; i++) {
            var className = '' + frames[i].getClassName();
            if (matchesHookFramework(className)) {
                report(source, 'frame=' + className);
                return;
            }
        }
    } catch (e) { /* best-effort */ }
}

function installJavaHooks() {
    // Class.forName('de.robv.android.xposed.XposedBridge') — checagem
    // clássica de detecção de Xposed/LSPosed (dispara sem precisar achar).
    //
    // Só a sobrecarga de três argumentos é hookada. A de um argumento
    // NÃO pode ser substituída: ART resolve o nome usando o class
    // loader de quem chamou, e essa informação se perde quando o
    // original é invocado através do Frida — o ART passa a inferir o
    // caller a partir do frame do próprio agente e resolve a classe no
    // boot class loader. O efeito é pior que não hookar: o app passa a
    // receber ClassNotFoundException para classes legítimas, e apps que
    // carregam código de um class loader próprio (packers, plugins)
    // quebram na inicialização.
    //
    // A sobrecarga de três argumentos preserva a semântica: o loader
    // chega explícito, e a de um argumento delega para ela — a checagem
    // continua sendo interceptada.
    try {
        var ClassCl = Java.use('java.lang.Class');
        var forName3 = ClassCl.forName.overload(
            'java.lang.String', 'boolean', 'java.lang.ClassLoader'
        );
        forName3.implementation = function (name, initialize, loader) {
            try {
                if (matchesHookFramework(name)) { report('Class.forName', '' + name); }
            } catch (e) { /* best-effort */ }
            return forName3.call(this, name, initialize, loader);
        };
    } catch (e) { /* sobrecarga indisponível */ }

    // ClassLoader.loadClass — variante da mesma checagem.
    try {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
            try {
                if (matchesHookFramework(name)) { report('ClassLoader.loadClass', '' + name); }
            } catch (e) { /* best-effort */ }
            return this.loadClass(name);
        };
    } catch (e) { /* Java indisponível */ }

    // File.exists — sondagem de paths de frameworks e de /proc.
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = '' + this.getAbsolutePath();
            try {
                var probe = procProbe(path);
                if (probe !== null) { report(probe, path + ' via File.exists'); }
                else if (matchesHookFramework(path)) { report('File.exists', path); }
            } catch (e) { /* best-effort */ }
            return this.exists();
        };
    } catch (e) { /* Java indisponível */ }

    // Runtime.exec / ProcessBuilder — comandos citando frameworks.
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            try {
                if (matchesHookFramework(cmd)) { report('Runtime.exec', '' + cmd); }
            } catch (e) { /* best-effort */ }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArr) {
            var joined = '';
            try { joined = cmdArr.join(' '); } catch (e) { joined = '' + cmdArr; }
            try {
                if (matchesHookFramework(joined)) { report('Runtime.exec[]', joined); }
            } catch (e) { /* best-effort */ }
            return this.exec(cmdArr);
        };
    } catch (e) { /* Java indisponível */ }

    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command();
            var joined = '';
            try { joined = cmd.toArray().join(' '); } catch (e) { joined = '' + cmd; }
            try {
                if (matchesHookFramework(joined)) { report('ProcessBuilder.start', joined); }
            } catch (e) { /* best-effort */ }
            return this.start();
        };
    } catch (e) { /* Java indisponível */ }

    // Stack traces — só reporta quando existe frame de framework (não
    // vira ruído com logs legítimos do app).
    try {
        var Throwable = Java.use('java.lang.Throwable');
        Throwable.getStackTrace.implementation = function () {
            var frames = this.getStackTrace();
            reportStackHit('Throwable.getStackTrace', frames);
            return frames;
        };
    } catch (e) { /* Java indisponível */ }

    try {
        var Thread = Java.use('java.lang.Thread');
        Thread.getStackTrace.implementation = function () {
            var frames = this.getStackTrace();
            reportStackHit('Thread.getStackTrace', frames);
            return frames;
        };
    } catch (e) { /* Java indisponível */ }
}

// A instalação é adiada: o carregamento do script precisa retornar antes
// que o agente limite o tempo de carga do script.
// Na fase nativa a bridge Java não existe, então os hooks Java ficam
// de fora.
if (RASPILOT_JAVA_ONLY) {
    if (typeof raspilotDeferJava === 'function') {
        raspilotDeferJava(installJavaHooks, 'anti-hooking-detect');
    } else if (typeof raspilotPerformJava === 'function') {
        raspilotPerformJava(installJavaHooks);
    } else if (typeof Java !== 'undefined' && Java.available) {
        Java.perform(installJavaHooks);
    }
}
"""


def _now_iso() -> str:
    """Retorna o timestamp atual em ISO8601 (UTC).

    Returns:
        Ex: ``'2026-10-14T18:00:00+00:00'``.
    """
    return datetime.now(timezone.utc).isoformat()


class AntiHookingCheck:
    """Verifica proteção anti-hooking do app e tenta contorná-la."""

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

    def _shell(self, command: str, timeout: int = 20) -> dict:
        """Executa um comando shell e retorna a resposta estruturada.

        Args:
            command: Comando shell do dispositivo.
            timeout: Timeout em segundos.

        Returns:
            Dict ``{'ok', 'rc', 'stdout', 'stderr'}``.
        """
        return self.dm.run_shell(command, timeout=timeout)

    def _shell_root(self, command: str, timeout: int = 20) -> dict:
        """Executa um comando shell elevando para root quando ``su`` existe.

        Diretórios como ``/data/adb/modules`` e ``/data/adb/lspd`` negam
        leitura ao usuário ``shell`` — sem elevação esse vetor daria
        falso-negativo mesmo com framework instalado.

        Args:
            command: Comando shell do dispositivo.
            timeout: Timeout em segundos.

        Returns:
            Dict ``{'ok', 'rc', 'stdout', 'stderr'}``.
        """
        runner = getattr(self.dm, "run_shell_root", None)
        if callable(runner):
            return runner(command, timeout=timeout)
        # Fake/legado sem suporte: cai no shell comum.
        return self.dm.run_shell(command, timeout=timeout)

    def _pull_apk(self, package_name: str, dest_dir: str) -> List[str]:
        """Baixa o(s) APK(s) do app para o host.

        Delega a :func:`checks.apk_utils.pull_apk` (compartilhado com o
        SSL Pinning) — mantido como método para permitir mock nos testes.

        Args:
            package_name: Package name do app alvo.
            dest_dir: Diretório local de destino.

        Returns:
            Lista de caminhos locais dos APKs baixados (vazia se falhar).
        """
        return pull_apk(self.dm, package_name, dest_dir)

    # ------------------------------------------------------------------
    # Vetores de dispositivo
    # ------------------------------------------------------------------
    def check_hook_framework_packages(self) -> dict:
        """Detecta frameworks de hooking instalados como app.

        Compara a lista de packages do dispositivo com
        :data:`HOOK_PACKAGE_KEYWORDS` (Xposed, LSPosed, EdXposed,
        Substrate, Riru, TaiChi).

        Returns:
            Dict com ``detected``, ``evidence`` (packages), ``details``
            e, em falha de shell, ``error``.
        """
        res = self._shell("pm list packages 2>/dev/null")
        if not res["ok"]:
            return {
                "detected": False,
                "evidence": [],
                "details": "Não foi possível listar packages",
                "error": res["stderr"] or f"rc={res['rc']}",
            }

        found: List[str] = []
        for line in res["stdout"].splitlines():
            pkg = line.replace("package:", "").strip()
            if not pkg:
                continue
            if any(k in pkg.lower() for k in HOOK_PACKAGE_KEYWORDS):
                found.append(pkg)

        detected = bool(found)
        result = {
            "detected": detected,
            "evidence": found,
            "details": (
                f"Frameworks de hooking instalados: {', '.join(found)}"
                if detected
                else "Nenhum framework de hooking (Xposed/LSPosed/Substrate) instalado"
            ),
        }
        logger.debug("check_hook_framework_packages: detected=%s evidence=%s", detected, found)
        return result

    def check_hook_modules_on_device(self) -> dict:
        """Detecta módulos de frameworks de hooking em ``/data/adb``.

        Lista ``/data/adb/modules`` (módulos Magisk/Zygisk com tema de
        hooking, ex: ``zygisk_lsposed``) e verifica o diretório de dados
        do LSPosed (``/data/adb/lspd``).

        Returns:
            Dict com ``detected``, ``evidence`` (paths) e ``details``.
        """
        evidence: List[str] = []

        res = self._shell_root("ls /data/adb/modules 2>/dev/null")
        if res["ok"] and res["stdout"]:
            for line in res["stdout"].splitlines():
                name = line.strip()
                if name and any(k in name.lower() for k in HOOK_MODULE_KEYWORDS):
                    evidence.append(f"/data/adb/modules/{name}")

        res = self._shell_root("ls /data/adb/lspd 2>/dev/null")
        if res["ok"] and res["stdout"]:
            evidence.append("/data/adb/lspd (dados do LSPosed)")

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Módulos de hooking no dispositivo: {'; '.join(evidence)}"
                if detected
                else "Nenhum módulo de framework de hooking em /data/adb"
            ),
        }
        logger.debug("check_hook_modules_on_device: detected=%s evidence=%s", detected, evidence)
        return result

    def check_hook_libraries(
        self, session: Optional[object] = None, pid: Optional[int] = None
    ) -> dict:
        """Enumera libs de frameworks de hooking no processo alvo.

        Usa a sessão Frida (visão de dentro do processo, sem depender de
        permissão do ``shell`` em ``/proc``) e, se ela não estiver
        disponível, faz fallback para ``/proc/<pid>/maps`` com elevação.

        Args:
            session: Sessão Frida ativa sobre o app alvo (opcional).
            pid: PID do processo alvo para o fallback via ``/proc``.

        Returns:
            Dict com ``detected``, ``evidence`` (nomes de módulos),
            ``source`` ('processo'|'/proc/<pid>/maps'|None) e ``details``.
            Em erro de enumeração sem fallback: ``detected=False`` + ``error``.
        """
        if session is None and pid is None:
            return {
                "detected": False,
                "evidence": [],
                "source": None,
                "details": "Sem sessão nem pid para enumerar módulos",
                "skipped": True,
            }

        evidence: List[str] = []
        errors: List[str] = []
        source: Optional[str] = None
        session_ok = False

        if session is not None:
            try:
                for name in enumerate_module_names(session):
                    if name and any(k in name.lower() for k in HOOK_MODULE_KEYWORDS):
                        if name not in evidence:
                            evidence.append(name)
                session_ok = True
                source = "processo"
            except Exception as exc:
                # Processo morto destrói a sessão ("session is gone") — o
                # alvo já saiu de cena, não é falha do check em si.
                if pid is not None and not self.dm.is_app_alive(pid):
                    return {
                        "detected": False,
                        "evidence": [],
                        "source": None,
                        "details": "processo encerrou antes da enumeração de módulos",
                        "skipped": True,
                    }
                errors.append(f"enumeração via Frida: {exc}")

        # Fallback só quando a visão de dentro do processo falhou.
        if not session_ok and pid is not None:
            res = self._shell_root(f"cat /proc/{pid}/maps 2>/dev/null")
            if res["ok"] and res["stdout"]:
                for line in res["stdout"].splitlines():
                    tokens = line.split()
                    path = tokens[-1] if tokens else ""
                    if path.startswith("/") and any(
                        k in path.lower() for k in HOOK_MODULE_KEYWORDS
                    ):
                        if path not in evidence:
                            evidence.append(path)
                source = "/proc/<pid>/maps"
            elif res["stderr"]:
                errors.append(res["stderr"])

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "source": source if detected else None,
            "details": (
                f"Libs de frameworks de hooking no processo: {evidence}"
                if detected
                else "Nenhuma lib de framework de hooking no processo alvo"
            ),
        }
        if errors and not detected:
            result["error"] = "; ".join(errors)
        logger.debug("check_hook_libraries: detected=%s evidence=%s", detected, evidence)
        return result

    # ------------------------------------------------------------------
    # Detecção estática
    # ------------------------------------------------------------------
    def detect_static(
        self, package_name: str, apk_path: Optional[str] = None
    ) -> dict:
        """Detecta assinaturas anti-hook no APK do app.

        Procura as classes/strings que SDKs anti-RASP usam para checar
        frameworks de hooking (Xposed, LSPosed, EdXposed, Substrate,
        hooks inline e Frida).

        Args:
            package_name: Package name do app alvo.
            apk_path: Caminho opcional de um APK local (pula o ``adb pull``).

        Returns:
            Dict com ``static_detected`` (bool), ``types`` (lista),
            ``primary`` (tipo principal ou ``None``), ``evidence`` e,
            em falha de pull, ``error``.
        """
        with tempfile.TemporaryDirectory(prefix="raspilot_hook_") as tmp:
            if apk_path:
                apks = [apk_path]
            else:
                apks = self._pull_apk(package_name, tmp)
                if not apks:
                    return {
                        "static_detected": False,
                        "types": [],
                        "primary": None,
                        "evidence": [],
                        "error": f"Não foi possível obter o APK de {package_name}",
                    }

            all_found: Dict[str, List[str]] = {}
            for apk in apks:
                try:
                    found = scan_apk(apk, STATIC_SIGNATURES)
                except zipfile.BadZipFile as exc:
                    logger.warning("APK inválido: %s", exc)
                    continue
                for sig_type, evidences in found.items():
                    all_found.setdefault(sig_type, []).extend(evidences)

        if not all_found:
            return {
                "static_detected": False,
                "types": [],
                "primary": None,
                "evidence": [],
                "details": "Nenhuma assinatura de framework anti-hook no APK",
            }

        chosen = sorted(
            all_found.keys(),
            key=lambda t: STATIC_PRIORITY.index(t) if t in STATIC_PRIORITY else 99,
        )[0]
        evidence = [f"[{t}] {e}" for t, items in all_found.items() for e in items]

        result = {
            "static_detected": True,
            "types": sorted(all_found.keys()),
            "primary": chosen,
            "evidence": evidence,
            "details": f"Assinaturas anti-hook no APK (principal: {chosen})",
        }
        logger.info("Assinaturas anti-hook detectadas: type=%s", chosen)
        return result

    # ------------------------------------------------------------------
    # Observação de detecção pelo app
    # ------------------------------------------------------------------
    def check_hook_detection_in_app(
        self,
        session: object,
        on_script_loaded: Optional[object] = None,
        window: int = 12,
        pid: Optional[int] = None,
        package_name: Optional[str] = None,
        logcat_mark: Optional[int] = None,
    ) -> dict:
        """Observa se o app alvo executa checagens anti-hook em runtime.

        Injeta um script de observação que registra (sem bloquear)
        ``Class.forName``/``ClassLoader.loadClass`` de classes de
        frameworks, ``File.exists`` em paths de frameworks e de ``/proc``,
        ``Runtime.exec``/``ProcessBuilder`` com strings de frameworks,
        buscas nativas (``strstr``/``strcmp``/``memcmp``), abertura de
        ``/proc/self/maps`` e ``/proc/self/status`` e stack traces com
        frames de frameworks.

        Sinais considerados fortes (qualquer um define ``detected=True``):
        tudo, exceto a leitura de ``maps``/``status``, que isoladamente
        tem uso legítimo e vira apenas ``weak_signals``. Se o app se
        encerrar durante a janela (reação típica de RASP), isso também é
        sinal forte.

        Args:
            session: Sessão Frida ativa sobre o app alvo.
            on_script_loaded: Callback chamado logo após ``script.load()``
                — usado para ``resume`` de spawn suspenso.
            window: Janela de observação em segundos.
            pid: PID do processo alvo (para monitorar se o app morre).
            package_name: Package name (melhora o filtro da causa da
                morte via logcat quando o processo encerra).

        Returns:
            Dict com ``detected`` (bool), ``detection_methods_found``,
            ``strong_signals``, ``weak_signals``, ``app_alive_at_end`` e
            ``death_cause`` (dict|None — evidências externas da morte).
        """
        found: List[str] = []
        strong: List[str] = []
        weak: List[str] = []
        script = None
        java_script = None
        kill_script = None
        java_load_error: Optional[str] = None
        stealth_loaded: List[tuple] = []
        resumed = False
        died_after: Optional[int] = None

        def add_signal(method: str, detail: str) -> None:
            entry = f"{method}: {detail}"
            if entry in found:
                return
            found.append(entry)
            bucket = weak if method in WEAK_DETECTION_METHODS else strong
            bucket.append(entry)
            logger.info("App executou checagem anti-hook -> %s", entry)

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("type") == "hook-detection-error":
                    # Diagnóstico do próprio script (hook não instalou) —
                    # não é uma checagem anti-hook do app.
                    logger.warning(
                        "Hook de observação anti-hook não instalou: %s",
                        payload.get("message"),
                    )
                    return
                if payload.get("type") == "app-kill":
                    # Quem matou o processo (kill_trace.js) — sinal forte.
                    add_signal("app_kill", payload.get("message", ""))
                    return
                if payload.get("type") != "hook-detection":
                    return
                add_signal(payload.get("method", "?"), payload.get("detail", ""))
            elif message.get("type") == "error":
                logger.debug("Erro no script anti-hook: %s", message.get("description"))

        try:
            if self.mode == "stealth":
                stealth_loaded = load_stealth(
                    session,
                    on_message=on_message,
                    replacements=self._script_replacements(),
                    include_proc_filter=True,
                )
            # Fase 1 (antes do resume): hooks nativos, sem bridge Java.
            script = load_script(
                session, HOOK_DETECTION_SCRIPT, on_message=on_message,
                name="raspilot-hook-detect-native",
                replacements=self._script_replacements(java_only=False),
                with_java_bridge=False,
                load_timeout=5.0,
            )
            if on_script_loaded is not None:
                on_script_loaded()
                resumed = True
            # Fase 2 (após o resume): hooks Java, com o app rodando.
            if self.no_java:
                java_load_error = None
            else:
                try:
                    java_script = load_script(
                        session, HOOK_DETECTION_SCRIPT, on_message=on_message,
                        name="raspilot-hook-detect-java",
                        replacements=self._script_replacements(java_only=True),
                        with_java_bridge=True,
                        load_timeout=5.0,
                    )
                except Exception as exc:
                    java_load_error = str(exc)
                    logger.warning(
                        "Hooks Java anti-hook não carregaram: %s", exc
                    )
                    safe_detach(session)
            if java_load_error is None and not self.no_java:
                # Diagnóstico de kill (usa Java) carregado por último.
                try:
                    kill_script = load_script_file(
                        session, KILL_TRACE_SCRIPT, on_message=on_message,
                        name="raspilot-kill-trace", load_timeout=3.0,
                    )
                except Exception:
                    logger.debug("kill_trace.js indisponível na observação", exc_info=True)
            for elapsed in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante a observação (~%ss)", pid, died_after
                    )
                    break
        except Exception as exc:
            logger.warning("Falha ao observar checagens anti-hook no app", exc_info=True)
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

            if failure.get("is_rasp"):
                for entry in format_detection_signals(
                    logcat, ("root", "hooking", "emulator", "debug", "integrity"),
                    limit=4,
                ):
                    method, _, detail = entry.partition(": ")
                    add_signal(method, detail)
                for item in logcat.get("security_signals", []) or []:
                    if isinstance(item, dict) and item.get("category") == "frida_agent_crash":
                        add_signal("frida_agent_crash", item.get("line", ""))
                        break
                add_signal(
                    "app_terminated",
                    "sessão encerrada durante o carregamento (reação do RASP)",
                )
                if death_cause:
                    add_signal("app_kill_external", death_cause.get("summary", "?"))
                return {
                    "detected": True,
                    "detection_methods_found": found,
                    "strong_signals": strong,
                    "weak_signals": weak,
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
                        "segurança no logcat — reação anti-hook"
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
                error = f"sessão encerrada antes da instalação dos hooks: {exc}"
            return {
                "detected": False,
                "detection_methods_found": [],
                "strong_signals": [],
                "weak_signals": [],
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
        if died_after is None and pid is not None:
            try:
                if not self.dm.is_app_alive(pid):
                    died_after = max(1, int(window))
                    logger.info("Processo %s morreu após a janela de observação", pid)
            except Exception:
                logger.debug("Falha na rechecagem de vida", exc_info=True)

        # Evidências de segurança observadas apenas no logcat. TLS/Frida
        # ficam de fora: são sintomas de pinning/anti-Frida, não de
        # anti-hooking. Uma linha por categoria.
        for entry in format_detection_signals(
            logcat, ("root", "hooking", "emulator", "debug", "integrity"), limit=4
        ):
            method, _, detail = entry.partition(": ")
            add_signal(method, detail)
        if logcat.get("agent_terminated"):
            # Falha da instrumentação (o agente quebrou dentro do
            # processo): é contexto, não checagem anti-hook do app.
            for item in logcat.get("security_signals", []) or []:
                if isinstance(item, dict) and item.get("category") == "frida_agent_crash":
                    entry = f"frida_agent_crash: {item.get('line', '')}"
                    if entry not in found:
                        found.append(entry)
                        weak.append(entry)
                    break

        death_cause: Optional[dict] = None
        death_classification: Optional[str] = None
        observation_status = "ok"
        error: Optional[str] = None
        app_alive = died_after is None

        if app_alive and self.no_java and not strong:
            observation_status = "native_only"
            error = (
                "hooks Java desativados (--no-java); a observação nativa não "
                "encontrou checagem anti-hook"
            )
        elif app_alive and java_load_error and not strong:
            observation_status = "error"
            error = (
                "hooks Java de observação não carregaram e nenhuma checagem "
                f"anti-hook foi observada: {java_load_error}"
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
            kill_traced = any(item.startswith("app_kill") for item in strong)

            if kill_traced:
                death_classification = "rasp_kill"
            elif baseline_died:
                # Já morria sozinho no baseline: não é possível isolar uma
                # reação anti-hook da instrumentação.
                death_classification = "baseline_death"
                observation_status = "baseline_death"
                error = (
                    "app encerrou no baseline sem instrumentação; não é possível "
                    "isolar uma reação anti-hook"
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
                death_classification = "unclassified_death"

            if death_classification in ("rasp_kill", "rasp_reaction", "unclassified_death"):
                add_signal(
                    "app_terminated",
                    f"processo encerrou ~{died_after}s após resume "
                    f"({death_classification})",
                )
                if death_cause:
                    add_signal("app_kill_external", death_cause.get("summary", "?"))

        # O app bloquear a auditoria é evidência de proteção: tanto uma
        # checagem observada quanto a terminação do processo contam.
        detected = (
            bool(strong) or death_classification in ("rasp_kill", "rasp_reaction")
        ) and observation_status != "inconclusive"
        result = {
            "detected": detected,
            "detection_methods_found": found,
            "strong_signals": strong,
            "weak_signals": weak,
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
                f"App executou checagens anti-hook: {'; '.join(strong)}"
                if strong
                else (
                    "Apenas sinais fracos (leitura de maps/status), "
                    "sem checagem anti-hook forte observada"
                    if weak
                    else "App não executou nenhuma checagem anti-hook observada"
                )
            ),
        }
        if error:
            result["error"] = error
        logger.info(
            "check_hook_detection_in_app: detected=%s strong=%s weak=%s death=%s",
            detected, len(strong), len(weak), death_classification,
        )
        return result

    # ------------------------------------------------------------------
    # Bypass
    # ------------------------------------------------------------------
    def attempt_bypass(self, package_name: str, window: int = 12) -> dict:
        """Tenta neutralizar as checagens anti-hook do app.

        Espawna o app com Frida, carrega o
        ``scripts/anti_hooking_bypass.js`` (oculta classes/paths/
        strings de frameworks, filtra ``/proc/self/maps`` e zera
        ``TracerPid``) e coleta logs pela janela informada.

        Sucesso exige evidência real de neutralização **e** o app
        permanecendo vivo: morte durante o bypass significa que o RASP
        detectou a injeção por outro vetor e o bypass não venceu.

        Args:
            package_name: Package name do app alvo.
            window: Janela de observação em segundos.

        Returns:
            Dict com ``success`` (bool), ``bypass_logs``, ``effective_logs``,
            ``app_alive_at_end`` (bool) e ``error`` (str|None).
        """
        bypass_logs: List[str] = []
        bypass_evidence: List[str] = []
        session = None
        script = None
        java_script = None
        proc_script = None
        kill_script = None
        java_load_error: Optional[str] = None
        stealth_loaded: List[tuple] = []
        died_after: Optional[int] = None

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("type") == "app-kill":
                    msg = "app-kill: " + payload.get("message", "")
                    if msg and msg not in bypass_logs:
                        bypass_logs.append(msg)
                    return
                if payload.get("type") == BYPASS_EVIDENCE_TYPE:
                    msg = payload.get("message", "")
                    if msg and msg not in bypass_evidence:
                        bypass_evidence.append(msg)
                    if msg and msg not in bypass_logs:
                        bypass_logs.append(msg)
                    return
                if payload.get("type") != "raspilot-hooking-bypass":
                    return
                msg = payload.get("message", "")
                if msg and msg not in bypass_logs:
                    bypass_logs.append(msg)
            elif message.get("type") == "error":
                desc = message.get("description", "")
                if desc:
                    bypass_logs.append(f"[script-error] {desc}")

        logcat_mark = get_logcat_mark(self.dm)
        try:
            # Spawn suspenso: instala os hooks ANTES do app rodar, para
            # não perder as checagens anti-hook da inicialização.
            session = self.dm.spawn_app(package_name, resume=False)
            if self.mode == "stealth":
                stealth_loaded = load_stealth(
                    session,
                    on_message=on_message,
                    replacements=self._script_replacements(),
                    include_proc_filter=True,
                )
            # Fase 1 (antes do resume): hooks nativos de bypass e filtro
            # de /proc, sem bridge Java.
            script = load_script_file(
                session, HOOK_BYPASS_SCRIPT, on_message=on_message,
                replacements=self._script_replacements(java_only=False),
                with_java_bridge=False,
                load_timeout=5.0,
            )
            proc_loaded = any(
                path == PROC_FILTER_SCRIPT for path, _ in stealth_loaded
            )
            if not proc_loaded:
                proc_script = load_script_file(
                    session, PROC_FILTER_SCRIPT, on_message=on_message,
                    replacements=self._script_replacements(java_only=False),
                    with_java_bridge=False,
                    load_timeout=5.0,
                )
            self.dm.resume_app()
            pid = self.dm.last_spawn_pid or self.dm.get_app_pid(package_name)
            # Fase 2 (após o resume): hooks Java de bypass.
            try:
                java_script = load_script_file(
                    session, HOOK_BYPASS_SCRIPT, on_message=on_message,
                    replacements=self._script_replacements(java_only=True),
                    with_java_bridge=True,
                    load_timeout=5.0,
                )
            except Exception as exc:
                java_load_error = str(exc)
                logger.warning("Hooks Java do bypass não carregaram: %s", exc)
                safe_detach(session)
            if java_load_error is None:
                # Diagnóstico de kill carregado por último.
                try:
                    kill_script = load_script_file(
                        session, KILL_TRACE_SCRIPT, on_message=on_message,
                        load_timeout=3.0,
                    )
                except Exception:
                    logger.debug("kill_trace.js indisponível no bypass", exc_info=True)
            for elapsed in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante o bypass anti-hook (~%ss)",
                        pid, died_after,
                    )
                    break
        except Exception as exc:
            logger.warning("Bypass anti-hook falhou", exc_info=True)
            pid = locals().get("pid") or self.dm.last_spawn_pid
            logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
            failure = classify_failure(logcat, self._baseline())
            app_alive: Optional[bool] = None
            death_cause = None
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
                    logger.debug("Falha ao capturar morte no bypass", exc_info=True)

            if app_alive is False:
                bypass_logs.append("app_terminated: processo morreu durante o bypass")
                if death_cause:
                    bypass_logs.append(
                        "death_cause: " + str(death_cause.get("summary", "?"))
                    )

            # Reação do RASP durante o carregamento: a proteção resistiu
            # (inclusive quando o agente foi derrubado e o app sobreviveu).
            if failure.get("is_rasp"):
                return {
                    "success": False,
                    "blocked": True,
                    "bypass_logs": bypass_logs,
                    "effective_logs": [],
                    "app_alive_at_end": False,
                    "death_cause": death_cause,
                    "logcat": logcat,
                    "logcat_evidence": format_evidence(logcat),
                    "error": None,
                }

            kind = str(failure.get("kind", "unknown"))
            status = "error" if kind in ("unknown", "unknown_death") else kind
            if kind == "start_timeout":
                error = (
                    "app morto por ActivityManager start timeout durante o bypass "
                    "(instrumentação); reduza o trabalho antes do resume"
                )
            elif kind == "baseline_death":
                error = "app encerrou no baseline sem instrumentação; bypass inconclusivo"
            elif kind == "instrumentation_crash":
                error = (
                    "app encerrou por crash/ANR sem evidência de segurança no logcat "
                    "(possível crash da instrumentação)"
                )
            else:
                error = str(exc)
            return {
                "success": False,
                "blocked": False,
                "bypass_logs": bypass_logs,
                "effective_logs": [],
                "app_alive_at_end": app_alive if app_alive is not None else True,
                "death_cause": death_cause,
                "logcat": logcat,
                "logcat_evidence": format_evidence(logcat),
                "error": error,
            }
        finally:
            safe_unload(script)
            safe_unload(java_script)
            safe_unload(proc_script)
            safe_unload(kill_script)
            unload_stealth(stealth_loaded)
            if session is not None:
                safe_detach(session)

        if died_after is not None:
            bypass_logs.append(
                f"app_terminated: processo encerrou ~{died_after}s após resume"
            )
            try:
                death_cause = self.dm.capture_death_cause(
                    pid=pid, package=package_name
                )
                bypass_logs.append(
                    "death_cause: " + str(death_cause.get("summary", "?"))
                )
            except Exception:
                logger.debug("Falha ao capturar causa da morte", exc_info=True)
                death_cause = None
        else:
            death_cause = None

        # Evidência real: logs que comprovam checagem neutralizada.
        # Evidência de bypass exige que a checagem do app tenha sido de
        # fato exercitada. O self-report do hook ("hookado", "carregado")
        # prova apenas que a instrumentação está ativa — não que o app
        # foi enganado.
        effective = list(bypass_evidence) or [
            log for log in bypass_logs
            if any(marker in log for marker in BYPASS_EVIDENCE_MARKERS)
            and "hookado" not in log
            and not log.endswith("carregado")
        ]
        alive = died_after is None
        success = bool(effective) and alive
        logcat = analyze_since(
            self.dm, logcat_mark, package_name, locals().get("pid")
        )
        # O app bloqueou a auditoria: encerrou com a instrumentação e a
        # causa é atribuível ao RASP. Isso é uma conclusão sobre a
        # proteção (ela resistiu), não uma etapa que não rodou.
        blocked = bool(
            not alive
            and classify_failure(logcat, self._baseline()).get("is_rasp")
        )
        error: Optional[str] = None
        if alive and java_load_error:
            # Hooks Java são essenciais para o anti-hooking; neutralizar
            # só a camada nativa não permite afirmar que o bypass venceu.
            success = False
            error = f"hooks Java do bypass não carregaram: {java_load_error}"
        elif not alive:
            # O app encerrou durante o bypass: o bypass não venceu — o
            # app bloqueou a auditoria.
            success = False
            error = (
                "o app bloqueou o bypass: encerrou durante a execução do bypass"
            )

        result = {
            "success": success,
            "blocked": blocked,
            "bypass_logs": bypass_logs,
            "effective_logs": effective,
            "app_alive_at_end": alive,
            "death_cause": death_cause,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "java_load_error": java_load_error,
            "stealth_used": bool(stealth_loaded),
            "error": error,
        }
        logger.info(
            "Bypass anti-hook: success=%s evidências=%s alive=%s",
            success, len(effective), alive,
        )
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self,
        package_name: str,
        window: int = 12,
        apk_path: Optional[str] = None,
        precomputed_detection: Optional[dict] = None,
        precomputed_bypass: Optional[dict] = None,
    ) -> dict:
        """Combina vetores, detecção (estática + dinâmica) e bypass.

        Semântica do veredito:

        - ``protection_detected=True`` e ``bypass_successful=True`` ⇒ o
          app tem proteção anti-hook, mas o bypass venceu (falha de RASP).
        - ``protection_detected=True`` e ``bypass_successful=False`` ⇒ a
          proteção resistiu ao bypass (OK).
        - ``protection_detected=False`` ⇒ o app não possui checagens
          anti-hook observáveis (falha de RASP; ``bypass_successful=None``).

        Um ``error`` no topo do resultado significa que uma fase
        essencial (observação sem proteção estática, ou o próprio
        bypass) não pôde executar — o reporter mapeia isso para ERROR.

        Args:
            package_name: Package name do app alvo.
            window: Janela de observação (segundos) da observação e do bypass.
            apk_path: Caminho opcional de APK local para a análise estática.

        Returns:
            Dict com ``protection_detected``, ``bypass_successful``,
            ``hook_frameworks_present``, ``checks`` (por vetor),
            ``static_detection``, ``app_detection``, ``bypass_details``
            e ``timestamp`` (ISO8601).
        """
        checks: Dict[str, dict] = {
            "hook_framework_packages": self.check_hook_framework_packages(),
            "hook_modules_on_device": self.check_hook_modules_on_device(),
        }

        static = self.detect_static(package_name, apk_path=apk_path)

        # Fase dinâmica: usa a observação combinada quando fornecida;
        # caso contrário, cria um spawn próprio (uso standalone).
        session = None
        pid: Optional[int] = None
        app_detection: dict = {}
        if precomputed_detection is not None:
            app_detection = precomputed_detection
            checks["hook_libraries"] = {
                "detected": False,
                "evidence": [],
                "source": None,
                "details": "enumeração feita na sessão combinada",
                "skipped": True,
            }
        else:
            logcat_mark = get_logcat_mark(self.dm)
            try:
                session = self.dm.spawn_app(package_name, resume=False)
                pid = self.dm.last_spawn_pid or self.dm.get_app_pid(package_name)
            except Exception as exc:
                logger.warning("Spawn para observação anti-hook falhou", exc_info=True)
                app_detection = {
                    "detected": False,
                    "detection_methods_found": [],
                    "strong_signals": [],
                    "weak_signals": [],
                    "app_alive_at_end": True,
                    "error": str(exc),
                }
                checks["hook_libraries"] = self.check_hook_libraries(None, pid=pid)
            else:
                try:
                    app_detection = self.check_hook_detection_in_app(
                        session,
                        on_script_loaded=self.dm.resume_app,
                        window=window,
                        pid=pid,
                        package_name=package_name,
                        logcat_mark=logcat_mark,
                    )
                finally:
                    # App está vivo (ou morreu) — enumera libs de hooking do
                    # processo antes de soltar a sessão. Sessão degradada
                    # (timeout de bridge) pode travar a enumeração.
                    if app_detection.get("session_unsafe"):
                        checks["hook_libraries"] = {
                            "detected": False,
                            "evidence": [],
                            "source": None,
                            "details": "enumeração pulada: sessão Frida degradada",
                            "skipped": True,
                        }
                    else:
                        checks["hook_libraries"] = self.check_hook_libraries(session, pid=pid)
                    safe_detach(session)

        protection_detected = bool(static.get("static_detected")) or bool(
            app_detection.get("detected")
        )

        phase_errors: List[str] = []
        if app_detection.get("error") and not protection_detected:
            # Sem sinal estático e sem observação: não dá para afirmar
            # ausência de proteção — o check não pôde concluir.
            phase_errors.append(str(app_detection["error"]))

        bypass_details: Optional[dict] = None
        bypass_successful: Optional[bool] = None
        bypass_skipped_reason: Optional[str] = None
        if self.mode == "detect":
            bypass_skipped_reason = "modo detect: bypass não executado"
        elif self.no_java:
            bypass_skipped_reason = "--no-java: hooks Java necessários ao bypass"
        elif protection_detected:
            if precomputed_bypass is not None:
                bypass_details = precomputed_bypass
            else:
                bypass_details = self.attempt_bypass(package_name, window=window)
            if bypass_details.get("blocked"):
                # O app bloqueou o bypass: a proteção resistiu. Isso é uma
                # conclusão sobre a proteção, não uma etapa que não rodou.
                bypass_successful = False
            elif bypass_details.get("error"):
                # A proteção foi detectada, mas o bypass não pôde ser
                # avaliado. Isso é uma etapa que não rodou, não uma
                # conclusão sobre a proteção: o veredito da detecção
                # continua válido.
                bypass_skipped_reason = f"bypass: {bypass_details['error']}"
            else:
                bypass_successful = bool(bypass_details.get("success"))

        result: dict = {
            "protection_detected": protection_detected,
            "bypass_successful": bypass_successful,
            "hook_frameworks_present": any(
                c.get("detected") for c in checks.values()
            ),
            "checks": checks,
            "static_detection": static,
            "app_detection": app_detection,
            "bypass_details": bypass_details,
            "bypass_skipped_reason": bypass_skipped_reason,
            "timestamp": _now_iso(),
        }
        if phase_errors:
            result["error"] = "; ".join(phase_errors)

        logger.info(
            "Anti-Hooking: protection_detected=%s bypass_successful=%s frameworks=%s",
            protection_detected, bypass_successful, result["hook_frameworks_present"],
        )
        return result
