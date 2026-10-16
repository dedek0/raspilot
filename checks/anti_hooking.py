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
from script_loader import (
    enumerate_module_names,
    load_script,
    load_script_file,
    safe_unload,
)

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_hooking")

# Caminho do script de bypass relativo à raiz do projeto.
HOOK_BYPASS_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "anti_hooking_bypass.js"
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

# Prioridade do tipo principal quando há várias assinaturas no APK.
STATIC_PRIORITY = ["xposed", "lsposed", "edxposed", "substrate", "inline_hook", "frida"]

# Métodos de observação considerados sinais FRACOS: leitura de
# /proc/.../maps e /proc/.../status também tem uso legítimo (profiling,
# crash handlers), então sozinhos não comprovam proteção anti-hook.
WEAK_DETECTION_METHODS = ("maps_scan", "status_scan")

# Trechos de log do anti_hooking_bypass.js que comprovam que uma checagem
# anti-hook foi neutralizada em runtime (diferente de mero "hook instalado").
BYPASS_EVIDENCE_MARKERS = ("neutralizado", "bloqueado", "removido")

# Script de OBSERVAÇÃO (não bypass): registra as checagens anti-hook que o
# app executa (Class.forName de classes Xposed, File.exists em paths de
# frameworks, Runtime.exec com 'frida', buscas nativas strstr/strcmp por
# strings de frameworks, abertura de /proc/self/maps e stack traces com
# frames Xposed) e as envia ao host via send().
HOOK_DETECTION_SCRIPT = """
'use strict';

// Palavras-chave de frameworks de hooking que apps anti-hook procuram
// (em classes, paths, comandos e buscas nativas).
var HOOK_KEYWORDS = [
    'frida', 'xposed', 'lsposed', 'lspd', 'edxposed', 'substrate',
    'sandhook', 'yahfa', 'lsplant', 'whale', 'dobby', 'riru', 'zygisk',
    'gadget', 'gum-js', 'linjector', 'andhook', 'shadowhook'
];

function matchesHookFramework(str) {
    try {
        if (str === null || str === undefined) { return false; }
        var lower = ('' + str).toLowerCase();
        for (var i = 0; i < HOOK_KEYWORDS.length; i++) {
            if (lower.indexOf(HOOK_KEYWORDS[i]) !== -1) { return true; }
        }
    } catch (e) { /* best-effort */ }
    return false;
}

// /proc/<pid>/maps e /proc/<pid>/status: varredura de libs injetadas e
// leitura de TracerPid. Retorna o nome do método fraco ou null.
function procProbe(path) {
    try {
        var p = '' + path;
        if (p.indexOf('/proc/') !== 0) { return null; }
        if (p.indexOf('maps') !== -1) { return 'maps_scan'; }
        if (p.indexOf('status') !== -1) { return 'status_scan'; }
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
    try {
        var Class = Java.use('java.lang.Class');
        var forName1 = Class.forName.overload('java.lang.String');
        forName1.implementation = function (name) {
            try {
                if (matchesHookFramework(name)) { report('Class.forName', '' + name); }
            } catch (e) { /* best-effort */ }
            return forName1.call(this, name);
        };
    } catch (e) { /* Java indisponível */ }

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

if (typeof raspilotPerformJava === 'function') {
    raspilotPerformJava(installJavaHooks);
} else if (typeof Java !== 'undefined' && Java.available) {
    Java.perform(installJavaHooks);
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

    def __init__(self, dm: "DeviceManager") -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
        """
        self.dm = dm

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
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

        Returns:
            Dict com ``detected`` (bool), ``detection_methods_found``,
            ``strong_signals``, ``weak_signals`` e ``app_alive_at_end``.
        """
        found: List[str] = []
        strong: List[str] = []
        weak: List[str] = []
        script = None
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
                if payload.get("type") != "hook-detection":
                    return
                add_signal(payload.get("method", "?"), payload.get("detail", ""))
            elif message.get("type") == "error":
                logger.debug("Erro no script anti-hook: %s", message.get("description"))

        try:
            script = load_script(
                session, HOOK_DETECTION_SCRIPT, on_message=on_message,
                name="raspilot-hook-detect",
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
            logger.warning("Falha ao observar checagens anti-hook no app", exc_info=True)
            return {
                "detected": False,
                "detection_methods_found": [],
                "strong_signals": [],
                "weak_signals": [],
                "app_alive_at_end": True,
                "error": str(exc),
            }
        finally:
            safe_unload(script)
            if not resumed and on_script_loaded is not None:
                # Garante que um spawn suspenso nunca fique travado.
                try:
                    on_script_loaded()
                except Exception:
                    logger.debug("Falha no resume de emergência", exc_info=True)

        app_alive = died_after is None
        if not app_alive:
            add_signal(
                "app_terminated",
                f"processo encerrou ~{died_after}s após resume (reação do RASP)",
            )

        detected = bool(strong)
        result = {
            "detected": detected,
            "detection_methods_found": found,
            "strong_signals": strong,
            "weak_signals": weak,
            "app_alive_at_end": app_alive,
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
        logger.info(
            "check_hook_detection_in_app: detected=%s strong=%s weak=%s",
            detected, len(strong), len(weak),
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
        session = None
        script = None
        died_after: Optional[int] = None

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("type") != "raspilot-hooking-bypass":
                    return
                msg = payload.get("message", "")
                if msg and msg not in bypass_logs:
                    bypass_logs.append(msg)
            elif message.get("type") == "error":
                desc = message.get("description", "")
                if desc:
                    bypass_logs.append(f"[script-error] {desc}")

        try:
            # Spawn suspenso: instala os hooks ANTES do app rodar, para
            # não perder as checagens anti-hook da inicialização.
            session = self.dm.spawn_app(package_name, resume=False)
            script = load_script_file(
                session, HOOK_BYPASS_SCRIPT, on_message=on_message
            )
            self.dm.resume_app()
            pid = self.dm.last_spawn_pid or self.dm.get_app_pid(package_name)
            for elapsed in range(max(1, int(window))):
                time.sleep(1)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante o bypass anti-hook (~%ss)",
                        pid, died_after,
                    )
                    break
        except Exception as exc:
            logger.warning("Bypass anti-hook falhou", exc_info=True)
            return {
                "success": False,
                "bypass_logs": bypass_logs,
                "effective_logs": [],
                "app_alive_at_end": True,
                "error": str(exc),
            }
        finally:
            safe_unload(script)
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    logger.debug("Falha ao detach da sessão", exc_info=True)

        if died_after is not None:
            bypass_logs.append(
                f"app_terminated: processo encerrou ~{died_after}s após resume"
            )

        # Evidência real: logs que comprovam checagem neutralizada.
        effective = [
            log for log in bypass_logs
            if any(marker in log for marker in BYPASS_EVIDENCE_MARKERS)
        ]
        alive = died_after is None
        success = bool(effective) and alive

        result = {
            "success": success,
            "bypass_logs": bypass_logs,
            "effective_logs": effective,
            "app_alive_at_end": alive,
            "error": None,
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
        self, package_name: str, window: int = 12, apk_path: Optional[str] = None
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

        # Fase dinâmica: spawn suspenso + script de observação.
        session = None
        pid: Optional[int] = None
        app_detection: dict
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
                )
            finally:
                # App está vivo (ou morreu) — enumera libs de hooking do
                # processo antes de soltar a sessão.
                checks["hook_libraries"] = self.check_hook_libraries(session, pid=pid)
                try:
                    session.detach()
                except Exception:
                    logger.debug("Falha ao detach da sessão", exc_info=True)

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
        if protection_detected:
            bypass_details = self.attempt_bypass(package_name, window=window)
            if bypass_details.get("error"):
                phase_errors.append(f"bypass: {bypass_details['error']}")
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
            "timestamp": _now_iso(),
        }
        if phase_errors:
            result["error"] = "; ".join(phase_errors)

        logger.info(
            "Anti-Hooking: protection_detected=%s bypass_successful=%s frameworks=%s",
            protection_detected, bypass_successful, result["hook_frameworks_present"],
        )
        return result
