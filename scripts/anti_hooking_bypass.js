/*
 * RASPilot — Anti-Hooking Bypass (script injetado via Frida).
 *
 * Neutraliza as checagens anti-hook do app alvo para provar que a
 * proteção contra frameworks de hooking pode ser contornada:
 *   - Class.forName/ClassLoader.loadClass de classes Xposed/LSPlant
 *     retornam null / ClassNotFoundException.
 *   - File.exists e File.list/listFiles escondem paths e entradas de
 *     frameworks (frida-server, xposed, lsposed, substrate...).
 *   - Runtime.exec e ProcessBuilder.start bloqueiam comandos que citam
 *     frameworks de hooking.
 *   - Stack traces (Throwable/Thread.getStackTrace) têm frames de
 *     frameworks removidos (detecção clássica de Xposed).
 *   - strstr/strcmp/strcasestr/memcmp em libc escondem as strings dos
 *     frameworks.
 *   - open/openat/fopen/access/stat de paths de frameworks retornam
 *     ENOENT/NULL.
 *   - O filtro de /proc (maps, TracerPid, /proc/net/tcp e comm de
 *     threads) vive em scripts/proc_filter.js, carregado junto.
 *
 * O script é idempotente e cada bloco é isolado em try/catch para
 * funcionar em múltiplas versões do Android/ART.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// Strings que apps anti-hook procuram (frameworks + instrumentação).
var HOOK_KEYWORDS = [
    'frida', 'xposed', 'lsposed', 'lspd', 'edxposed', 'substrate',
    'sandhook', 'yahfa', 'lsplant', 'whale', 'dobby', 'riru', 'zygisk',
    'gadget', 'gum-js', 'linjector', 'andhook', 'shadowhook'
];

// Paths exatos adicionais (além do matcher por palavra-chave).
var HOOK_PATHS = [
    '/data/local/tmp/frida-server',
    '/data/local/tmp/re.frida.server',
    '/data/local/tmp/frida',
    'frida-server',
    're.frida.server'
];

// Envia log para o host (visível em bypass_logs do relatório).
function report(msg) {
    try {
        send({ type: 'raspilot-hooking-bypass', message: msg });
    } catch (e) { /* host indisponível — ignora */ }
}

function matchesHookFramework(str) {
    try {
        if (str === null || str === undefined) { return false; }
        var lower = ('' + str).toLowerCase();
        for (var i = 0; i < HOOK_KEYWORDS.length; i++) {
            if (lower.indexOf(HOOK_KEYWORDS[i]) !== -1) { return true; }
        }
        if (HOOK_PATHS.indexOf(lower) !== -1) { return true; }
    } catch (e) { /* best-effort */ }
    return false;
}

// 'block' (path de framework → ENOENT) | null.
// O filtro de /proc (maps/status/net/comm) vive em proc_filter.js.
function classifyPath(path) {
    try {
        if (matchesHookFramework('' + path)) { return 'block'; }
    } catch (e) { /* best-effort */ }
    return null;
}

// Define errno do bionic (best-effort) para simular ENOENT.
function setErrno(value) {
    try {
        var errnoFn = raspilotFindExport('libc.so', '__errno');
        if (errnoFn !== null) {
            var getErrno = new NativeFunction(errnoFn, 'pointer', []);
            getErrno().writeS32(value);
        }
    } catch (e) { /* best-effort */ }
}

// ----------------------------------------------------------------------
// 1) Java — Class.forName / ClassLoader.loadClass
// ----------------------------------------------------------------------
function hookClassLookups() {
    try {
        var Class = Java.use('java.lang.Class');
        var forName1 = Class.forName.overload('java.lang.String');
        forName1.implementation = function (name) {
            try {
                if (matchesHookFramework(name)) {
                    report("neutralizado: Class.forName('" + name + "') -> null");
                    return null;
                }
            } catch (e) { /* best-effort */ }
            return forName1.call(this, name);
        };
    } catch (e) {
        report('falha ao hookar Class.forName(String): ' + e);
    }

    try {
        var ClassCl = Java.use('java.lang.Class');
        var forName3 = ClassCl.forName.overload(
            'java.lang.String', 'boolean', 'java.lang.ClassLoader'
        );
        forName3.implementation = function (name, initialize, loader) {
            try {
                if (matchesHookFramework(name)) {
                    report("neutralizado: Class.forName('" + name + "', ...) -> null");
                    return null;
                }
            } catch (e) { /* best-effort */ }
            return forName3.call(this, name, initialize, loader);
        };
    } catch (e) {
        report('falha ao hookar Class.forName(String, boolean, ClassLoader): ' + e);
    }

    try {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        var CNFE = Java.use('java.lang.ClassNotFoundException');
        ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
            var shouldThrow = false;
            try { shouldThrow = matchesHookFramework(name); } catch (e) { shouldThrow = false; }
            if (shouldThrow) {
                report("neutralizado: ClassLoader.loadClass('" + name + "') -> ClassNotFoundException");
                throw CNFE.$new('' + name);
            }
            return this.loadClass(name);
        };
    } catch (e) {
        report('falha ao hookar ClassLoader.loadClass: ' + e);
    }
}

// ----------------------------------------------------------------------
// 2) Java — File.exists / list / listFiles
// ----------------------------------------------------------------------
function hookFileChecks() {
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = '' + this.getAbsolutePath();
            try {
                if (matchesHookFramework(path)) {
                    report('neutralizado: File.exists(' + path + ') -> false');
                    return false;
                }
            } catch (e) { /* best-effort */ }
            return this.exists();
        };
        report('File.exists hookado');
    } catch (e) {
        report('falha ao hookar File.exists: ' + e);
    }

    try {
        var FileList = Java.use('java.io.File');
        FileList.list.overload().implementation = function () {
            var orig = this.list();
            try {
                if (orig === null) { return orig; }
                var dir = '' + this.getAbsolutePath();
                var kept = [];
                var removed = 0;
                for (var i = 0; i < orig.length; i++) {
                    var entry = '' + orig[i];
                    if (matchesHookFramework(entry)) { removed++; continue; }
                    kept.push(entry);
                }
                if (removed > 0) {
                    report('neutralizado: File.list(' + dir + ') -> ' + removed +
                           ' entrada(s) removida(s)');
                    return Java.array('java.lang.String', kept);
                }
            } catch (e) { /* best-effort */ }
            return orig;
        };
        report('File.list hookado');
    } catch (e) {
        report('falha ao hookar File.list: ' + e);
    }

    try {
        var FileListFiles = Java.use('java.io.File');
        FileListFiles.listFiles.overload().implementation = function () {
            var orig = this.listFiles();
            try {
                if (orig === null) { return orig; }
                var dir = '' + this.getAbsolutePath();
                var kept = [];
                var removed = 0;
                for (var i = 0; i < orig.length; i++) {
                    var entry = '' + orig[i].getName();
                    if (matchesHookFramework(entry)) { removed++; continue; }
                    kept.push(orig[i]);
                }
                if (removed > 0) {
                    report('neutralizado: File.listFiles(' + dir + ') -> ' + removed +
                           ' entrada(s) removida(s)');
                    return Java.array('java.io.File', kept);
                }
            } catch (e) { /* best-effort */ }
            return orig;
        };
        report('File.listFiles hookado');
    } catch (e) {
        report('falha ao hookar File.listFiles: ' + e);
    }
}

// ----------------------------------------------------------------------
// 3) Java — Runtime.exec / ProcessBuilder.start
// ----------------------------------------------------------------------
function hookRuntimeExec() {
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var IOE = Java.use('java.io.IOException');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            var blocked = false;
            try { blocked = matchesHookFramework(cmd); } catch (e) { blocked = false; }
            if (blocked) {
                report('bloqueado: Runtime.exec(' + cmd + ')');
                throw IOE.$new('Command blocked by RASPilot');
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArr) {
            var joined = '';
            try { joined = cmdArr.join(' '); } catch (e) { joined = '' + cmdArr; }
            var blocked = false;
            try { blocked = matchesHookFramework(joined); } catch (e) { blocked = false; }
            if (blocked) {
                report('bloqueado: Runtime.exec[](' + joined + ')');
                throw IOE.$new('Command blocked by RASPilot');
            }
            return this.exec(cmdArr);
        };
        report('Runtime.exec hookado');
    } catch (e) {
        report('falha ao hookar Runtime.exec: ' + e);
    }

    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        var IOE2 = Java.use('java.io.IOException');
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command();
            var joined = '';
            try { joined = cmd.toArray().join(' '); } catch (e) { joined = '' + cmd; }
            var blocked = false;
            try { blocked = matchesHookFramework(joined); } catch (e) { blocked = false; }
            if (blocked) {
                report('bloqueado: ProcessBuilder.start(' + joined + ')');
                throw IOE2.$new('Command blocked by RASPilot');
            }
            return this.start();
        };
        report('ProcessBuilder.start hookado');
    } catch (e) {
        report('falha ao hookar ProcessBuilder.start: ' + e);
    }
}

// ----------------------------------------------------------------------
// 4) Java — stack traces sem frames de frameworks
// ----------------------------------------------------------------------
function filterFrames(frames, source) {
    try {
        if (frames === null || frames === undefined) { return frames; }
        var kept = [];
        var removed = 0;
        for (var i = 0; i < frames.length; i++) {
            var className = '' + frames[i].getClassName();
            if (matchesHookFramework(className)) { removed++; continue; }
            kept.push(frames[i]);
        }
        if (removed > 0) {
            report('neutralizado: ' + source + ' -> ' + removed +
                   ' frame(s) de hook removido(s)');
            return Java.array('java.lang.StackTraceElement', kept);
        }
    } catch (e) { /* best-effort */ }
    return frames;
}

function hookStackTrace() {
    try {
        var Throwable = Java.use('java.lang.Throwable');
        Throwable.getStackTrace.implementation = function () {
            return filterFrames(this.getStackTrace(), 'Throwable.getStackTrace');
        };
        report('Throwable.getStackTrace hookado');
    } catch (e) {
        report('falha ao hookar Throwable.getStackTrace: ' + e);
    }

    try {
        var Thread = Java.use('java.lang.Thread');
        Thread.getStackTrace.implementation = function () {
            return filterFrames(this.getStackTrace(), 'Thread.getStackTrace');
        };
        report('Thread.getStackTrace hookado');
    } catch (e) {
        report('falha ao hookar Thread.getStackTrace: ' + e);
    }
}

// ----------------------------------------------------------------------
// 5) Native — libc: strstr / strcmp / strcasestr / memcmp
// ----------------------------------------------------------------------
function hookLibcStringHooks() {
    ['strstr', 'strcmp', 'strcasestr'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._hide = false;
                    try {
                        var a = args[0].readCString();
                        var b = args[1].readCString();
                        if (matchesHookFramework(a) || matchesHookFramework(b)) {
                            this._hide = true;
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (!this._hide) { return; }
                    if (name === 'strstr' || name === 'strcasestr') {
                        retval.replace(ptr(0)); // não encontrado
                    } else {
                        retval.replace(ptr(1)); // "diferente"
                    }
                    report('neutralizado: libc.' + name + ' -> string de framework oculta');
                }
            });
            report('libc.' + name + ' hookado');
        } catch (e) {
            report('falha ao hookar libc.' + name + ': ' + e);
        }
    });

    try {
        var memcmpAddr = raspilotFindExport('libc.so', 'memcmp');
        if (memcmpAddr !== null) {
            Interceptor.attach(memcmpAddr, {
                onEnter: function (args) {
                    this._hide = false;
                    try {
                        var n = args[2].toInt32();
                        if (n > 0 && n < 4096) {
                            var bytes = new Uint8Array(args[0].readByteArray(n));
                            var s = '';
                            for (var i = 0; i < bytes.length; i++) {
                                var c = bytes[i];
                                s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ' ';
                            }
                            if (matchesHookFramework(s)) { this._hide = true; }
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (this._hide) {
                        retval.replace(ptr(1)); // buffers diferentes
                        report('neutralizado: libc.memcmp -> buffers considerados diferentes');
                    }
                }
            });
            report('libc.memcmp hookado');
        }
    } catch (e) {
        report('falha ao hookar libc.memcmp: ' + e);
    }
}

// ----------------------------------------------------------------------
// 6) Native — paths: bloqueio de frameworks + rastreio de /proc
// ----------------------------------------------------------------------
function hookOpenFamily() {
    ['open', 'openat', 'openat64'].forEach(function (name) {
        var pathIndex = (name === 'open') ? 0 : 1;
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._block = false;
                    this._path = '';
                    try {
                        var path = args[pathIndex].readCString();
                        this._path = path;
                        if (classifyPath(path) === 'block') { this._block = true; }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (this._block) {
                        setErrno(2); // ENOENT
                        retval.replace(ptr(-1));
                        report('neutralizado: ' + name + '(' + this._path + ') -> ENOENT');
                    }
                }
            });
            report('libc.' + name + ' hookado');
        } catch (e) {
            report('falha ao hookar ' + name + ': ' + e);
        }
    });
}

function hookFopenFamily() {
    ['fopen', 'fopen64'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._block = false;
                    this._path = '';
                    try {
                        var path = args[0].readCString();
                        this._path = path;
                        if (classifyPath(path) === 'block') { this._block = true; }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (this._block) {
                        setErrno(2); // ENOENT
                        retval.replace(ptr(0)); // NULL
                        report('neutralizado: ' + name + '(' + this._path + ') -> ENOENT');
                    }
                }
            });
            report('libc.' + name + ' hookado');
        } catch (e) {
            report('falha ao hookar ' + name + ': ' + e);
        }
    });
}

function hookAccessStatFamily() {
    ['access', 'stat', 'stat64', 'lstat', 'lstat64', 'faccessat', 'faccessat2'].forEach(
        function (name) {
            try {
                var addr = raspilotFindExport('libc.so', name);
                if (addr === null) { return; }
                var pathIndex = (name === 'faccessat' || name === 'faccessat2') ? 1 : 0;
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        this._block = false;
                        this._path = '';
                        try {
                            var path = args[pathIndex].readCString();
                            this._path = path;
                            if (classifyPath(path) === 'block') { this._block = true; }
                        } catch (e) { /* best-effort */ }
                    },
                    onLeave: function (retval) {
                        if (this._block) {
                            setErrno(2); // ENOENT
                            retval.replace(ptr(-1));
                            report('neutralizado: ' + name + '(' + this._path + ') -> ENOENT');
                        }
                    }
                });
                report('libc.' + name + ' hookado');
            } catch (e) {
                report('falha ao hookar ' + name + ': ' + e);
            }
        }
    );
}

// ----------------------------------------------------------------------
// 7) Native — filtro de conteúdo de /proc (maps e TracerPid)
// ----------------------------------------------------------------------
// ----------------------------------------------------------------------
// Bootstrap — idempotente
// ----------------------------------------------------------------------
function main() {
    hookLibcStringHooks();
    hookOpenFamily();
    hookFopenFamily();
    hookAccessStatFamily();

    var attachJava = function () {
        var ok = raspilotPerformJava(function () {
            hookClassLookups();
            hookFileChecks();
            hookRuntimeExec();
            hookStackTrace();
        });
        if (!ok) {
            report('Java indisponível — hooks Java pulados');
        }
    };
    attachJava();

    report('anti_hooking_bypass.js carregado');
}

setImmediate(main);
