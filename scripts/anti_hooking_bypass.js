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

// true = apenas hooks Java (após resume); false = apenas nativos
// (antes do resume, sem bridge Java).
var RASPILOT_JAVA_ONLY = (typeof __RASPILOT_JAVA_ONLY__ !== 'undefined')
    ? __RASPILOT_JAVA_ONLY__
    : false;

// Strings que apps anti-hook procuram (frameworks + instrumentação).
//
// A lista é separada em duas tieres de propósito. A busca por strings é
// um gancho global: qualquer strstr/strcmp do app passa por ela. Um
// termo que também é palavra comum em português e inglês ("gadget",
// "whale", "epic") transformaria uma busca legítima do app em
// detecção de hooking — e faria o bypass bloquear o app sem motivo.
//
// O tier forte é o que identifica um framework sem ambiguidade.
var HOOK_KEYWORDS = [
    'de.robv.android.xposed', 'xposedbridge', 'xposed.bridge',
    'lsposed', 'lspd', 'edxposed', 'epic.xposed',
    'cydia.substrate', 'com.saurik.substrate',
    'sandhook', 'yahfa', 'lsplant', 'dobby', 'riru', 'zygisk',
    'frida', 'libfrida', 'gum-js', 'linjector', 'andhook', 'shadowhook',
    'libloader64_v8', 'libloader32_v7'
];

// Termos ambíguos: usados apenas na verificação de caminhos e nomes de
// arquivo, onde a chance de colisão é baixa e o custo de deixar passar
// é maior que o de bloquear indevidamente.
var HOOK_PATH_KEYWORDS = [
    'xposed', 'whale', 'epic', 'gadget', 'sandhook', 'shadowhook'
];

// Paths exatos adicionais (além do matcher por palavra-chave).
var HOOK_PATHS = [
    '/data/local/tmp/frida-server',
    '/data/local/tmp/re.frida.server',
    '/data/local/tmp/frida',
    'frida-server',
    're.frida.server'
];

// Casa um termo como TOKEN, e não como substring solta.
//
// A comparação por substring transformava qualquer acesso do app a um
// arquivo próprio em "ocultação de framework" quando o nome do pacote
// continha o termo — e o bypass passava a esconder arquivos legítimos
// do app. A fronteira exige que o termo esteja isolado por caracteres
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

// Envia log para o host (visível em bypass_logs do relatório).
function report(msg) {
    try {
        send({ type: 'raspilot-hooking-bypass', message: msg });
    } catch (e) { /* host indisponível — ignora */ }
}

// Evidência de bypass: a checagem do app foi de fato exercitada e o
// resultado foi neutralizado. Difere do simples "hook instalado", que
// apenas indica que a instrumentação está ativa.
function reportEvidence(msg) {
    try {
        send({ type: 'bypass-evidence', message: msg });
    } catch (e) { /* host indisponível — ignora */ }
}

// Exceção de "classe não encontrada" usada para simular a ausência de
// um framework de hooking.
//
// A marca própria permite distinguir a exceção que o script lançou de
// uma exceção qualquer surgida no gancho — no primeiro caso a
// substituição deve ser re-lançada ao app, no segundo o gancho deve
// apenas seguir em silêncio.
function notFoundException(className) {
    var exc = null;
    try {
        var CNFE = Java.use('java.lang.ClassNotFoundException');
        exc = CNFE.$new('' + className);
    } catch (e) {
        exc = new Error('' + className);
    }
    try {
        exc.__raspilot = true;
    } catch (e) { /* best-effort */ }
    return exc;
}

// Verifica se um caminho/nome de arquivo referencia um framework.
function matchesHookPath(str) {
    try {
        if (str === null || str === undefined) { return false; }
        var lower = ('' + str).toLowerCase();
        if (matchesHookFramework(lower)) { return true; }
        for (var i = 0; i < HOOK_PATH_KEYWORDS.length; i++) {
            if (containsToken(lower, HOOK_PATH_KEYWORDS[i])) { return true; }
        }
        return false;
    } catch (e) { return false; }
}

function matchesHookFramework(str) {
    try {
        if (str === null || str === undefined) { return false; }
        var lower = ('' + str).toLowerCase();
        for (var i = 0; i < HOOK_KEYWORDS.length; i++) {
            if (containsToken(lower, HOOK_KEYWORDS[i])) { return true; }
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
    // A sobrecarga de um argumento de Class.forName NÃO é hookada.
    //
    // ART resolve o nome da classe com o class loader de quem chamou.
    // Invocar o original através do Frida faz o ART inferir o caller a
    // partir do frame do agente em vez do frame do app — e a classe
    // passa a ser procurada no boot class loader. O app então recebe
    // ClassNotFoundException para classes legítimas, e apps que usam um
    // class loader próprio (packers, plugins) quebram na inicialização.
    //
    // A sobrecarga de três argumentos preserva a semântica (o loader
    // chega explícito) e continua interceptando a de um argumento, que
    // delega para ela.
    try {
        var ClassCl = Java.use('java.lang.Class');
        var forName3 = ClassCl.forName.overload(
            'java.lang.String', 'boolean', 'java.lang.ClassLoader'
        );
        forName3.implementation = function (name, initialize, loader) {
            try {
                if (matchesHookFramework(name)) {
                    reportEvidence("neutralizado: Class.forName('" + name +
                        "', ...) -> ClassNotFoundException");
                    throw notFoundException(name);
                }
            } catch (e) {
                if (e && e.__raspilot) { throw e; }
            }
            return forName3.call(this, name, initialize, loader);
        };
    } catch (e) {
        report('falha ao hookar Class.forName(String, boolean, ClassLoader): ' + e);
    }

    try {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        var loadClass = ClassLoader.loadClass.overload('java.lang.String');
        var CNFE = Java.use('java.lang.ClassNotFoundException');
        loadClass.implementation = function (name) {
            var shouldThrow = false;
            try { shouldThrow = matchesHookFramework(name); } catch (e) { shouldThrow = false; }
            if (shouldThrow) {
                reportEvidence("neutralizado: ClassLoader.loadClass('" + name + "') -> ClassNotFoundException");
                throw CNFE.$new('' + name);
            }
            // Chama a implementação original da classe base: a
            // delegação para o parent e a resolução via findClass
            // continuam sendo feitas pelo ART.
            return loadClass.call(this, name);
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
                if (matchesHookPath(path)) {
                    reportEvidence('neutralizado: File.exists(' + path + ') -> false');
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
                    if (matchesHookPath(entry)) { removed++; continue; }
                    kept.push(entry);
                }
                if (removed > 0) {
                    reportEvidence('neutralizado: File.list(' + dir + ') -> ' + removed +
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
                    if (matchesHookPath(entry)) { removed++; continue; }
                    kept.push(orig[i]);
                }
                if (removed > 0) {
                    reportEvidence('neutralizado: File.listFiles(' + dir + ') -> ' + removed +
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
            reportEvidence('neutralizado: ' + source + ' -> ' + removed +
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
// 5) Native — libc: strstr / strcasestr / memcmp
// ----------------------------------------------------------------------
//
// strcmp é deixado de fora de propósito: ele é chamado dezenas de
// milhares de vezes por segundo pelo runtime do app e pelo motor
// JavaScript do próprio agente. Um gancho nesse ponto consome o tempo
// do agente de instrumentação, que deixa de responder — e o sintoma é
// uma sessão que trava sem erro.
//
// A comparação de nomes exatos continua coberta em outro nível: a
// camada Java devolve "classe inexistente" para os frameworks de
// hooking, e o /proc do processo não mostra nenhum deles.

// Busca por palavra-chave diretamente nos bytes do buffer.
//
// Evita materializar a string caractere a caractere: em função muito
// chamada o custo quadrático dessa conversão é o que trava o app.
function bytesContainKeyword(buffer, keywords) {
    if (buffer === null || buffer === undefined) { return false; }
    var bytes = new Uint8Array(buffer);
    var lower = [];
    for (var i = 0; i < bytes.length; i++) {
        var c = bytes[i];
        lower[i] = (c >= 65 && c <= 90) ? (c + 32) : c;
    }
    for (var k = 0; k < keywords.length; k++) {
        var needle = keywords[k];
        var limit = lower.length - needle.length;
        for (var p = 0; p <= limit; p++) {
            var match = true;
            for (var j = 0; j < needle.length; j++) {
                if (lower[p + j] !== needle.charCodeAt(j)) {
                    match = false;
                    break;
                }
            }
            if (!match) { continue; }
            // Fronteira de token: o byte anterior e o byte posterior
            // precisam ser não alfanuméricos, senão "fridaplayer" casaria
            // com "frida".
            var before = p === 0 ? 0 : lower[p - 1];
            var after = (p + needle.length < lower.length) ? lower[p + needle.length] : 0;
            if (isTokenByte(before) && isTokenByte(after)) { return true; }
        }
    }
    return false;
}

// Um byte é fronteira de token quando não é alfanumérico.
function isTokenByte(c) {
    if (c === 0) { return true; }
    var lower = (c >= 65 && c <= 90) ? (c + 32) : c;
    return !((lower >= 97 && lower <= 122) || (lower >= 48 && lower <= 57));
}

// Busca por palavra-chave numa string.
function containsKeyword(cstr, keywords) {
    if (cstr === null || cstr === undefined) { return false; }
    var lower = ('' + cstr).toLowerCase();
    for (var i = 0; i < keywords.length; i++) {
        if (containsToken(lower, keywords[i])) { return true; }
    }
    return false;
}

function hookLibcStringHooks() {
    ['strstr', 'strcasestr'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._hide = false;
                    try {
                        // strstr(haystack, needle): o que interessa é o
                        // needle — é o nome que o app procura. Esconder
                        // o haystack quebraria buscas legítimas do app
                        // por um termo qualquer.
                        var b = args[1].readCString();
                        if (containsKeyword(b, HOOK_KEYWORDS)) {
                            this._hide = true;
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (!this._hide) { return; }
                    retval.replace(ptr(0)); // não encontrado
                    reportEvidence('neutralizado: libc.' + name + ' -> string de framework oculta');
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
                        // Buffers grandes são o caso comum (comparação de
                        // blocos inteiros) e não é neles que mora o nome
                        // de um framework.
                        if (n > 0 && n <= 64) {
                            if (bytesContainKeyword(args[0].readByteArray(n), HOOK_KEYWORDS) ||
                                    bytesContainKeyword(args[1].readByteArray(n), HOOK_KEYWORDS)) {
                                this._hide = true;
                            }
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (this._hide) {
                        retval.replace(ptr(1)); // buffers diferentes
                        reportEvidence('neutralizado: libc.memcmp -> buffers considerados diferentes');
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
                        reportEvidence('neutralizado: ' + name + '(' + this._path + ') -> ENOENT');
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
                        reportEvidence('neutralizado: ' + name + '(' + this._path + ') -> ENOENT');
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
                            reportEvidence('neutralizado: ' + name + '(' + this._path + ') -> ENOENT');
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
    if (!RASPILOT_JAVA_ONLY) {
        hookLibcStringHooks();
        hookOpenFamily();
        hookFopenFamily();
        hookAccessStatFamily();
    }

    var attachJava = function () {
        // A instalação Java é adiada: o carregamento do script precisa
        // retornar antes que o agente limite o tempo de carga.
        raspilotDeferJava(function () {
            hookClassLookups();
            hookFileChecks();
            hookRuntimeExec();
            hookStackTrace();
        }, 'anti-hooking-bypass');
    };
    attachJava();

    report('anti_hooking_bypass.js carregado');
}

main();
