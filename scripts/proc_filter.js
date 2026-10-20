/*
 * RASPilot — Proc Filter (script injetado via Frida).
 *
 * Filtra as leituras de /proc que apps RASP usam para detectar
 * instrumentação, escondendo os artefatos do próprio Frida:
 *   - /proc/.../maps: remove linhas de libs de hook (frida, xposed,
 *     lsposed, gadget, gum-js...)
 *   - /proc/.../status: zera TracerPid (anti-ptrace)
 *   - /proc/net/tcp(6): remove as linhas das portas Frida 27042/27043
 *     (port-scan via /proc, comum em anti-frida)
 *   - /proc/.../task/.../comm e /proc/.../comm: oculta nomes de threads
 *     de hook (ex: gum-js-loop)
 *
 * Implementado via rastreio de fds/FILE* em open/openat/fopen e filtro
 * do conteúdo em read/fgets. Módulo de leitura (não bloqueia paths);
 * o bloqueio de paths de frameworks fica no anti_hooking_bypass.js.
 * É observatório no host: reporta cada neutralização via
 * type 'raspilot-hooking-bypass' (vira evidência de bypass).
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// fd/FILE* abertos de arquivos de /proc tratados (kind: maps|status|net|comm).
var fdKind = {};
var fpKind = {};
var rawFdKind = {};
var SYSCALL_NR = null;
if (Process.arch === 'arm64') {
    SYSCALL_NR = { read: 63, openat: 56, close: 57, readlinkat: 78, ptrace: 117 };
} else if (Process.arch === 'x64') {
    SYSCALL_NR = { read: 0, openat: 257, close: 3, readlinkat: 267, ptrace: 101 };
}

function report(msg) {
    try {
        send({ type: 'raspilot-hooking-bypass', message: msg });
    } catch (e) { /* host indisponível */ }
}

// Evidência de bypass: o app leu o arquivo de /proc e alguma indicação
// de framework foi de fato removida do conteúdo. Uma leitura sem
// qualquer remoção não é evidência de nada.
function reportEvidence(msg) {
    try {
        send({ type: 'bypass-evidence', message: msg });
    } catch (e) { /* host indisponível */ }
}

function setErrno(value) {
    try {
        var errnoFn = raspilotFindExport('libc.so', '__errno');
        if (errnoFn !== null) {
            var getErrno = new NativeFunction(errnoFn, 'pointer', []);
            getErrno().writeS32(value);
        }
    } catch (e) { /* best-effort */ }
}

// Casa um termo como TOKEN, e não como substring solta.
//
// A comparação por substring casava "frida" dentro do nome do pacote
// do próprio app e filtrava o /proc do app como se fosse artefato de
// instrumentação. A fronteira exige que o termo esteja isolado por
// caracteres não alfanuméricos.
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
        var keywords = [
            'frida', 'libfrida', 'xposed', 'lsposed', 'lspd', 'edxposed',
            'substrate', 'sandhook', 'yahfa', 'lsplant', 'whale', 'dobby',
            'riru', 'zygisk', 'gadget', 'gum-js', 'linjector', 'andhook',
            'shadowhook', 'libloader64_v8', 'libloader32_v7'
        ];
        for (var i = 0; i < keywords.length; i++) {
            if (containsToken(lower, keywords[i])) { return true; }
        }
    } catch (e) { /* best-effort */ }
    return false;
}

// 'maps' | 'status' | 'net' | 'comm' | null (não é /proc tratável).
function classifyProcPath(path) {
    try {
        var p = '' + path;
        if (p.indexOf('/proc/') !== 0) { return null; }
        if (p.indexOf('maps') !== -1) { return 'maps'; }
        if (p.indexOf('status') !== -1) { return 'status'; }
        if (p.indexOf('/net/tcp') !== -1) { return 'net'; }
        if (p.indexOf('/comm') !== -1) { return 'comm'; }
    } catch (e) { /* best-effort */ }
    return null;
}

function kindLabel(kind) {
    if (kind === 'maps') { return '/proc/self/maps'; }
    if (kind === 'status') { return '/proc/self/status'; }
    if (kind === 'net') { return '/proc/net/tcp'; }
    return '/proc/.../comm';
}

function strToBytes(s) {
    var bytes = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) {
        bytes[i] = s.charCodeAt(i) & 0xff;
    }
    return bytes;
}

// ----------------------------------------------------------------------
// Filtros de conteúdo
// ----------------------------------------------------------------------
function filterMaps(text) {
    var lines = text.split('\n');
    var kept = [];
    var removed = 0;
    for (var i = 0; i < lines.length; i++) {
        if (lines[i].indexOf('/') !== -1 && matchesHookFramework(lines[i])) {
            removed++;
            continue;
        }
        kept.push(lines[i]);
    }
    return {
        text: kept.join('\n'),
        changed: removed > 0,
        count: removed,
        label: 'linhas de libs de hook removidas'
    };
}

function filterStatus(text) {
    var replaced = 0;
    var out = text.replace(/TracerPid:[ \t]*(\d+)/g, function (match, pid) {
        if (pid !== '0') {
            replaced++;
            return 'TracerPid:\t0';
        }
        return match;
    });
    return {
        text: out,
        changed: replaced > 0,
        count: replaced,
        label: 'TracerPid zerado'
    };
}

// Portas Frida em hex (uppercase) como aparecem em /proc/net/tcp(6).
// Inclui as portas clássicas e a porta stealth configurada no host.
var FRIDA_NET_PORTS = ['69A2', '69A3', '__RASPILOT_FRIDA_PORT_HEX__'];

function filterNetTcp(text) {
    var lines = text.split('\n');
    var kept = [];
    var removed = 0;
    for (var i = 0; i < lines.length; i++) {
        var hide = false;
        for (var p = 0; p < FRIDA_NET_PORTS.length; p++) {
            var port = FRIDA_NET_PORTS[p];
            if (port && lines[i].indexOf(':' + port) !== -1) {
                hide = true;
                break;
            }
        }
        if (hide) {
            removed++;
            continue;
        }
        kept.push(lines[i]);
    }
    return {
        text: kept.join('\n'),
        changed: removed > 0,
        count: removed,
        label: 'portas Frida removidas'
    };
}

// Substitui nome de thread de hook por um nome benigno mais curto/igual
// (o filtro de read/fgets só consegue reescrever para algo menor ou igual).
function filterComm(text) {
    if (matchesHookFramework(text)) {
        var candidates = ['Jit worker', 'pool-1', 'p1', 'x'];
        var replacement = 'x';
        for (var i = 0; i < candidates.length; i++) {
            if (candidates[i].length < text.length) {
                replacement = candidates[i];
                break;
            }
        }
        return {
            text: replacement + '\n',
            changed: true,
            count: 1,
            label: 'nome de thread de hook oculto'
        };
    }
    return { text: text, changed: false, count: 0, label: '' };
}

function filterProc(kind, text) {
    if (kind === 'maps') { return filterMaps(text); }
    if (kind === 'status') { return filterStatus(text); }
    if (kind === 'net') { return filterNetTcp(text); }
    return filterComm(text);
}

// Reencaixa o conteúdo filtrado no tamanho original.
//
// O offset do arquivo no kernel já avançou com a leitura: devolver menos
// bytes do que o app pediu faz o app perder a diferença e enxergar um
// /proc truncado no meio do registro, o que é um sinal de adulteração e
// pode derrubar parsers que dependem da estrutura do arquivo.
//
// O preenchimento é feito com quebras de linha: a contagem de linhas do
// arquivo permanece a mesma e o tamanho devolvido é idêntico ao original.
// O cálculo é feito em bytes, e não em caracteres, para não estourar o
// buffer quando o conteúdo tiver caracteres multibyte.
function padToSize(text, size) {
    var current = strToBytes(text).length;
    if (current >= size) { return null; }
    return text + '\n'.repeat(size - current);
}

// ----------------------------------------------------------------------
// Rastreio de fds/FILE* de /proc
// ----------------------------------------------------------------------
function hookProcOpenFamily() {
    ['open', 'openat', 'openat64'].forEach(function (name) {
        var pathIndex = (name === 'open') ? 0 : 1;
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._kind = null;
                    try {
                        this._kind = classifyProcPath(args[pathIndex].readCString());
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (this._kind === null) { return; }
                    var fd = retval.toInt32();
                    if (fd >= 0) { fdKind[fd] = this._kind; }
                }
            });
        } catch (e) { /* falha silenciosa — outro hook pode cobrir */ }
    });

    ['fopen', 'fopen64'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._kind = null;
                    try {
                        this._kind = classifyProcPath(args[0].readCString());
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (this._kind === null || retval.isNull()) { return; }
                    fpKind[retval.toString()] = this._kind;
                }
            });
        } catch (e) { /* best-effort */ }
    });
}

function hookProcReads() {
    try {
        var readAddr = raspilotFindExport('libc.so', 'read');
        if (readAddr !== null) {
            Interceptor.attach(readAddr, {
                onEnter: function (args) {
                    this._fd = args[0].toInt32();
                    this._buf = args[1];
                    this._kind = fdKind[this._fd] || null;
                },
                onLeave: function (retval) {
                    if (this._kind === null) { return; }
                    var n = retval.toInt32();
                    if (n <= 0) { return; }
                    try {
                        var orig = this._buf.readUtf8String(n);
                        if (orig === null || orig.length === 0) { return; }
                        var res = filterProc(this._kind, orig);
                        if (!res.changed) { return; }
                        // O tamanho devolvido ao app é preservado: só o
                        // conteúdo muda.
                        var text = padToSize(res.text, n);
                        if (text === null) { return; }
                        this._buf.writeByteArray(strToBytes(text));
                        reportEvidence('neutralizado: ' + kindLabel(this._kind) + ' em read() → ' +
                               res.count + ' ' + res.label);
                    } catch (e) { /* best-effort */ }
                }
            });
        }
    } catch (e) { /* best-effort */ }

    try {
        var fgetsAddr = raspilotFindExport('libc.so', 'fgets');
        if (fgetsAddr !== null) {
            Interceptor.attach(fgetsAddr, {
                onEnter: function (args) {
                    this._buf = args[0];
                    this._fp = args[2].toString();
                    this._kind = fpKind[this._fp] || null;
                },
                onLeave: function (retval) {
                    if (this._kind === null || retval.isNull()) { return; }
                    try {
                        var orig = this._buf.readCString();
                        if (orig === null || orig.length === 0) { return; }
                        var res = filterProc(this._kind, orig);
                        if (!res.changed) { return; }
                        // O comprimento devolvido é preservado: o stdio já
                        // avançou no arquivo e devolver menos caracteres
                        // desalinharia as leituras seguintes.
                        var text = padToSize(res.text, orig.length);
                        if (text === null) { return; }
                        this._buf.writeByteArray(strToBytes(text));
                        reportEvidence('neutralizado: ' + kindLabel(this._kind) + ' em fgets() → ' +
                               res.count + ' ' + res.label);
                    } catch (e) { /* best-effort */ }
                }
            });
        }
    } catch (e) { /* best-effort */ }

    // Evita fds obsoletos (reuso de fd após close).
    try {
        var closeAddr = raspilotFindExport('libc.so', 'close');
        if (closeAddr !== null) {
            Interceptor.attach(closeAddr, {
                onEnter: function (args) {
                    try {
                        var fd = args[0].toInt32();
                        if (fdKind[fd] !== undefined) { delete fdKind[fd]; }
                        if (rawFdKind[fd] !== undefined) { delete rawFdKind[fd]; }
                    } catch (e) { /* best-effort */ }
                }
            });
        }
    } catch (e) { /* best-effort */ }

    try {
        var fcloseAddr = raspilotFindExport('libc.so', 'fclose');
        if (fcloseAddr !== null) {
            Interceptor.attach(fcloseAddr, {
                onEnter: function (args) {
                    try {
                        var key = args[0].toString();
                        if (fpKind[key] !== undefined) { delete fpKind[key]; }
                    } catch (e) { /* best-effort */ }
                }
            });
        }
    } catch (e) { /* best-effort */ }
}

function hookThreadNames() {
    try {
        var pthread = raspilotFindExport('libc.so', 'pthread_setname_np');
        if (pthread === null) { return; }
        Interceptor.attach(pthread, {
            onEnter: function (args) {
                try {
                    var name = args[1].readCString();
                    if (matchesHookFramework(name)) {
                        // Nome benigno mais curto que o original (buffer seguro).
                        args[1].writeUtf8String('Jit worker');
                        reportEvidence('neutralizado: pthread_setname_np(' + name + ') oculto');
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { /* best-effort */ }
}

function hookReadlinkFamily() {
    ['readlink', 'readlinkat'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            var pathIndex = (name === 'readlinkat') ? 1 : 0;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._block = false;
                    this._path = '';
                    try {
                        var path = args[pathIndex].readCString();
                        this._path = path;
                        if (matchesHookFramework(path)) { this._block = true; }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (this._block) {
                        setErrno(2);
                        retval.replace(ptr(-1));
                        reportEvidence('neutralizado: ' + name + '(' + this._path + ') -> ENOENT');
                    }
                }
            });
        } catch (e) { /* best-effort */ }
    });
}

function hookPtrace() {
    try {
        var addr = raspilotFindExport('libc.so', 'ptrace');
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this._traced = false;
                try {
                    if (args[0].toInt32() === 0) { // PTRACE_TRACEME
                        this._traced = true;
                    }
                } catch (e) { /* best-effort */ }
            },
            onLeave: function (retval) {
                if (this._traced) {
                    retval.replace(ptr(0));
                    reportEvidence('neutralizado: ptrace(PTRACE_TRACEME) -> 0');
                }
            }
        });
    } catch (e) { /* best-effort */ }
}

function hookRawSyscall() {
    if (SYSCALL_NR === null) { return; }
    try {
        var addr = raspilotFindExport('libc.so', 'syscall');
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this._nr = args[0].toInt32();
                this._kind = null;
                this._block = false;
                this._path = '';
                try {
                    if (this._nr === SYSCALL_NR.openat) {
                        this._path = args[2].readCString();
                        this._kind = classifyProcPath(this._path);
                        this._block = matchesHookFramework(this._path);
                    } else if (this._nr === SYSCALL_NR.read) {
                        this._fd = args[1].toInt32();
                        this._buf = args[2];
                        this._kind = rawFdKind[this._fd] || null;
                    } else if (this._nr === SYSCALL_NR.readlinkat) {
                        this._path = args[2].readCString();
                        this._block = matchesHookFramework(this._path);
                    } else if (this._nr === SYSCALL_NR.ptrace) {
                        this._traced = args[1].toInt32() === 0;
                    } else if (this._nr === SYSCALL_NR.close) {
                        delete rawFdKind[args[1].toInt32()];
                    }
                } catch (e) { /* best-effort */ }
            },
            onLeave: function (retval) {
                try {
                    if (this._nr === SYSCALL_NR.openat) {
                        if (this._block) {
                            setErrno(2);
                            retval.replace(ptr(-1));
                            reportEvidence('neutralizado: syscall(openat,' + this._path + ') -> ENOENT');
                        } else if (this._kind !== null) {
                            var fd = retval.toInt32();
                            if (fd >= 0) { rawFdKind[fd] = this._kind; }
                        }
                    } else if (this._nr === SYSCALL_NR.read && this._kind !== null) {
                        var n = retval.toInt32();
                        if (n > 0) {
                            var orig = this._buf.readUtf8String(n);
                            if (orig !== null && orig.length > 0) {
                                var res = filterProc(this._kind, orig);
                                if (res.changed) {
                                    var text = padToSize(res.text, n);
                                    if (text === null) { return; }
                                    this._buf.writeByteArray(strToBytes(text));
                                    reportEvidence('neutralizado: ' + kindLabel(this._kind) +
                                           ' em syscall(read) → ' + res.count + ' ' + res.label);
                                }
                            }
                        }
                    } else if (this._nr === SYSCALL_NR.readlinkat && this._block) {
                        setErrno(2);
                        retval.replace(ptr(-1));
                        reportEvidence('neutralizado: syscall(readlinkat,' + this._path + ') -> ENOENT');
                    } else if (this._nr === SYSCALL_NR.ptrace && this._traced) {
                        retval.replace(ptr(0));
                        reportEvidence('neutralizado: syscall(ptrace) -> 0');
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { /* best-effort */ }
}

function main() {
    hookProcOpenFamily();
    hookProcReads();
    hookReadlinkFamily();
    hookPtrace();
    hookRawSyscall();
    hookThreadNames();
    report('proc_filter.js carregado');
}

main();
