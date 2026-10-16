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

function report(msg) {
    try {
        send({ type: 'raspilot-hooking-bypass', message: msg });
    } catch (e) { /* host indisponível */ }
}

function matchesHookFramework(str) {
    try {
        if (str === null || str === undefined) { return false; }
        var lower = ('' + str).toLowerCase();
        var keywords = [
            'frida', 'xposed', 'lsposed', 'lspd', 'edxposed', 'substrate',
            'sandhook', 'yahfa', 'lsplant', 'whale', 'dobby', 'riru', 'zygisk',
            'gadget', 'gum-js', 'linjector', 'andhook', 'shadowhook'
        ];
        for (var i = 0; i < keywords.length; i++) {
            if (lower.indexOf(keywords[i]) !== -1) { return true; }
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
function filterNetTcp(text) {
    var lines = text.split('\n');
    var kept = [];
    var removed = 0;
    for (var i = 0; i < lines.length; i++) {
        if (lines[i].indexOf(':69A2') !== -1 || lines[i].indexOf(':69A3') !== -1) {
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
                        var text = res.text;
                        if (text.length < n) {
                            this._buf.writeUtf8String(text);
                            retval.replace(ptr(text.length));
                        } else if (text.length === n) {
                            this._buf.writeByteArray(strToBytes(text));
                        } else {
                            return; // não cabe no buffer — mantém original
                        }
                        report('neutralizado: ' + kindLabel(this._kind) + ' em read() → ' +
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
                        var text = res.text;
                        if (text.length >= orig.length) { return; }
                        this._buf.writeUtf8String(text);
                        report('neutralizado: ' + kindLabel(this._kind) + ' em fgets() → ' +
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
                        report('neutralizado: pthread_setname_np(' + name + ') oculto');
                    }
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { /* best-effort */ }
}

function main() {
    hookProcOpenFamily();
    hookProcReads();
    hookThreadNames();
    report('proc_filter.js carregado');
}

setImmediate(main);
