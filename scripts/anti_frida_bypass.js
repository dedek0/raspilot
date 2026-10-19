/*
 * RASPilot — Anti-Frida Bypass (script injetado via Frida).
 *
 * Oculta a presença do Frida do app alvo para provar que mecanismos de
 * detecção de Frida podem ser contornados:
 *   - Hooka strstr/strcmp/memcmp em libc.so para esconder strings "frida".
 *   - Hooka File.exists() para retornar false em paths Frida.
 *   - Hooka Runtime.exec() e ProcessBuilder.start() para bloquear comandos
 *     contendo "frida".
 *   - Hooka pthread_setname_np / Thread.getName para esconder nomes de
 *     threads do Frida (gum-js-loop, gmain, pool-frida).
 *
 * O script é idempotente e cada bloco é isolado em try/catch para
 * funcionar em múltiplas versões do Android/ART.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// Paths e strings que apps usam para detectar o Frida.
var FRIDA_PATHS = [
    '/data/local/tmp/frida-server',
    '/data/local/tmp/re.frida.server',
    '/data/local/tmp/frida',
    'frida-server',
    're.frida.server'
];

var FRIDA_THREADS = ['gum-js-loop', 'gmain', 'pool-frida', 'frida'];

// Porta stealth configurada no host (substituída antes da injeção).
// O typeof mantém o script válido mesmo se o placeholder não for trocado.
var RASPILOT_FRIDA_PORT = (typeof __RASPILOT_FRIDA_PORT__ !== 'undefined')
    ? __RASPILOT_FRIDA_PORT__
    : 27999;

// Envia log para o host (visível em bypass_logs do relatório).
function report(msg) {
    try {
        send({ type: 'raspilot-bypass', message: msg });
    } catch (e) { /* host indisponível — ignora */ }
}

// True se a string contém 'frida' (case-insensitive).
function looksLikeFrida(str) {
    try {
        if (str === null || str === undefined) { return false; }
        return ('' + str).toLowerCase().indexOf('frida') !== -1;
    } catch (e) { return false; }
}

// ----------------------------------------------------------------------
// 1) Native — libc.so: strstr / strcmp / memcmp
// ----------------------------------------------------------------------
function hookLibcStringHooks() {
    var names = ['strstr', 'strcmp', 'memcmp'];
    names.forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._hide = false;
                    try {
                        if (name === 'strstr') {
                            var haystack = args[0].readCString();
                            var needle = args[1].readCString();
                            if (looksLikeFrida(needle) || looksLikeFrida(haystack)) {
                                this._hide = true;
                            }
                        } else if (name === 'strcmp') {
                            if (looksLikeFrida(args[0].readCString()) ||
                                looksLikeFrida(args[1].readCString())) {
                                this._hide = true;
                            }
                        } else if (name === 'memcmp') {
                            var n = args[2].toInt32();
                            if (n > 0 && n < 4096) {
                                var buf = args[0].readByteArray(n);
                                if (buf !== null) {
                                    var s = '';
                                    var bytes = new Uint8Array(buf);
                                    for (var i = 0; i < bytes.length; i++) {
                                        var c = bytes[i];
                                        s += (c >= 32 && c < 127)
                                            ? String.fromCharCode(c)
                                            : String.fromCharCode(32);
                                    }
                                    if (looksLikeFrida(s)) { this._hide = true; }
                                }
                            }
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (!this._hide) { return; }
                    if (name === 'strstr') {
                        retval.replace(ptr(0)); // não encontrado
                    } else if (name === 'strcmp' || name === 'memcmp') {
                        retval.replace(ptr(1)); // "diferente"
                    }
                }
            });
            report('libc.' + name + ' hookado');
        } catch (e) {
            report('falha ao hookar libc.' + name + ': ' + e);
        }
    });
}

// ----------------------------------------------------------------------
// 1b) Native — connect() para portas Frida (bloqueia port scan local)
// ----------------------------------------------------------------------
function hookConnectPorts() {
    try {
        var connectPtr = raspilotFindExport('libc.so', 'connect');
        if (connectPtr === null) { return; }
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                this._block = false;
                try {
                    var sa = args[1];
                    var family = sa.readU16();
                    // AF_INET (2) e AF_INET6 (10) usam o mesmo offset de
                    // porta (network byte order) no início de sockaddr.
                    if (family === 2 || family === 10) {
                        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        if (port === 27042 || port === 27043 ||
                            port === RASPILOT_FRIDA_PORT) {
                            this._block = true;
                            report('connect(porta ' + port + ') bloqueado');
                        }
                    }
                } catch (e) { /* best-effort */ }
            },
            onLeave: function (retval) {
                if (this._block) {
                    retval.replace(ptr(-11)); // -EAGAIN
                }
            }
        });
        report('libc.connect hookado (portas Frida)');
    } catch (e) {
        report('falha ao hookar connect: ' + e);
    }
}

// ----------------------------------------------------------------------
// 2) Java — File.exists() em paths Frida
// ----------------------------------------------------------------------
function hookFileExists() {
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = '' + this.getAbsolutePath();
            if (looksLikeFrida(path) || FRIDA_PATHS.indexOf(path) !== -1) {
                report('File.exists(' + path + ') -> false');
                return false;
            }
            return this.exists();
        };
        report('File.exists hookado');
    } catch (e) {
        report('falha ao hookar File.exists: ' + e);
    }
}

// ----------------------------------------------------------------------
// 3) Java — Runtime.exec() e ProcessBuilder.start()
// ----------------------------------------------------------------------
function hookRuntimeExec() {
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (looksLikeFrida(cmd)) {
                report('Runtime.exec(' + cmd + ') bloqueado');
                throw Java.use('java.io.IOException').$new('Command blocked by RASPilot');
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArr) {
            var joined = '';
            try { joined = cmdArr.join(' '); } catch (e) { joined = '' + cmdArr; }
            if (looksLikeFrida(joined)) {
                report('Runtime.exec[](' + joined + ') bloqueado');
                throw Java.use('java.io.IOException').$new('Command blocked by RASPilot');
            }
            return this.exec(cmdArr);
        };
        report('Runtime.exec hookado');
    } catch (e) {
        report('falha ao hookar Runtime.exec: ' + e);
    }

    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command();
            var joined = '';
            try { joined = cmd.toArray().join(' '); } catch (e) { joined = '' + cmd; }
            if (looksLikeFrida(joined)) {
                report('ProcessBuilder.start(' + joined + ') bloqueado');
                throw Java.use('java.io.IOException').$new('Command blocked by RASPilot');
            }
            return this.start();
        };
        report('ProcessBuilder.start hookado');
    } catch (e) {
        report('falha ao hookar ProcessBuilder.start: ' + e);
    }
}

// ----------------------------------------------------------------------
// 4) Threads — esconde nomes de threads do Frida
// ----------------------------------------------------------------------
function hookThreadNames() {
    try {
        var Thread = Java.use('java.lang.Thread');
        Thread.getName.implementation = function () {
            var name = this.getName();
            if (name !== null) {
                var lower = ('' + name).toLowerCase();
                for (var i = 0; i < FRIDA_THREADS.length; i++) {
                    if (lower.indexOf(FRIDA_THREADS[i]) !== -1) {
                        return 'Thread-' + this.getId();
                    }
                }
            }
            return name;
        };
        report('Thread.getName hookado');
    } catch (e) {
        report('falha ao hookar Thread.getName: ' + e);
    }

    try {
        var pthread = raspilotFindExport('libc.so', 'pthread_setname_np');
        if (pthread !== null) {
            Interceptor.attach(pthread, {
                onEnter: function (args) {
                    try {
                        var name = args[1].readCString();
                        if (looksLikeFrida(name)) {
                            args[1].writeUtf8String('hidden');
                            report('pthread_setname_np(' + name + ') -> hidden');
                        }
                    } catch (e) { /* best-effort */ }
                }
            });
            report('pthread_setname_np hookado');
        }
    } catch (e) {
        report('falha ao hookar pthread_setname_np: ' + e);
    }
}

// ----------------------------------------------------------------------
// Bootstrap — idempotente
// ----------------------------------------------------------------------
function main() {
    hookLibcStringHooks();
    hookConnectPorts();

    var attachJava = function () {
        var ok = raspilotPerformJava(function () {
            hookFileExists();
            hookRuntimeExec();
            hookThreadNames();
        });
        if (!ok) {
            report('Java indisponível — hooks Java pulados');
        }
    };
    attachJava();

    report('anti_frida_bypass.js carregado');
}

main();
