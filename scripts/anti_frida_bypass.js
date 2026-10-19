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

// Ação do app que foi de fato impedida. Distinto do relato de
// instalação do hook: aqui o app tentou algo e a instrumentação
// impediu — é a evidência do que a proteção tentou fazer.
function reportNeutralized(msg) {
    try {
        send({ type: 'raspilot-neutralized', message: msg });
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
// 4) Auto-destruição — impede que o app se mate
// ----------------------------------------------------------------------
//
// Vasos de RASP que abortam o próprio processo no instante em que
// detectam a instrumentação: o alvo envia um sinal de parada para si
// mesmo, observa o quanto tempo levou para voltar e, se o tempo não
// bater com o esperado, aborta.
//
// O sinal de parada é o caso mais perigoso: ele congela a thread do
// próprio processo — e, se a thread afetada for a do agente de
// instrumentação, a sessão inteira deixa de responder, sem que o
// processo necessariamente morra. O sintoma é uma instrumentação que
// "trava" sem erro.
//
// Os sinais são neutralizados apenas quando o alvo é o próprio processo:
// kill para outros processos continua intacto.
var SELF_SIGNALS = {
    6: 'SIGABRT',
    9: 'SIGKILL',
    19: 'SIGSTOP',
    24: 'SIGXCPU',
    25: 'SIGXFSZ'
};

function signalName(sig) {
    return SELF_SIGNALS[sig] || ('SIG' + sig);
}

function isSelfPid(pid) {
    try {
        return pid === Process.id || pid === 0;
    } catch (e) {
        return false;
    }
}

// Números de syscall de sinal por arquitetura. O alvo pode chamá-los
// direto, por dentro do wrapper syscall(), para não passar pelos
// ganchos de libc.
//
// Os índices são relativos aos argumentos da chamada, sem contar o
// número do syscall: selfIndex aponta o alvo e sigIndex o sinal.
var SIGNAL_SYSCALLS = {
    arm64: [
        { nr: 129, selfIndex: 0, sigIndex: 1, name: 'kill' },
        { nr: 130, selfIndex: 0, sigIndex: 1, name: 'tkill' },
        { nr: 131, selfIndex: 0, sigIndex: 2, name: 'tgkill' },
        { nr: 307, selfIndex: 0, sigIndex: 1, name: 'rt_sigqueueinfo' },
        { nr: 314, selfIndex: 0, sigIndex: 2, name: 'rt_tgsigqueueinfo' }
    ],
    x64: [
        { nr: 62, selfIndex: 0, sigIndex: 1, name: 'kill' },
        { nr: 200, selfIndex: 0, sigIndex: 1, name: 'tkill' },
        { nr: 234, selfIndex: 0, sigIndex: 2, name: 'tgkill' },
        { nr: 307, selfIndex: 0, sigIndex: 1, name: 'rt_sigqueueinfo' },
        { nr: 314, selfIndex: 0, sigIndex: 2, name: 'rt_tgsigqueueinfo' }
    ]
};

function hookSelfTermination() {
    // raise(sig): o app sinaliza a si mesmo.
    //
    // A substituição é total (Interceptor.replace) em vez de um gancho
    // que apenas observa: o sinal é entregue durante a chamada, então
    // ajustar o valor de retorno não impede a entrega — é preciso
    // outright não chamar a função original.
    try {
        var raiseAddr = raspilotFindExport('libc.so', 'raise');
        if (raiseAddr !== null) {
            var origRaise = new NativeFunction(raiseAddr, 'int', ['int']);
            Interceptor.replace(raiseAddr, new NativeCallback(function (sig) {
                try {
                    if (SELF_SIGNALS[sig] !== undefined) {
                        reportNeutralized('auto-destruição neutralizada: raise(' +
                               signalName(sig) + ')');
                        return 0;
                    }
                } catch (e) { /* best-effort */ }
                return origRaise(sig);
            }, 'int', ['int']));
            report('libc.raise substituído (auto-destruição)');
        }
    } catch (e) {
        report('falha ao substituir raise: ' + e);
    }

    // kill(pid, sig) / tgkill(tgid, tid, sig) / killpg(pgrp, sig) /
    // pthread_kill(thread, sig).
    //
    // Em tgkill o alvo do sinal é a thread, mas o grupo de threads é o
    // que identifica o processo: um SIGSTOP em uma thread do processo
    // congela a instrumentação tanto quanto um SIGSTOP no processo
    // inteiro.
    var killers = [
        { name: 'kill', types: ['int', 'int'], selfIndex: 0, sigIndex: 1 },
        { name: 'tgkill', types: ['int', 'int', 'int'], selfIndex: 0, sigIndex: 2 },
        { name: 'killpg', types: ['int', 'int'], selfIndex: 0, sigIndex: 1 },
        { name: 'pthread_kill', types: ['pointer', 'int'], selfIndex: -1, sigIndex: 1 }
    ];
    killers.forEach(function (spec) {
        try {
            var addr = raspilotFindExport('libc.so', spec.name);
            if (addr === null) { return; }
            var orig = new NativeFunction(addr, 'int', spec.types);
            var args = spec.types.slice();
            var callback = new NativeCallback(function () {
                var a = Array.prototype.slice.call(arguments);
                try {
                    var sig = a[spec.sigIndex] | 0;
                    // pthread_kill só pode mirar threads do próprio
                    // processo, então não há alvo a verificar.
                    var target = spec.selfIndex < 0
                        ? Process.id
                        : (a[spec.selfIndex] | 0);
                    if (SELF_SIGNALS[sig] !== undefined && isSelfPid(target)) {
                        reportNeutralized('auto-destruição neutralizada: ' + spec.name +
                               '(' + signalName(sig) + ')');
                        return 0;
                    }
                } catch (e) { /* best-effort */ }
                return orig.apply(null, a);
            }, 'int', spec.types);
            Interceptor.replace(addr, callback);
            report('libc.' + spec.name + ' substituído (auto-destruição)');
        } catch (e) {
            report('falha ao substituir ' + spec.name + ': ' + e);
        }
    });

    // abort(): encerra o processo com SIGABRT. A detecção de RASP
    // normalmente chega até aqui depois de identificar a instrumentação
    // — e o runtime do app aborta quando uma thread externa se anexa
    // à máquina virtual, o que derruba a sessão de instrumentação
    // inteira sem que o processo precise morrer.
    try {
        var abortAddr = raspilotFindExport('libc.so', 'abort');
        if (abortAddr !== null) {
            var origAbort = new NativeFunction(abortAddr, 'void', []);
            Interceptor.replace(abortAddr, new NativeCallback(function () {
                reportNeutralized('auto-destruição neutralizada: abort()');
            }, 'void', []));
            report('libc.abort substituído (auto-destruição)');
        }
    } catch (e) {
        report('falha ao substituir abort: ' + e);
    }

    hookRawSignalSyscalls();
}

// Chamadas diretas a syscall() para entrega de sinal.
//
// Um alvo que quer evitar os ganchos de libc chama a syscall direto.
// É por isso que a neutralização do sinal de parada precisa existir
// também nesse caminho: sem ele, o processo inteiro (e a thread do
// agente de instrumentação) congela sem que nada seja registrado.
//
// A substituição repassa os argumentos com 64 bits, preservando o
// retorno de syscalls que devolvem ponteiros.
function hookRawSignalSyscalls() {
    var specs = SIGNAL_SYSCALLS[Process.arch];
    if (!specs) { return; }
    try {
        var addr = raspilotFindExport('libc.so', 'syscall');
        if (addr === null) { return; }
        var orig = new NativeFunction(addr, 'long',
            ['long', 'long', 'long', 'long', 'long', 'long', 'long']);
        var callback = new NativeCallback(function (nr, a1, a2, a3, a4, a5, a6) {
            try {
                var n = nr | 0;
                for (var i = 0; i < specs.length; i++) {
                    var spec = specs[i];
                    if (spec.nr !== n) { continue; }
                    // O número do syscall é o primeiro argumento; os
                    // demais são os do sinal, conforme a chamada.
                    var callArgs = [a1, a2, a3, a4, a5, a6];
                    var target = callArgs[spec.selfIndex] | 0;
                    var sig = callArgs[spec.sigIndex] | 0;
                    if (SELF_SIGNALS[sig] !== undefined && isSelfPid(target)) {
                        reportNeutralized('auto-destruição neutralizada: syscall(' +
                               spec.name + ', ' + signalName(sig) + ')');
                        return 0;
                    }
                    break;
                }
            } catch (e) { /* best-effort */ }
            return orig(nr, a1, a2, a3, a4, a5, a6);
        }, 'long', ['long', 'long', 'long', 'long', 'long', 'long', 'long']);
        Interceptor.replace(addr, callback);
        report('libc.syscall substituído (auto-destruição)');
    } catch (e) {
        report('falha ao substituir syscall: ' + e);
    }
}

// ----------------------------------------------------------------------
// Bootstrap — idempotente
// ----------------------------------------------------------------------

// Indica que o script foi carregado apenas com a camada nativa (sem
// bridge Java). Nesse caso os hooks Java são omitidos: a bridge é o
// que torna a injeção visível para o app.
var RASPILOT_JAVA_ONLY = (typeof __RASPILOT_JAVA_ONLY__ !== 'undefined')
    ? __RASPILOT_JAVA_ONLY__
    : false;

function main() {
    hookLibcStringHooks();
    hookConnectPorts();
    hookSelfTermination();

    if (RASPILOT_JAVA_ONLY) {
        report('anti_frida_bypass.js carregado (somente nativo)');
        return;
    }

    var attachJava = function () {
        raspilotDeferJava(function () {
            hookFileExists();
            hookRuntimeExec();
            hookThreadNames();
        }, 'anti-frida-bypass');
    };
    attachJava();

    report('anti_frida_bypass.js carregado');
}

main();
