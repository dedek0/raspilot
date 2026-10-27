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

// Strings que identificam a instrumentação em memória.
//
// O nome do agente é ofuscado pela ferramenta (o nome do memfd não
// aparece como "frida"), então a lista precisa cobrir tanto o nome
// original quanto o ofuscado.
var FRIDA_MARKERS = [
    'frida', 'gum-js', 'linjector', 'frida-agent', 'libfrida',
    'libloader64_v8', 'libloader32_v7'
];

var FRIDA_THREADS = ['gum-js-loop', 'gmain', 'pool-frida', 'frida'];

// Limite de caracteres inspecionados por chamada nos ganchos de string.
// Buffers maiores não são verificados: a chance de um marcador estar
// neles é desprezível, e o custo de ler tudo não é.
var MAX_SCAN_CHARS = 256;

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
        var lower = ('' + str).toLowerCase();
        for (var i = 0; i < FRIDA_MARKERS.length; i++) {
            if (lower.indexOf(FRIDA_MARKERS[i]) !== -1) { return true; }
        }
        return false;
    } catch (e) { return false; }
}

// ----------------------------------------------------------------------
// Verificação de marcadores — sem alocação no caminho quente
// ----------------------------------------------------------------------
//
// Os ganchos de string são Cheap por natureza: só strstr é hookado,
// porque strcmp e memcmp são chamados dezenas de milhares de vezes por
// segundo pelo runtime do app e pelo motor JavaScript do agente. A
// verificação precisa ser barata: qualquer alocação por chamada — ler a
// string inteira, copiá-la em minúsculas — consome o tempo do agente e
// o impede de responder, e o sintoma é uma sessão que trava sem erro.
//
// A comparação é feita sobre os caracteres, sem montar string e sem
// chamar funções nativas de dentro do gancho: chamar uma NativeFunction
// dentro do gancho reentra no motor do agente e derruba a sessão.
//
// Os marcadores reduzidos a um needle cada cobrem a lista completa.
var MARKER_NEEDLES = ['frida', 'gum-js', 'linjector', 'libloader'];

var MARKER_BYTES = [];

function initMarkerTables() {
    MARKER_BYTES = [];
    for (var m = 0; m < MARKER_NEEDLES.length; m++) {
        var needle = MARKER_NEEDLES[m];
        var bytes = [];
        for (var i = 0; i < needle.length; i++) {
            bytes.push(needle.charCodeAt(i));
        }
        MARKER_BYTES.push(bytes);
    }
}

// Procura um marcador numa string, sem alocar uma cópia em minúsculas.
function containsMarkerInString(str) {
    var len = str.length;
    if (len > MAX_SCAN_CHARS) { len = MAX_SCAN_CHARS; }
    for (var k = 0; k < MARKER_BYTES.length; k++) {
        var marker = MARKER_BYTES[k];
        var limit = len - marker.length;
        for (var i = 0; i <= limit; i++) {
            var match = true;
            for (var j = 0; j < marker.length; j++) {
                var c = str.charCodeAt(i + j);
                if (c >= 65 && c <= 90) { c += 32; } // A-Z -> a-z
                if (c !== marker[j]) { match = false; break; }
            }
            if (match) { return true; }
        }
    }
    return false;
}

// Lê a string terminada em NUL apontada e procura um marcador.
//
// A leitura para no terminador: ler um tamanho fixo a partir do ponteiro
// pode passar do fim da página mapeada e derrubar o processo.
function containsMarkerAt(ptr) {
    if (ptr === null || ptr === undefined) { return false; }
    try {
        var str = ptr.readCString();
        if (str === null || str.length === 0) { return false; }
        return containsMarkerInString(str);
    } catch (e) {
        return false;
    }
}

// ----------------------------------------------------------------------
// 1) Native — libc.so: strstr/strcmp/strncmp/memcmp
// ----------------------------------------------------------------------
//
// Os ganchos de comparação são caros: o runtime do app e o motor
// JavaScript do agente chamam strcmp/memcmp dezenas de milhares de
// vezes. Por isso eles têm um fast-path: só leem o buffer quando o
// tamanho é pequeno e o primeiro byte pode iniciar um marcador. A
// comparação é feita sobre bytes, sem montar string nem chamar
// NativeFunction dentro do gancho.
var reportedLibcHide = false;

function reportLibcHide(name) {
    if (reportedLibcHide) { return; }
    reportedLibcHide = true;
    reportNeutralized('libc.' + name + ' ocultou marcador de instrumentação');
}

function markerFirstByte(c) {
    var lower = (c >= 65 && c <= 90) ? (c + 32) : c;
    return lower === 102 || lower === 103 || lower === 108 ||
           lower === 114 || lower === 109 || lower === 112 ||
           lower === 47;
}

function isTokenByte(c) {
    if (c === 0) { return true; }
    var lower = (c >= 65 && c <= 90) ? (c + 32) : c;
    return !((lower >= 97 && lower <= 122) || (lower >= 48 && lower <= 57));
}

function bytesContainMarker(buffer) {
    if (buffer === null || buffer === undefined) { return false; }
    var bytes = new Uint8Array(buffer);
    for (var k = 0; k < MARKER_BYTES.length; k++) {
        var marker = MARKER_BYTES[k];
        var limit = bytes.length - marker.length;
        for (var p = 0; p <= limit; p++) {
            var match = true;
            for (var j = 0; j < marker.length; j++) {
                var c = bytes[p + j];
                if (c >= 65 && c <= 90) { c += 32; }
                if (c !== marker[j]) { match = false; break; }
            }
            if (!match) { continue; }
            var before = p === 0 ? 0 : bytes[p - 1];
            var after = (p + marker.length < bytes.length)
                ? bytes[p + marker.length]
                : 0;
            if (isTokenByte(before) && isTokenByte(after)) { return true; }
        }
    }
    return false;
}

function hookLibcStringHooks() {
    var names = ['strstr'];
    names.forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._hide = false;
                    try {
                        if (containsMarkerAt(args[0]) ||
                                containsMarkerAt(args[1])) {
                            this._hide = true;
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (!this._hide) { return; }
                    retval.replace(ptr(0)); // não encontrado
                    reportLibcHide(name);
                }
            });
            report('libc.' + name + ' hookado');
        } catch (e) {
            report('falha ao hookar libc.' + name + ': ' + e);
        }
    });

    // Comparações de string contra nomes de artefatos. O fast-path evita
    // ler ponteiros que não podem começar com um marcador.
    ['strcmp', 'strncmp'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this._hide = false;
                    try {
                        var firstA = args[0].readU8();
                        var firstB = args[1].readU8();
                        if (!markerFirstByte(firstA) &&
                                !markerFirstByte(firstB)) {
                            return;
                        }
                        if (name === 'strncmp') {
                            var n = args[2].toInt32();
                            if (n <= 0 || n > MAX_SCAN_CHARS) { return; }
                            if (bytesContainMarker(args[0].readByteArray(n)) ||
                                    bytesContainMarker(args[1].readByteArray(n))) {
                                this._hide = true;
                            }
                        } else if (containsMarkerAt(args[0]) ||
                                containsMarkerAt(args[1])) {
                            this._hide = true;
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (!this._hide) { return; }
                    retval.replace(1); // strings diferentes
                    reportLibcHide(name);
                }
            });
            report('libc.' + name + ' hookado');
        } catch (e) {
            report('falha ao hookar libc.' + name + ': ' + e);
        }
    });

    // memcmp: comparações por tamanho, típicas de checagens nativas sem
    // string literal. O limite de 64 bytes cobre os nomes de artefatos e
    // evita ler buffers grandes.
    try {
        var memcmpAddr = raspilotFindExport('libc.so', 'memcmp');
        if (memcmpAddr !== null) {
            Interceptor.attach(memcmpAddr, {
                onEnter: function (args) {
                    this._hide = false;
                    try {
                        var n = args[2].toInt32();
                        if (n <= 0 || n > 64) { return; }
                        var firstA = args[0].readU8();
                        var firstB = args[1].readU8();
                        if (!markerFirstByte(firstA) &&
                                !markerFirstByte(firstB)) {
                            return;
                        }
                        if (bytesContainMarker(args[0].readByteArray(n)) ||
                                bytesContainMarker(args[1].readByteArray(n))) {
                            this._hide = true;
                        }
                    } catch (e) { /* best-effort */ }
                },
                onLeave: function (retval) {
                    if (!this._hide) { return; }
                    retval.replace(1); // buffers diferentes
                    reportLibcHide('memcmp');
                }
            });
            report('libc.memcmp hookado (fast-path)');
        }
    } catch (e) {
        report('falha ao hookar libc.memcmp: ' + e);
    }
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

    // exit()/_exit(): o app pode encerrar o processo por conta própria
    // depois de identificar a instrumentação — System.exit e
    // Runtime.exit chegam aqui. Sem neutralizar, a janela de observação
    // termina antes de produzir sinal algum.
    try {
        var exitAddr = raspilotFindExport('libc.so', 'exit');
        if (exitAddr !== null) {
            var origExit = new NativeFunction(exitAddr, 'void', ['int']);
            Interceptor.replace(exitAddr, new NativeCallback(function (code) {
                // A saída não é entregue: o app continua vivo até o fim
                // da janela de observação. O gancho é removido no fim
                // da execução, e o encerramento normal volta a valer.
                reportNeutralized('auto-destruição neutralizada: exit(' + code + ')');
            }, 'void', ['int']));
            report('libc.exit substituído (auto-destruição)');
        }
    } catch (e) {
        report('falha ao substituir exit: ' + e);
    }

    // A entrega de sinal por syscall direta não é interceptada.
    //
    // Substituir a função syscall() significa que toda chamada de
    // syscall do processo passa pelo gancho — e o gancho é executado
    // pelo agente de instrumentação. Quando o agente está ocupado (por
    // exemplo, carregando a camada Java), a thread que chamou a
    // syscall fica esperando o agente, e o app trava esperando a
    // thread: a sessão inteira para de responder sem erro nenhum.
    //
    // O custo de manter a sessão viva é maior do que o de cobrir esse
    // caminho, que exige do alvo uma montagem de syscall na mão.
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
    initMarkerTables();
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
