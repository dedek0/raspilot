/*
 * RASPilot — Kill Trace (script injetado via Frida).
 *
 * Observa quem encerra o processo alvo e com que pilha:
 *   - Java: System.exit, Runtime.exit, Runtime.halt,
 *     android.os.Process.killProcess
 *   - Nativo: libc exit/_exit/abort/kill/killpg/tgkill/raise e o
 *     wrapper syscall() para exit/exit_group/kill (arm64)
 *
 * Cada evento é enviado ao host com a pilha Java (quando disponível) ou
 * o backtrace nativo — diagnóstico para identificar o vetor de
 * auto-destruição de um RASP antes de neutralizá-lo.
 *
 * O script é observatório: chama o original após reportar (não bloqueia).
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

function report(msg) {
    try {
        send({ type: 'app-kill', message: msg });
    } catch (e) { /* host indisponível */ }
}

function javaStack() {
    try {
        var JT = Java.use('java.lang.Thread');
        var stack = JT.currentThread().getStackTrace();
        var parts = [];
        for (var i = 0; i < stack.length && i < 15; i++) {
            parts.push('' + stack[i].getClassName() + '.' + stack[i].getMethodName());
        }
        return parts.join(' <- ');
    } catch (e) { return '(sem stack java: ' + e + ')'; }
}

function nativeBacktrace(ctx) {
    try {
        var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        var parts = [];
        for (var i = 0; i < bt.length && i < 12; i++) {
            parts.push(DebugSymbol.fromAddress(bt[i]).toString());
        }
        return parts.join(' <- ');
    } catch (e) { return '(sem backtrace: ' + e + ')'; }
}

function attachNative(name, describe) {
    try {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var info = describe ? describe(args) : '';
                    report('libc.' + name + info + ' <- ' + nativeBacktrace(this.context));
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) { /* módulo indisponível */ }
}

function installNative() {
    attachNative('exit', function (args) { return '(' + args[0].toInt32() + ')'; });
    attachNative('_exit', function (args) { return '(' + args[0].toInt32() + ')'; });
    attachNative('abort', null);
    attachNative('kill', function (args) {
        return '(pid=' + args[0].toInt32() + ' sig=' + args[1].toInt32() + ')';
    });
    attachNative('killpg', function (args) {
        return '(pgrp=' + args[0].toInt32() + ' sig=' + args[1].toInt32() + ')';
    });
    attachNative('tgkill', function (args) {
        return '(tgid=' + args[0].toInt32() + ' tid=' + args[1].toInt32() +
               ' sig=' + args[2].toInt32() + ')';
    });
    attachNative('raise', function (args) { return '(sig=' + args[0].toInt32() + ')'; });

    // syscall(): cobre exit(93)/exit_group(94) e kill(129)/tkill(130)/
    // tgkill(131) chamados diretamente (números do arm64).
    try {
        var syscallAddr = raspilotFindExport('libc.so', 'syscall');
        if (syscallAddr !== null) {
            Interceptor.attach(syscallAddr, {
                onEnter: function (args) {
                    try {
                        var nr = args[0].toInt32();
                        if (nr === 93 || nr === 94 || nr === 129 || nr === 130 || nr === 131) {
                            report('libc.syscall(nr=' + nr + ') <- ' +
                                   nativeBacktrace(this.context));
                        }
                    } catch (e) { /* best-effort */ }
                }
            });
        }
    } catch (e) { /* best-effort */ }
}

function installJava() {
    // A instalação é adiada: tocar em Java dispara a inicialização do
    // runtime Java no processo alvo, que pode levar dezenas de segundos
    // e bloquearia o carregamento do script.
    raspilotDeferJava(function () {
        try {
            var Sys = Java.use('java.lang.System');
            Sys.exit.implementation = function (code) {
                report('System.exit(' + code + ') <- ' + javaStack());
                this.exit(code);
            };
        } catch (e) { /* best-effort */ }

        try {
            var Runtime = Java.use('java.lang.Runtime');
            Runtime.exit.implementation = function (code) {
                report('Runtime.exit(' + code + ') <- ' + javaStack());
                this.exit(code);
            };
        } catch (e) { /* best-effort */ }

        try {
            var RuntimeHalt = Java.use('java.lang.Runtime');
            RuntimeHalt.halt.implementation = function (code) {
                report('Runtime.halt(' + code + ') <- ' + javaStack());
                this.halt(code);
            };
        } catch (e) { /* best-effort */ }

        try {
            var OsProcess = Java.use('android.os.Process');
            OsProcess.killProcess.implementation = function (pid) {
                report('Process.killProcess(' + pid + ') <- ' + javaStack());
                this.killProcess(pid);
            };
        } catch (e) { /* best-effort */ }
    }, 'kill-trace');
}

function main() {
    installNative();
    installJava();
    report('kill-trace carregado');
}

main();
