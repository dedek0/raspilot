/*
 * RASPilot — Sonda de anti-tampering em memória.
 *
 * Simula uma assinatura de pacote alterada sem reinstalar o APK:
 * - PackageManager.getPackageInfo devolve um Signature[] diferente;
 * - PackageManager.checkSignatures devolve SIGNATURE_MISMATCH (-3).
 *
 * Se o app verificar a própria assinatura e reagir (crash/bloqueio), a
 * proteção foi exercitada. Se continuar vivo e utilizável, o teste é
 * inconclusivo ou vulnerável, dependendo do controle sem tamper.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

var MODE = '__RASPILOT_TAMPER_MODE__';

function report(msg) {
    try {
        send({ type: 'tamper-probe', message: msg });
    } catch (e) { /* host indisponível */ }
}

function hookPackageInfo() {
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var Signature = Java.use('android.content.pm.Signature');
        var bytes = Java.array('byte', [0x52, 0x41, 0x53, 0x50, 0x69, 0x6c, 0x6f, 0x74]);
        var fake = Signature.$new(bytes);
        var hooked = 0;
        PM.getPackageInfo.overloads.forEach(function (overload) {
            try {
                overload.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    var info = overload.apply(this, args);
                    try {
                        if (info !== null && info.signatures &&
                                info.signatures.value) {
                            info.signatures.value = Java.array(
                                'android.content.pm.Signature', [fake]
                            );
                            report('getPackageInfo signatures -> alterado');
                        }
                    } catch (e) { /* campo indisponível */ }
                    return info;
                };
                hooked++;
            } catch (e) { /* overload incompatível */ }
        });
        if (hooked > 0) {
            report('getPackageInfo hookado (' + hooked + ' overload(s))');
        }
    } catch (e) {
        report('falha ao hookar getPackageInfo: ' + e);
    }
}

function hookCheckSignatures() {
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var hooked = 0;
        PM.checkSignatures.overloads.forEach(function (overload) {
            try {
                overload.implementation = function () {
                    report('checkSignatures -> SIGNATURE_MISMATCH');
                    return -3;
                };
                hooked++;
            } catch (e) { /* overload incompatível */ }
        });
        if (hooked > 0) {
            report('checkSignatures hookado (' + hooked + ' overload(s))');
        }
    } catch (e) {
        report('falha ao hookar checkSignatures: ' + e);
    }
}

function install() {
    report('instalando hooks de assinatura em memória');
    hookPackageInfo();
    hookCheckSignatures();
    report('sonda de assinatura ativa');
}

function main() {
    if (MODE !== 'tamper') {
        report('sham: bridge Java ativa, hooks de assinatura desligados');
        return;
    }
    report('tamper_probe.js carregado');
    if (typeof raspilotDeferJava === 'function') {
        if (!raspilotDeferJava(install, 'tamper-probe')) {
            report('Java indisponível — sonda de tamper não instalada');
        }
        return;
    }
    if (!raspilotPerformJava(install)) {
        report('Java indisponível — sonda de tamper não instalada');
    }
}

main();
