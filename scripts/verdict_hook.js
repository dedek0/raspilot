/*
 * RASPilot — Verdict Hook (script injetado via Frida).
 *
 * Neutraliza a comunicação de "o app foi violado" dos SDKs de RASP.
 *
 * A evasão por gancho em primitivas (strstr, Class.forName, File.exists)
 * neutraliza a *detecção*. O SDK, porém, ainda comunica a decisão: chama
 * um callback de ameaça, ou um método que devolve um veredito, e o app
 * age a partir dali — bloqueia a tela, envia um evento para o servidor
 * ou encerra o processo.
 *
 * Aqui a comunicação em si é neutralizada: métodos que apenas reportam
 * a ameaça deixam de reportar, e métodos que devolvem um veredito
 * devolvem "nada errado".
 *
 * A varredura é feita pelo NOME do método, não pelo do pacote: o nome
 * descreve a ação ("onThreatDetected", "terminateApp") e se mantém
 * estável mesmo quando o SDK muda de pacote ou de classe.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// Métodos que comunicam a violação. Substituídos em tempo de carga pelo
// host com o catálogo de vendors.
var VERDICT_METHODS = (typeof __RASPILOT_VERDICT_METHODS__ !== 'undefined')
    ? __RASPILOT_VERDICT_METHODS__
    : [];

// Métodos que devolvem um veredito booleano: "false" significa que
// nada foi encontrado.
var BOOLEAN_VERDICT_METHODS = (typeof __RASPILOT_BOOLEAN_VERDICT_METHODS__ !== 'undefined')
    ? __RASPILOT_BOOLEAN_VERDICT_METHODS__
    : [];

// Classes conhecidas de SDK, para o gancho direcionado.
var VENDOR_CLASSES = (typeof __RASPILOT_VENDOR_CLASSES__ !== 'undefined')
    ? __RASPILOT_VENDOR_CLASSES__
    : [];

// Limite de classes varridas: apps com muitos dex têm milhares de
// classes e a varredura custa tempo de CPU.
var MAX_CLASSES = 1200;

function report(msg) {
    try {
        send({ type: 'raspilot-verdict', message: msg });
    } catch (e) { /* host indisponível */ }
}

function reportEvidence(msg) {
    try {
        send({ type: 'bypass-evidence', message: msg });
    } catch (e) { /* host indisponível */ }
}

function isVerdictMethod(name) {
    for (var i = 0; i < VERDICT_METHODS.length; i++) {
        if (name === VERDICT_METHODS[i]) { return true; }
    }
    return false;
}

function isBooleanVerdictMethod(name) {
    for (var i = 0; i < BOOLEAN_VERDICT_METHODS.length; i++) {
        if (name === BOOLEAN_VERDICT_METHODS[i]) { return true; }
    }
    return false;
}

// Neutraliza os métodos de veredito de uma classe.
function hookVerdictMethods(cls, label) {
    var hooked = 0;
    try {
        var declared = cls.class.getDeclaredMethods();
        for (var i = 0; i < declared.length; i++) {
            var method = declared[i];
            var name = '' + method.getName();
            if (!isVerdictMethod(name) && !isBooleanVerdictMethod(name)) {
                continue;
            }
            var ret = '' + method.getReturnType().getName();
            try {
                var target = cls[name];
                if (target === undefined) { continue; }
                if (ret === 'void') {
                    target.implementation = function () {
                        reportEvidence('veredito neutralizado: ' + label + '.' +
                            name + '()');
                    };
                } else if (ret === 'boolean') {
                    target.implementation = function () {
                        reportEvidence('veredito neutralizado: ' + label + '.' +
                            name + '() -> false');
                        return false;
                    };
                } else {
                    // Tipo de retorno desconhecido: mexer nele pode
                    // quebrar o fluxo do app. Fica de fora.
                    continue;
                }
                hooked++;
            } catch (e) { /* método não hookável */ }
        }
    } catch (e) { /* sem getDeclaredMethods */ }
    return hooked;
}

// Varre as classes carregadas em busca de métodos de veredito.
function sweepLoadedClasses() {
    var classes = [];
    try {
        Java.enumerateLoadedClasses({
            onMatch: function (name) { classes.push(name); },
            onComplete: function () { }
        });
    } catch (e) {
        report('varredura de classes indisponível: ' + e);
        return 0;
    }

    var limit = Math.min(classes.length, MAX_CLASSES);
    var total = 0;
    for (var i = 0; i < limit; i++) {
        var name = classes[i];
        // Só classes do app: as do framework não têm o que reportar.
        if (name.indexOf('com.android.') === 0 ||
                name.indexOf('android.') === 0 ||
                name.indexOf('java.') === 0 ||
                name.indexOf('javax.') === 0 ||
                name.indexOf('dalvik.') === 0 ||
                name.indexOf('libcore.') === 0) {
            continue;
        }
        try {
            var cls = Java.use(name);
            var n = hookVerdictMethods(cls, name);
            if (n > 0) {
                total += n;
                report('veredito hookado: ' + name + ' (' + n + ' método(s))');
            }
        } catch (e) { /* classe não utilizável */ }
    }
    report('varredura concluída: ' + total + ' método(s) de veredito');
    return total;
}

// Gancho direcionado nas classes conhecidas dos vendors.
function hookKnownVendors() {
    var total = 0;
    for (var i = 0; i < VENDOR_CLASSES.length; i++) {
        var name = VENDOR_CLASSES[i];
        try {
            var cls = Java.use(name);
            var n = hookVerdictMethods(cls, name);
            if (n > 0) {
                total += n;
                report('vendor hookado: ' + name + ' (' + n + ' método(s))');
            }
        } catch (e) { /* vendor não presente */ }
    }
    return total;
}

function main() {
    report('verdict_hook.js carregado');
    var known = hookKnownVendors();
    var swept = sweepLoadedClasses();
    report('verdict_hook pronto: ' + (known + swept) + ' método(s)');
}

main();
