/*
 * RASPilot — Spoof de Emulador (script injetado via Frida).
 *
 * Faz o processo do app enxergar — ou não enxergar — um emulador, para
 * medir a proteção anti-emulador do app:
 *
 * - modo "probe": o app recebe a identidade completa de um AVD (Build.*,
 *   SystemProperties, /dev/qemu_pipe, IMEI/IMSI, ANDROID_ID). Se o app
 *   detectar e reagir, existe proteção anti-emulador.
 *
 * - modo "mask": o app recebe a identidade de um device físico nos canais
 *   DECISIVOS (a assinatura clássica de emulador: Build, ro.kernel.qemu,
 *   /dev/qemu_pipe...) e mantém os artefatos SECUNDÁRIOS que um emulador
 *   real ainda deixa expostos (IMEI 000..., ANDROID_ID de emulador, telco
 *   "Android", ro.serialno). É o cenário realista de "emulador com camada
 *   de stealth": se o app ainda reage, é porque consulta um canal que não
 *   foi ocultado — e o relatório diz qual.
 *
 * Toda consulta do app a uma primitiva sensível é reportada ao host: é o
 * que permite dizer QUAL canal o app usou, e não apenas que ele usou
 * algum.
 *
 * O script é idempotente e cada bloco é isolado em try/catch para
 * funcionar em múltiplas versões do Android/ART.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// 'probe' = o app enxerga um emulador; 'mask' = os artefatos decisivos
// ficam ocultos.
var MODE = (typeof __RASPILOT_EMU_MODE__ !== 'undefined')
    ? __RASPILOT_EMU_MODE__
    : 'probe';

// true = apenas hooks Java (após resume); false = apenas nativos
// (antes do resume, sem bridge Java).
var JAVA_ONLY = (typeof __RASPILOT_JAVA_ONLY__ !== 'undefined')
    ? __RASPILOT_JAVA_ONLY__
    : false;

var IS_MASK = (MODE === 'mask');

// ----------------------------------------------------------------------
// Identidade de um AVD (API 33, x86_64)
// ----------------------------------------------------------------------
var EMU = {
    FINGERPRINT: 'google/sdk_gphone64_x86_64/emu64a:13/TQ3A.230901.001/10750268:user/release-keys',
    MODEL: 'sdk_gphone64_x86_64',
    MANUFACTURER: 'Google',
    BRAND: 'google',
    DEVICE: 'emu64a',
    PRODUCT: 'sdk_gphone64_x86_64',
    HARDWARE: 'goldfish',
    BOARD: 'goldfish_x86',
    ID: 'TQ3A.230901.001',
    HOST: 'Build-Temporary',
    TAGS: 'test-keys',
    TYPE: 'userdebug',
    USER: 'android',
    SERIAL: 'unknown',
    BOOTLOADER: 'unknown',
    DISPLAY: 'EMU'
};

// Canais DECISIVOS: a assinatura que nenhum device real apresenta.
// São os que uma camada de stealth de emulador oculta de fato.
var DECISIVE_BUILD = [
    'FINGERPRINT', 'MODEL', 'MANUFACTURER', 'BRAND', 'DEVICE',
    'PRODUCT', 'HARDWARE', 'BOARD', 'TAGS'
];

// Canais SECUNDÁRIOS: artefatos que um emulador real deixa expostos
// (identidade do aparelho, ABI, build interno). Ocultá-los exige
// instrumentação mais profunda que a de um spoof de propriedades.
var SECONDARY_BUILD = [
    'ID', 'HOST', 'TYPE', 'USER', 'SERIAL', 'BOOTLOADER', 'DISPLAY'
];

var EMU_PROPS = {
    'ro.kernel.qemu': '1',
    'ro.boot.qemu': '1',
    'ro.kernel.qemu.gles': '1',
    'ro.qemu.sf': '1',
    'qemu.sf': '1',
    'ro.hardware': 'goldfish',
    'ro.boot.hardware': 'ranchu',
    'ro.hardware.egl': 'emulation',
    'ro.product.model': 'sdk_gphone64_x86_64',
    'ro.product.name': 'sdk_gphone64_x86_64',
    'ro.product.device': 'emu64a',
    'ro.product.brand': 'google',
    'ro.product.manufacturer': 'Google',
    'ro.build.fingerprint': EMU.FINGERPRINT,
    'ro.build.tags': 'test-keys',
    'ro.build.characteristics': 'emulator,phone',
    'ro.build.id': EMU.ID,
    'ro.build.host': EMU.HOST,
    'ro.build.user': EMU.USER,
    'ro.build.type': EMU.TYPE,
    'ro.build.display.id': EMU.ID,
    'ro.serialno': EMU.SERIAL,
    'ro.boot.serialno': EMU.SERIAL,
    'ro.bootloader': EMU.BOOTLOADER,
    'ro.product.cpu.abi': 'x86_64'
};

var DECISIVE_PROPS = [
    'ro.kernel.qemu', 'ro.boot.qemu', 'ro.kernel.qemu.gles', 'ro.qemu.sf',
    'qemu.sf', 'ro.hardware', 'ro.boot.hardware', 'ro.hardware.egl',
    'ro.product.model', 'ro.product.name', 'ro.product.device',
    'ro.product.brand', 'ro.product.manufacturer', 'ro.build.fingerprint',
    'ro.build.tags', 'ro.build.characteristics'
];

var SECONDARY_PROPS = [
    'ro.build.id', 'ro.build.host', 'ro.build.user', 'ro.build.type',
    'ro.build.display.id', 'ro.serialno', 'ro.boot.serialno',
    'ro.bootloader', 'ro.product.cpu.abi'
];

// Arquivos/dirs que só existem em emulador.
var EMU_FILES = [
    '/dev/qemu_pipe',
    '/dev/socket/qemud',
    '/dev/goldfish_pipe',
    '/sys/qemu_trace',
    '/init.goldfish.rc',
    '/system/lib/libc_malloc_debug_qemu.so',
    '/system/lib64/libc_malloc_debug_qemu.so'
];

// Identidade de telefonia de um emulador: o IMEI zerado e o número
// 15555215554 são marcas conhecidas de AVD.
var EMU_TELEPHONY = {
    getDeviceId: '000000000000000',
    getImei: '000000000000000',
    getMeid: '000000000000000',
    getSubscriberId: '310260000000000',
    getSimSerialNumber: '89012600000000000000',
    getNetworkOperatorName: 'Android',
    getNetworkOperator: '310260',
    getSimOperator: '310260',
    getLine1Number: '15555215554'
};

var EMU_ANDROID_ID = '9774d56d682e549c';

// Marcadores que apps anti-emulador procuram em memória (código nativo).
var NATIVE_KEYWORDS = [
    'goldfish', 'ranchu', 'vbox86', 'qemu', 'sdk_gphone', 'sdk_phone',
    'generic_x86', 'genymotion', 'bluestacks', 'vbox', 'ttvm', 'windroye',
    'droid4x', 'qemu_pipe', 'qemud', 'android sdk built for'
];

// Métodos cujo nome descreve a decisão "isto é um emulador". A varredura
// é pelo NOME porque o pacote e a classe mudam entre SDKs, mas o nome da
// ação permanece.
var EMU_VERDICT_SPECS = [
    'onEmulator*',
    'isEmulator*',
    'isRunningOnEmulator*',
    'isProbablyAnEmulator*',
    'detectEmulator*',
    'checkEmulator*',
    'emulatorDetect*',
    'onVirtualEnv*',
    'isVirtualEnv*',
    'isProbablyVirtual*',
    'isStockEmulator*'
];

// ----------------------------------------------------------------------
// Relato
// ----------------------------------------------------------------------

// Consulta do app a uma primitiva sensível a emulador.
//
// channel: 'decisive' (artefato que nenhum device real tem) ou
//          'secondary' (artefato que um emulador real deixa exposto).
// kind:    'query' (o app consultou a primitiva), 'spoof' (a
//          instrumentação trocou o valor) ou 'mask' (o artefato foi
//          ocultado e o app viu o valor real).
// masked:  True quando o artefato foi ocultado (modo mask).
function report(channel, method, detail, masked, kind) {
    try {
        send({
            type: 'emulator-detection',
            channel: '' + channel,
            method: '' + method,
            detail: '' + detail,
            masked: !!masked,
            kind: kind || 'query'
        });
    } catch (e) { /* host indisponível */ }
}

// Diagnóstico da instrumentação (não é sinal do app).
function note(msg) {
    try {
        send({ type: 'emulator-note', message: '' + msg });
    } catch (e) { /* host indisponível */ }
}

function errorNote(msg) {
    try {
        send({ type: 'emulator-error', message: '' + msg });
    } catch (e) { /* host indisponível */ }
}

// ----------------------------------------------------------------------
// Classificação dos canais
// ----------------------------------------------------------------------
function propChannel(key) {
    if (DECISIVE_PROPS.indexOf(key) !== -1) { return 'decisive'; }
    if (SECONDARY_PROPS.indexOf(key) !== -1) { return 'secondary'; }
    return null;
}

function buildChannel(name) {
    if (DECISIVE_BUILD.indexOf(name) !== -1) { return 'decisive'; }
    if (SECONDARY_BUILD.indexOf(name) !== -1) { return 'secondary'; }
    return null;
}

function isEmulatorFile(path) {
    return EMU_FILES.indexOf(path) !== -1;
}

// Casa um termo como TOKEN: "goldfish" não pode casar com "goldfishbar".
function isTokenBoundary(ch) {
    return ch === '' || !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'));
}

function containsEmulatorKeyword(lower) {
    for (var i = 0; i < NATIVE_KEYWORDS.length; i++) {
        var term = NATIVE_KEYWORDS[i];
        var idx = lower.indexOf(term);
        while (idx !== -1) {
            var before = idx === 0 ? '' : lower.charAt(idx - 1);
            var after = idx + term.length >= lower.length
                ? '' : lower.charAt(idx + term.length);
            if (isTokenBoundary(before) && isTokenBoundary(after)) { return true; }
            idx = lower.indexOf(term, idx + 1);
        }
    }
    return false;
}

// ----------------------------------------------------------------------
// Camada nativa
// ----------------------------------------------------------------------
function hookNative() {
    hookNativePropertyGet();
    hookNativePropertyFind();
    hookNativePropertyRead();
    hookNativeFileAccess();
    hookNativeStringSearch();
}

// Nome da propriedade associado ao prop_info_t* devolvido por
// __system_property_find. A leitura de uma propriedade em bionic passa
// por "find" (devolve o handle) e "read" (copia o valor) — e é o
// par find/read que muitos apps usam para ler propriedades sem passar
// por __system_property_get.
var propNames = {};

// __system_property_get — a leitura nativa de propriedades.
function hookNativePropertyGet() {
    var addr = raspilotFindExport('libc.so', '__system_property_get');
    if (addr === null) {
        note('__system_property_get indisponível');
        return;
    }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.key = null;
            this.buffer = args[1];
            try { this.key = args[0].readCString(); } catch (e) { this.key = null; }
        },
        onLeave: function (retval) {
            var key = this.key;
            if (!key) { return; }
            var channel = propChannel(key);
            if (channel === null) { return; }
            if (IS_MASK && channel === 'decisive') {
                // O artefato fica oculto: o app lê o valor real do device.
                report('decisive', 'native.__system_property_get', key, true);
                return;
            }
            var value = EMU_PROPS[key];
            if (value === undefined) { return; }
            try {
                this.buffer.writeUtf8String(value);
                retval.replace(value.length);
            } catch (e) { /* best-effort */ }
            report(channel, 'native.__system_property_get', key + '=' + value, false);
        }
    });
}

// __system_property_find — devolve o handle da propriedade.
function hookNativePropertyFind() {
    var addr = raspilotFindExport('libc.so', '__system_property_find');
    if (addr === null) { return; }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.key = null;
            try { this.key = args[0].readCString(); } catch (e) { this.key = null; }
        },
        onLeave: function (retval) {
            var key = this.key;
            if (!key) { return; }
            try { propNames[retval.toString()] = key; } catch (e) { /* best-effort */ }
            var channel = propChannel(key);
            if (channel === null) { return; }
            if (IS_MASK && channel === 'decisive') {
                report('decisive', 'native.__system_property_find', key, true);
                return;
            }
            report(channel, 'native.__system_property_find', key, false);
        }
    });
}

// __system_property_read — copia o valor da propriedade para o buffer.
function hookNativePropertyRead() {
    var addr = raspilotFindExport('libc.so', '__system_property_read');
    if (addr === null) { return; }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.buffer = args[1];
            this.spoof = null;
            var key = null;
            try { key = propNames[args[0].toString()] || null; } catch (e) { key = null; }
            if (!key) { return; }
            var channel = propChannel(key);
            if (channel === null) { return; }
            if (IS_MASK && channel === 'decisive') {
                // Deixa o valor real: o artefato fica oculto.
                report('decisive', 'native.__system_property_read', key, true);
                return;
            }
            var value = EMU_PROPS[key];
            if (value === undefined) { return; }
            this.spoof = value;
        },
        onLeave: function (retval) {
            if (!this.spoof) { return; }
            try {
                this.buffer.writeUtf8String(this.spoof);
                retval.replace(this.spoof.length);
            } catch (e) { /* best-effort */ }
        }
    });
}

// access/faccessat — a sondagem de existência de paths de emulador.
function hookNativeFileAccess() {
    ['access', 'faccessat', 'faccessat2'].forEach(function (name) {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.path = null;
                try {
                    var idx = (name === 'access') ? 0 : 1;
                    this.path = args[idx].readCString();
                } catch (e) { this.path = null; }
            },
            onLeave: function (retval) {
                var path = this.path;
                if (!path || !isEmulatorFile(path)) { return; }
                if (IS_MASK) {
                    // Esconde o artefato: o path passa a não existir.
                    retval.replace(-1);
                    try {
                        if (typeof errno !== 'undefined') { errno.value = 2; }
                    } catch (e) { /* errno indisponível */ }
                    report('decisive', 'native.' + name, path + ' -> oculto', true);
                } else {
                    retval.replace(0);
                    report('decisive', 'native.' + name, path + ' -> presente', false);
                }
            }
        });
    });
}

// strstr/strcasestr/strcmp — o app procurando marcadores de emulador em
// memória (detecção nativa).
//
// Os dois argumentos são verificados: um deles é a constante do app
// ("qemu", "goldfish"...), o outro é o valor comparado. Os dois lados
// são reportados porque a ordem dos argumentos varia entre chamadas:
// é o que mostra se a comparação casou ou apenas existiu.
function clipText(text) {
    var value = '' + text;
    return value.length > 48 ? value.substring(0, 48) + '…' : value;
}

function hookNativeStringSearch() {
    ['strstr', 'strcasestr', 'strcmp'].forEach(function (name) {
        var addr = raspilotFindExport('libc.so', name);
        if (addr === null) { return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var left = '' + args[0].readCString();
                    var right = '' + args[1].readCString();
                    var hit = containsEmulatorKeyword(left.toLowerCase()) ||
                        containsEmulatorKeyword(right.toLowerCase());
                    if (!hit) { return; }
                    report('decisive', 'native.' + name,
                        'a="' + clipText(left) + '" b="' + clipText(right) + '"',
                        IS_MASK);
                } catch (e) { /* best-effort */ }
            }
        });
    });
}

// ----------------------------------------------------------------------
// Camada Java
// ----------------------------------------------------------------------
function installJavaHooks() {
    hookBuildFields();
    hookSystemProperties();
    hookFileExists();
    hookTelephony();
    hookSecureSettings();
    hookRuntimeExec();
    var hooked = observeVerdictMethods();
    note('hooks Java instalados (' + hooked + ' método(s) de veredito)');

    // As classes do app são carregadas ao longo da inicialização: uma
    // segunda varredura pega o detector que só foi resolvido depois.
    setTimeout(function () {
        if (typeof raspilotPerformJava === 'function') {
            raspilotPerformJava(function () { observeVerdictMethods(); });
        }
    }, 5000);
}

// Build.* — campos estáticos com a identidade do device.
//
// Leituras de campo não são interceptáveis: o hook apenas troca o valor.
// O que é registrado aqui é a *troca*, não uma consulta do app — a
// evidência de que o app consultou o campo vem da reação do app.
function hookBuildFields() {
    var Build = null;
    try {
        Build = Java.use('android.os.Build');
    } catch (e) {
        note('android.os.Build indisponível');
        return;
    }
    Object.keys(EMU).forEach(function (name) {
        var channel = buildChannel(name);
        if (channel === null) { return; }
        if (IS_MASK && channel === 'decisive') {
            // Não toca: o app continua vendo o valor real do device, e o
            // artefato de emulador fica oculto.
            report('decisive', 'Build.' + name, 'valor real preservado', true, 'mask');
            return;
        }
        try {
            var field = Build[name];
            if (!field) { return; }
            field.value = EMU[name];
            report(channel, 'Build.' + name, EMU[name], false, 'spoof');
        } catch (e) {
            note('Build.' + name + ' não alterável: ' + e);
        }
    });
}

// SystemProperties.get — leitura Java de propriedades do sistema.
function hookSystemProperties() {
    var SP = null;
    try {
        SP = Java.use('android.os.SystemProperties');
    } catch (e) {
        note('android.os.SystemProperties indisponível: ' + e);
        return;
    }

    var origGet = null;
    try {
        origGet = SP.get.overload('java.lang.String');
        origGet.implementation = function (key) {
            try {
                var name = '' + key;
                var channel = propChannel(name);
                if (channel !== null) {
                    if (IS_MASK && channel === 'decisive') {
                        report('decisive', 'SystemProperties.get', name, true);
                        return origGet.call(this, key);
                    }
                    var value = EMU_PROPS[name];
                    if (value !== undefined) {
                        report(channel, 'SystemProperties.get', name + '=' + value, false);
                        return value;
                    }
                }
            } catch (e) { /* best-effort */ }
            return origGet.call(this, key);
        };
    } catch (e) {
        note('SystemProperties.get(String) indisponível: ' + e);
    }

    try {
        var origGet2 = SP.get.overload('java.lang.String', 'java.lang.String');
        origGet2.implementation = function (key, def) {
            try {
                var name = '' + key;
                var channel = propChannel(name);
                if (channel !== null) {
                    if (IS_MASK && channel === 'decisive') {
                        report('decisive', 'SystemProperties.get', name, true);
                        return origGet2.call(this, key, def);
                    }
                    var value = EMU_PROPS[name];
                    if (value !== undefined) {
                        report(channel, 'SystemProperties.get', name + '=' + value, false);
                        return value;
                    }
                }
            } catch (e) { /* best-effort */ }
            return origGet2.call(this, key, def);
        };
    } catch (e) { /* sobrecarga ausente */ }
}

// File.exists/canRead — sondagem dos paths exclusivos de emulador.
function hookFileExists() {
    var File = null;
    try {
        File = Java.use('java.io.File');
    } catch (e) {
        note('java.io.File indisponível');
        return;
    }

    var origExists = File.exists;
    File.exists.implementation = function () {
        try {
            var path = '' + this.getAbsolutePath();
            if (isEmulatorFile(path)) {
                if (IS_MASK) {
                    report('decisive', 'File.exists', path + ' -> oculto', true);
                    return false;
                }
                report('decisive', 'File.exists', path + ' -> presente', false);
                return true;
            }
        } catch (e) { /* best-effort */ }
        return origExists.call(this);
    };

    try {
        var origCanRead = File.canRead;
        File.canRead.implementation = function () {
            try {
                var path = '' + this.getAbsolutePath();
                if (isEmulatorFile(path)) {
                    if (IS_MASK) {
                        report('decisive', 'File.canRead', path + ' -> oculto', true);
                        return false;
                    }
                    report('decisive', 'File.canRead', path + ' -> presente', false);
                    return true;
                }
            } catch (e) { /* best-effort */ }
            return origCanRead.call(this);
        };
    } catch (e) { /* canRead ausente */ }
}

// TelephonyManager — IMEI/IMSI/número da linha de um emulador.
function hookTelephony() {
    var TM = null;
    try {
        TM = Java.use('android.telephony.TelephonyManager');
    } catch (e) {
        note('android.telephony.TelephonyManager indisponível');
        return;
    }
    Object.keys(EMU_TELEPHONY).forEach(function (name) {
        try {
            var orig = TM[name];
            if (!orig) { return; }
            orig.implementation = function () {
                // A exceção original é preservada: em Android moderno o
                // getDeviceId exige permissão e lançar é o comportamento
                // real do device.
                var real = orig.call(this);
                report('secondary', 'TelephonyManager.' + name,
                    EMU_TELEPHONY[name], false);
                return EMU_TELEPHONY[name];
            };
        } catch (e) { /* método ausente nesta versão */ }
    });
}

// Settings.Secure.ANDROID_ID — constante conhecida de emulador.
function hookSecureSettings() {
    var Secure = null;
    try {
        Secure = Java.use('android.provider.Settings$Secure');
    } catch (e) {
        note('android.provider.Settings$Secure indisponível');
        return;
    }
    var orig = null;
    try {
        orig = Secure.getString.overload(
            'android.content.ContentResolver', 'java.lang.String'
        );
        orig.implementation = function (resolver, name) {
            try {
                if ('' + name === 'android_id') {
                    report('secondary', 'Settings.Secure.getString',
                        'android_id=' + EMU_ANDROID_ID, false);
                    return EMU_ANDROID_ID;
                }
            } catch (e) { /* best-effort */ }
            return orig.call(this, resolver, name);
        };
    } catch (e) {
        note('Settings.Secure.getString indisponível: ' + e);
    }
}

// Runtime.exec — o app lendo properties por "getprop" (canal que o
// spoof não cobre; é registrado para que o relatório seja honesto).
function hookRuntimeExec() {
    var Runtime = null;
    try {
        Runtime = Java.use('java.lang.Runtime');
    } catch (e) { return; }
    try {
        var orig = Runtime.exec.overload('java.lang.String');
        orig.implementation = function (cmd) {
            try {
                var text = '' + cmd;
                if (text.indexOf('getprop') !== -1) {
                    report('secondary', 'Runtime.exec', text, false);
                }
            } catch (e) { /* best-effort */ }
            return orig.call(this, cmd);
        };
    } catch (e) { /* sobrecarga ausente */ }
}

// ----------------------------------------------------------------------
// Observação dos métodos de veredito
// ----------------------------------------------------------------------
function descriptorToType(desc) {
    if (desc === 'I') { return 'int'; }
    if (desc === 'Z') { return 'boolean'; }
    if (desc === 'J') { return 'long'; }
    if (desc === 'D') { return 'double'; }
    if (desc === 'F') { return 'float'; }
    if (desc === 'B') { return 'byte'; }
    if (desc === 'C') { return 'char'; }
    if (desc === 'S') { return 'short'; }
    if (desc === 'V') { return 'void'; }
    if (desc.charAt(0) === 'L') {
        return desc.substring(1, desc.length - 1).replace(/\//g, '.');
    }
    if (desc.charAt(0) === '[') {
        return '[' + descriptorToType(desc.substring(1));
    }
    return desc;
}

function descriptorToTypes(signature) {
    try {
        var open = signature.indexOf('(');
        var close = signature.indexOf(')');
        if (open === -1 || close === -1) { return null; }
        var inner = signature.substring(open + 1, close);
        if (inner === '') { return []; }
        var parts = inner.split(',');
        var out = [];
        for (var i = 0; i < parts.length; i++) {
            out.push(descriptorToType(parts[i]));
        }
        return out;
    } catch (e) { return null; }
}

// Marca o método observado e delega ao original: o comportamento do app
// é preservado, apenas a chamada é registrada.
function hookVerdictMethod(match) {
    try {
        var cls = Java.use(match.className);
        var wrapper = cls[match.methodName];
        if (!wrapper) { return false; }
        var target = wrapper;
        if (typeof wrapper.overload === 'function') {
            var types = descriptorToTypes(match.signature);
            if (types === null) { return false; }
            target = wrapper.overload.apply(wrapper, types);
        }
        var label = match.className + '.' + match.methodName;
        target.implementation = function () {
            report('decisive', 'verdict:' + label, match.signature, false);
            return target.apply(this, arguments);
        };
        return true;
    } catch (e) {
        return false;
    }
}

function observeVerdictMethods() {
    var matches = [];
    try {
        Java.enumerateMethods(EMU_VERDICT_SPECS, {
            onMatch: function (m) { matches.push(m); },
            onComplete: function () { }
        });
    } catch (e) {
        note('enumerateMethods indisponível: ' + e);
        return 0;
    }
    var hooked = 0;
    for (var i = 0; i < matches.length; i++) {
        if (hookVerdictMethod(matches[i])) { hooked++; }
    }
    if (hooked > 0) {
        report('decisive', 'verdict-scan',
            hooked + ' método(s) de veredito de emulador observados', false);
    }
    return hooked;
}

// ----------------------------------------------------------------------
// main
// ----------------------------------------------------------------------
function main() {
    note('emulator_spoof.js carregado (modo=' + MODE + ')');
    if (!JAVA_ONLY) {
        hookNative();
    }
    if (JAVA_ONLY) {
        if (typeof raspilotDeferJava === 'function') {
            raspilotDeferJava(installJavaHooks, 'emulator-spoof');
        } else if (typeof raspilotPerformJava === 'function') {
            raspilotPerformJava(installJavaHooks);
        } else if (typeof Java !== 'undefined' && Java.available) {
            Java.perform(installJavaHooks);
        }
    }
}

main();
