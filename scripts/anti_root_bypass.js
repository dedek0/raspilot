/*
 * RASPilot — Anti-Root Bypass (script injetado via Frida).
 *
 * Contorna mecanismos comuns de detecção de root dentro do app alvo,
 * provando que a presença de root não é bloqueada pelo RASP do app:
 *   - RootBeer (com.scottyab.rootbeer): checkForRoot, detectRoot,
 *     detectRootManagementApps, checkForDangerousApps, checkSuExists...
 *   - File.exists()/canRead() em paths de su e Magisk.
 *   - Runtime.exec()/ProcessBuilder com 'su'/'which su'/'magisk'.
 *   - Propriedades suspeitas via SystemProperties.get.
 *
 * Cada bloco é isolado em try/catch e o script é idempotente.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

var RASPILOT_JAVA_ONLY = (typeof __RASPILOT_JAVA_ONLY__ !== 'undefined')
    ? __RASPILOT_JAVA_ONLY__
    : false;

var ROOT_PATHS = [
    '/system/bin/su', '/system/xbin/su', '/sbin/su', '/vendor/bin/su',
    '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
    '/system/app/Superuser.apk', '/system/xbin/daemonsu',
    '/data/adb/magisk', '/sbin/.magisk', '/system/bin/magisk',
    '/system/bin/busybox', '/system/xbin/busybox'
];

var ROOT_TOKENS = [
    'magisk', 'superuser', 'busybox', 'rootbeer', 'test-keys',
    'daemonsu', 'rootcloak'
];

var SUSPICIOUS_PROPS = {
    'ro.debuggable': '0',
    'ro.secure': '1',
    'service.adb.root': '0',
    'ro.build.tags': 'release-keys'
};

function report(msg) {
    try {
        send({ type: 'raspilot-bypass', message: msg });
    } catch (e) { /* host indisponível */ }
}

function isRootPath(path) {
    try {
        if (path === null || path === undefined) { return false; }
        var p = '' + path;
        for (var i = 0; i < ROOT_PATHS.length; i++) {
            if (p.indexOf(ROOT_PATHS[i]) !== -1) { return true; }
        }
        return p.indexOf('su') !== -1 && p.charAt(p.length - 1) === 'u' &&
               (p.indexOf('/su') !== -1 || p === 'su');
    } catch (e) { return false; }
}

function safeCString(ptr) {
    try {
        if (ptr === null || ptr === undefined) { return ''; }
        var value = ptr.readCString();
        return value === null ? '' : '' + value;
    } catch (e) {
        return '';
    }
}

function containsRootToken(value) {
    try {
        var text = ('' + value).toLowerCase();
        for (var i = 0; i < ROOT_TOKENS.length; i++) {
            if (text.indexOf(ROOT_TOKENS[i]) !== -1) { return true; }
        }
    } catch (e) { /* best-effort */ }
    return false;
}

// ----------------------------------------------------------------------
// 1) Native — paths de root
// ----------------------------------------------------------------------
function hookNativePaths() {
    ['open', 'openat', 'openat64'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var path = safeCString(name === 'open' ? args[0] : args[1]);
                    if (isRootPath(path)) {
                        this._block = true;
                        report('native_' + name + '(' + path + ') -> -1');
                    }
                },
                onLeave: function (retval) {
                    if (this._block) { retval.replace(-1); }
                }
            });
        } catch (e) { report('falha em native_' + name + ': ' + e); }
    });

    ['access', 'stat', 'lstat', 'readlink', 'readlinkat'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var path = safeCString(
                        name === 'readlinkat' ? args[1] : args[0]
                    );
                    if (isRootPath(path)) {
                        this._block = true;
                        report('native_' + name + '(' + path + ') -> -1');
                    }
                },
                onLeave: function (retval) {
                    if (this._block) { retval.replace(-1); }
                }
            });
        } catch (e) { report('falha em native_' + name + ': ' + e); }
    });
}

// ----------------------------------------------------------------------
// 2) Native — buscas de string por root
// ----------------------------------------------------------------------
function hookNativeStrings() {
    ['strstr', 'strcmp'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var a = safeCString(args[0]);
                    var b = safeCString(args[1]);
                    if (containsRootToken(a) || containsRootToken(b)) {
                        this._hide = true;
                        report('native_' + name + ' ocultou token de root');
                    }
                },
                onLeave: function (retval) {
                    if (!this._hide) { return; }
                    if (name === 'strstr') {
                        retval.replace(ptr(0));
                    } else {
                        retval.replace(1);
                    }
                }
            });
        } catch (e) { report('falha em native_' + name + ': ' + e); }
    });

    try {
        var addr = raspilotFindExport('libc.so', '__system_property_get');
        if (addr !== null) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var key = safeCString(args[0]);
                    if (SUSPICIOUS_PROPS.hasOwnProperty(key)) {
                        this._block = true;
                        report('native___system_property_get(' + key + ') -> vazio');
                    }
                },
                onLeave: function (retval) {
                    if (this._block) { retval.replace(0); }
                }
            });
        }
    } catch (e) { report('falha em __system_property_get: ' + e); }
}

// ----------------------------------------------------------------------
// 3) RootBeer
// ----------------------------------------------------------------------
function hookRootBeer() {
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        var methods = [
            'checkForRoot', 'detectRoot', 'detectRootManagementApps',
            'detectPotentiallyDangerousApps', 'detectTestKeys',
            'checkForBinary', 'checkForDangerousProps', 'checkForRWPaths',
            'detectRootCloakingApps', 'checkSuExists', 'checkForRootNative',
            'checkForMagiskBinary', 'isRooted', 'isRootedWithoutBusyBoxCheck'
        ];
        methods.forEach(function (name) {
            try {
                if (RootBeer[name]) {
                    RootBeer[name].implementation = function () {
                        report('RootBeer.' + name + ' -> false');
                        return false;
                    };
                }
            } catch (e) { /* overload ausente nesta versão */ }
        });
        report('RootBeer hooks instalados');
    } catch (e) {
        report('RootBeer ausente — pulado');
    }
}

// ----------------------------------------------------------------------
// 2) File.exists()/canRead() em paths de root
// ----------------------------------------------------------------------
function hookFileApis() {
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = '' + this.getAbsolutePath();
            if (isRootPath(path)) {
                report('File.exists(' + path + ') -> false');
                return false;
            }
            return this.exists();
        };
        File.canRead.implementation = function () {
            var path = '' + this.getAbsolutePath();
            if (isRootPath(path)) {
                report('File.canRead(' + path + ') -> false');
                return false;
            }
            return this.canRead();
        };
        File.canWrite.implementation = function () {
            var path = '' + this.getAbsolutePath();
            if (isRootPath(path)) {
                report('File.canWrite(' + path + ') -> false');
                return false;
            }
            return this.canWrite();
        };
        report('File.exists/canRead/canWrite hookados');
    } catch (e) {
        report('falha ao hookar File: ' + e);
    }
}

// ----------------------------------------------------------------------
// 3) Runtime.exec / ProcessBuilder com su/magisk
// ----------------------------------------------------------------------
function hookExec() {
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (('' + cmd).indexOf('su') !== -1 || ('' + cmd).indexOf('magisk') !== -1) {
                report('Runtime.exec(' + cmd + ') -> IOException');
                throw Java.use('java.io.IOException').$new('su not found');
            }
            return this.exec(cmd);
        };
        report('Runtime.exec hookado');
    } catch (e) {
        report('falha ao hookar Runtime.exec: ' + e);
    }
}

// ----------------------------------------------------------------------
// 4) SystemProperties suspeitas
// ----------------------------------------------------------------------
function hookSystemProperties() {
    try {
        var SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (key) {
            if (SUSPICIOUS_PROPS.hasOwnProperty('' + key)) {
                var value = SUSPICIOUS_PROPS['' + key];
                report('SystemProperties.get(' + key + ') -> ' + value);
                return value;
            }
            return this.get(key);
        };
        SP.get.overload('java.lang.String', 'java.lang.String').implementation =
            function (key, def) {
                if (SUSPICIOUS_PROPS.hasOwnProperty('' + key)) {
                    var value = SUSPICIOUS_PROPS['' + key];
                    report('SystemProperties.get(' + key + ') -> ' + value);
                    return value;
                }
                return this.get(key, def);
            };
        report('SystemProperties hookada');
    } catch (e) {
        report('falha ao hookar SystemProperties: ' + e);
    }
}

function main() {
    report('anti_root_bypass.js carregado');
    if (!RASPILOT_JAVA_ONLY) {
        hookNativePaths();
        hookNativeStrings();
        report('camada nativa de root carregada');
        return;
    }
    var ok = raspilotPerformJava(function () {
        hookRootBeer();
        hookFileApis();
        hookExec();
        hookSystemProperties();
    });
    if (!ok) {
        report('Java indisponível — nada a hookar');
    }
}

main();
