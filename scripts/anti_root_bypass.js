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

var ROOT_PATHS = [
    '/system/bin/su', '/system/xbin/su', '/sbin/su', '/vendor/bin/su',
    '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
    '/system/app/Superuser.apk', '/system/xbin/daemonsu',
    '/data/adb/magisk', '/sbin/.magisk', '/system/bin/magisk'
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
        console.log('[RASPilot Root] ' + msg);
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

// ----------------------------------------------------------------------
// 1) RootBeer
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
    if (typeof Java === 'undefined' || !Java.available) {
        report('Java indisponível — nada a hookar');
        return;
    }
    Java.perform(function () {
        hookRootBeer();
        hookFileApis();
        hookExec();
        hookSystemProperties();
    });
}

setImmediate(main);
