/*
 * RASPilot — Observação de detecção de root pelo app.
 *
 * Registra (sem bloquear) as consultas que o app faz a paths, comandos,
 * propriedades, packages e APIs de RootBeer. A primeira carga é nativa,
 * antes do resume; a segunda é Java, depois do resume.
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

var ROOT_PROPS = [
    'ro.debuggable', 'ro.secure', 'service.adb.root', 'ro.build.tags',
    'ro.build.type', 'ro.boot.verifiedbootstate', 'ro.boot.flash.locked'
];

var ROOT_PACKAGES = [
    'com.topjohnwu.magisk', 'eu.chainfire.supersu',
    'com.koushikdutta.superuser', 'com.noshufou.android.su',
    'com.kingroot.kinguser', 'me.bmax.apatch', 'me.weishu.kernelsu',
    'com.rifsxd.ksunext'
];

var ROOT_TOKENS = [
    'magisk', 'superuser', 'busybox', 'rootbeer', 'test-keys',
    'daemonsu', 'rootcloak'
];

function report(method, detail) {
    try {
        send({ type: 'root-detection', method: method, detail: detail });
    } catch (e) { /* host indisponível */ }
}

function reportError(msg) {
    try {
        send({ type: 'root-detection-error', message: msg });
    } catch (e) { /* host indisponível */ }
}

function lowered(value) {
    try {
        return ('' + value).toLowerCase();
    } catch (e) {
        return '';
    }
}

function isRootPath(value) {
    var text = lowered(value);
    if (!text) { return false; }
    for (var i = 0; i < ROOT_PATHS.length; i++) {
        if (text === ROOT_PATHS[i] || text.indexOf(ROOT_PATHS[i]) !== -1) {
            return true;
        }
    }
    return false;
}

function isRootCommand(value) {
    var text = lowered(value);
    if (!text) { return false; }
    if (text.indexOf('which su') !== -1 || text.indexOf('/su ') !== -1 ||
            text.indexOf('/su') === 0 || text.indexOf('magisk') !== -1 ||
            text.indexOf('busybox') !== -1) {
        return true;
    }
    return /(^|[\s;|&])su($|[\s;|&])/.test(text);
}

function isRootProp(value) {
    var text = lowered(value);
    for (var i = 0; i < ROOT_PROPS.length; i++) {
        if (text === ROOT_PROPS[i]) { return true; }
    }
    return false;
}

function isRootPackage(value) {
    var text = lowered(value);
    for (var i = 0; i < ROOT_PACKAGES.length; i++) {
        if (text === ROOT_PACKAGES[i]) { return true; }
    }
    return false;
}

function containsRootToken(value) {
    var text = lowered(value);
    for (var i = 0; i < ROOT_TOKENS.length; i++) {
        if (text.indexOf(ROOT_TOKENS[i]) !== -1) { return true; }
    }
    return false;
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

if (!RASPILOT_JAVA_ONLY) {
    ['open', 'openat', 'openat64'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var path = safeCString(name === 'open' ? args[0] : args[1]);
                    if (isRootPath(path)) {
                        report('native_' + name, path);
                    }
                }
            });
        } catch (e) { reportError('hook ' + name + ': ' + e); }
    });

    ['access', 'stat', 'lstat', 'readlink', 'readlinkat'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var path = safeCString(
                        (name === 'readlinkat') ? args[1] : args[0]
                    );
                    if (isRootPath(path)) {
                        report('native_' + name, path);
                    }
                }
            });
        } catch (e) { reportError('hook ' + name + ': ' + e); }
    });

    ['strstr', 'strcmp'].forEach(function (name) {
        try {
            var addr = raspilotFindExport('libc.so', name);
            if (addr === null) { return; }
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var a = safeCString(args[0]);
                    var b = safeCString(args[1]);
                    if (containsRootToken(a) || containsRootToken(b)) {
                        report('native_' + name, 'needle=' + (containsRootToken(b) ? b : a));
                    }
                }
            });
        } catch (e) { reportError('hook ' + name + ': ' + e); }
    });
}

if (RASPILOT_JAVA_ONLY) {
    try {
        var File = Java.use('java.io.File');
        ['exists', 'canRead', 'canWrite'].forEach(function (name) {
            try {
                File[name].implementation = function () {
                    var path = '';
                    try { path = '' + this.getAbsolutePath(); } catch (e) { /* ignore */ }
                    if (isRootPath(path)) {
                        report('File.' + name, path);
                    }
                    return this[name]();
                };
            } catch (e) { reportError('File.' + name + ': ' + e); }
        });
    } catch (e) { reportError('File indisponível: ' + e); }

    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (isRootCommand(cmd)) { report('Runtime.exec', '' + cmd); }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
            var joined = '';
            try { joined = cmd.join(' '); } catch (e) { /* ignore */ }
            if (isRootCommand(joined)) { report('Runtime.exec[]', joined); }
            return this.exec(cmd);
        };
    } catch (e) { reportError('Runtime.exec indisponível: ' + e); }

    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var joined = '';
            try { joined = this.command().toString(); } catch (e) { /* ignore */ }
            if (isRootCommand(joined)) { report('ProcessBuilder.start', joined); }
            return this.start();
        };
    } catch (e) { reportError('ProcessBuilder indisponível: ' + e); }

    try {
        var SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (key) {
            if (isRootProp(key)) { report('SystemProperties.get', '' + key); }
            return this.get(key);
        };
        SP.get.overload('java.lang.String', 'java.lang.String').implementation =
            function (key, def) {
                if (isRootProp(key)) { report('SystemProperties.get', '' + key); }
                return this.get(key, def);
            };
    } catch (e) { reportError('SystemProperties indisponível: ' + e); }

    try {
        var PM = Java.use('android.content.pm.PackageManager');
        ['getPackageInfo'].forEach(function (name) {
            try {
                PM[name].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        var pkg = args.length > 0 ? '' + args[0] : '';
                        if (isRootPackage(pkg)) {
                            report('PackageManager.getPackageInfo', pkg);
                        }
                        return overload.apply(this, args);
                    };
                });
            } catch (e) { /* assinatura diferente */ }
        });
    } catch (e) { reportError('PackageManager indisponível: ' + e); }

    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        [
            'checkForRoot', 'detectRoot', 'isRooted', 'isRootedWithoutBusyBoxCheck',
            'checkSuExists', 'detectRootManagementApps', 'checkForMagiskBinary'
        ].forEach(function (name) {
            try {
                if (RootBeer[name]) {
                    RootBeer[name].implementation = function () {
                        report('RootBeer.' + name, 'chamado');
                        return this[name]();
                    };
                }
            } catch (e) { /* overload ausente */ }
        });
    } catch (e) { /* RootBeer não empacotado */ }
}
