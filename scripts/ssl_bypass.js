/*
 * RASPilot — SSL Pinning Bypass universal (script injetado via Frida).
 *
 * Cobre todas as camadas comuns de SSL pinning em apps Android:
 *   1.  Java TrustManager (X509TrustManager via registerClass + SSLContext.init)
 *   2.  HostnameVerifier (HttpsURLConnection + Apache AbstractVerifier)
 *   3.  OkHttp 3/4 CertificatePinner (check(String, List) / check$okhttp),
 *       com retry + enumerateClassLoaders para apps que empacotam o OkHttp
 *       em dex secundário (carregado depois do spawn)
 *   4.  OkHttp CertificateChainCleaner
 *   5.  NetworkSecurityConfig (NetworkSecurityTrustManager, RootTrustManager)
 *   6.  Conscrypt (Platform.checkServerTrusted, TrustManagerImpl.verifyChain)
 *   7.  Apache HttpClient (AbstractVerifier.verify)
 *   8.  WebView (WebViewClient.onReceivedSslError -> proceed)
 *   9.  Native BoringSSL/OpenSSL (SSL_CTX_set_custom_verify, SSL_get_verify_result,
 *       SSL_CTX_set_verify) com captura de host via SSL_get_servername
 *   10. Flutter (libflutter.so — ssl_verify_result e o ber interno)
 *
 * Semântica dos logs (importante para o veredito do check):
 *   - Instalação: "... hookado" / "... indisponível" — diagnóstico, NUNCA
 *     conta como evidência de bypass.
 *   - Interceptação real: "... bypass (host)" / "... interceptado" / com
 *     marcadores em EVIDENCE_MARKERS — só esses comprovam unpinning.
 *
 * Cada bloco é isolado em try/catch e o script é idempotente, para
 * funcionar em múltiplas versões de Android, libs e frameworks.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// Hosts interceptados durante a sessão (para relatório).
var interceptedHosts = [];

// Deduplicação de logs de "primeiro disparo" (hooks muito chamados).
var firedOnce = {};

function log(msg) {
    try {
        send({ type: 'ssl-bypass', message: msg });
    } catch (e) { /* host indisponível */ }
}

function logOnce(key, msg) {
    if (firedOnce[key]) { return; }
    firedOnce[key] = true;
    log(msg);
}

function markHost(host) {
    try {
        if (host && interceptedHosts.indexOf('' + host) === -1) {
            interceptedHosts.push('' + host);
            send({ type: 'ssl-bypass-host', host: '' + host });
        }
    } catch (e) { /* best-effort */ }
}

// ----------------------------------------------------------------------
// 1) Java — X509TrustManager (checkServerTrusted / checkClientTrusted)
// ----------------------------------------------------------------------
function registerNoopTrustManager(TrustManager) {
    // Forma 1: a bridge resolve os overloads da interface automaticamente.
    try {
        var cls = Java.registerClass({
            name: 'org.raspilot.NoopX509TrustManager',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        return cls.$new();
    } catch (err1) {
        // Forma 2: argumentTypes explícitos (algumas versões da bridge
        // exigem a forma detalhada).
        try {
            var cls2 = Java.registerClass({
                name: 'org.raspilot.NoopX509TrustManager',
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: {
                        returnType: '',
                        argumentTypes: [
                            '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
                        ],
                        implementation: function (chain, authType) {}
                    },
                    checkServerTrusted: {
                        returnType: '',
                        argumentTypes: [
                            '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
                        ],
                        implementation: function (chain, authType) {}
                    },
                    getAcceptedIssuers: {
                        returnType: '[Ljava.security.cert.X509Certificate;',
                        argumentTypes: [],
                        implementation: function () { return []; }
                    }
                }
            });
            return cls2.$new();
        } catch (err2) {
            // Classe já registrada (idempotência) — reutiliza.
            try {
                return Java.use('org.raspilot.NoopX509TrustManager').$new();
            } catch (err3) {
                log('TrustManager noop indisponível: ' + err1 + ' | fallback: ' + err2);
                return null;
            }
        }
    }
}

function hookTrustManager() {
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var noopInstance = registerNoopTrustManager(TrustManager);

        if (noopInstance !== null) {
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                log('SSLContext.init interceptado');
                this.init(km, [noopInstance], sr);
            };
            log('X509TrustManager + SSLContext.init hookado');
        }
    } catch (e) {
        log('TrustManager hook falhou: ' + e);
    }

    // TrustManagerImpl (Android/OpenSSL): verifyChain -> no-op.
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            markHost(host);
            log('TrustManagerImpl.verifyChain bypass (' + host + ')');
            return untrustedChain;
        };
        log('TrustManagerImpl.verifyChain hookado');
    } catch (e) {
        log('TrustManagerImpl.verifyChain indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 2) Java — HostnameVerifier
// ----------------------------------------------------------------------
function hookHostnameVerifier() {
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
            log('setDefaultHostnameVerifier ignorado');
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
            log('setHostnameVerifier ignorado');
        };
        log('HttpsURLConnection.setHostnameVerifier hookado');
    } catch (e) {
        log('HostnameVerifier hook falhou: ' + e);
    }

    try {
        var AllowAllHostnameVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AllowAllHostnameVerifier.verify.overload(
            'java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean'
        ).implementation = function (host, valid, altnames, strict) {
            markHost(host);
            log('Apache AbstractVerifier.verify bypass (' + host + ')');
        };
        log('Apache AbstractVerifier.verify hookado');
    } catch (e) {
        log('Apache AbstractVerifier indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 3+4) OkHttp — CertificatePinner e CertificateChainCleaner
// (com retry: em apps com dex secundário a classe só existe depois do spawn)
// ----------------------------------------------------------------------
var OKHTTP_RETRIES = [1000, 3000, 6000, 10000];
var okhttpState = { check: false, checkVar: false, chain: false };

// Procura a classe no classloader padrão e, se ausente, nos classloaders
// enumerados (dex secundário / classloader do RASP).
function useClassAnywhere(name) {
    try {
        return Java.use(name);
    } catch (e) { /* segue para os classloaders */ }
    var found = null;
    try {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                if (found !== null) { return; }
                try {
                    found = Java.ClassFactory.get(loader).use(name);
                } catch (e) { /* outro classloader */ }
            },
            onComplete: function () {}
        });
    } catch (e) { /* enumerate indisponível */ }
    return found;
}

function retrySuffix(attempt) {
    return attempt > 0 ? ' (retry ' + attempt + ')' : '';
}

function hookOkHttpOnce(attempt) {
    if (!okhttpState.check) {
        var CertificatePinner = useClassAnywhere('okhttp3.CertificatePinner');
        if (CertificatePinner !== null) {
            try {
                CertificatePinner.check.overload(
                    'java.lang.String', 'java.util.List'
                ).implementation = function (host, peerCerts) {
                    markHost(host);
                    log('OkHttp CertificatePinner.check bypass (' + host + ')');
                    return;
                };
                okhttpState.check = true;
                log('OkHttp CertificatePinner.check(String, List) hookado' + retrySuffix(attempt));
            } catch (e) {
                log('OkHttp CertificatePinner.check hook falhou: ' + e);
            }
            try {
                CertificatePinner.check.overload(
                    'java.lang.String', '[Ljava.security.cert.Certificate;'
                ).implementation = function (host, certs) {
                    markHost(host);
                    log('OkHttp CertificatePinner.check(String, Certificate[]) bypass (' + host + ')');
                    return;
                };
            } catch (e) { /* sem overload varargs */ }
        } else if (attempt === OKHTTP_RETRIES.length) {
            log('OkHttp CertificatePinner indisponível após retries');
        }
    }

    if (!okhttpState.checkVar) {
        var Pinner4 = useClassAnywhere('okhttp3.CertificatePinner');
        if (Pinner4 !== null) {
            try {
                // OkHttp 4 (Kotlin): check$okhttp com Function0.
                Pinner4['check$okhttp'].implementation = function (host, cleanedChain, closure) {
                    markHost(host);
                    log('OkHttp CertificatePinner.check$okhttp bypass (' + host + ')');
                    return;
                };
                okhttpState.checkVar = true;
                log('OkHttp CertificatePinner.check$okhttp hookado' + retrySuffix(attempt));
            } catch (e) { /* sem overload $okhttp nesta versão */ }
        }
    }

    if (!okhttpState.chain) {
        var Cleaner = useClassAnywhere('okhttp3.internal.tls.CertificateChainCleaner');
        if (Cleaner !== null) {
            try {
                Cleaner.clean.implementation = function (hostname, peerCertificates) {
                    markHost(hostname);
                    log('CertificateChainCleaner.clean bypass (' + hostname + ')');
                    return peerCertificates;
                };
                okhttpState.chain = true;
                log('CertificateChainCleaner.clean hookado' + retrySuffix(attempt));
            } catch (e) {
                log('CertificateChainCleaner.clean hook falhou: ' + e);
            }
        } else if (attempt === OKHTTP_RETRIES.length) {
            log('CertificateChainCleaner indisponível após retries');
        }
    }
}

function scheduleOkHttpRetries() {
    OKHTTP_RETRIES.forEach(function (delay, idx) {
        setTimeout(function () {
            try {
                raspilotPerformJava(function () { hookOkHttpOnce(idx + 1); });
            } catch (e) { /* best-effort */ }
        }, delay);
    });
}

// ----------------------------------------------------------------------
// 5) NetworkSecurityConfig (Android 7+)
// ----------------------------------------------------------------------
function hookNetworkSecurityConfig() {
    try {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSTM.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
        ).implementation = function (chain, authType) {
            log('NetworkSecurityTrustManager.checkServerTrusted bypass (sem host)');
        };
        log('NetworkSecurityTrustManager hookado');
    } catch (e) {
        log('NetworkSecurityTrustManager indisponível: ' + e);
    }

    try {
        var RootTrustManager = Java.use('android.security.net.config.RootTrustManager');
        RootTrustManager.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
        ).implementation = function (chain, host) {
            markHost(host);
            log('RootTrustManager.checkServerTrusted bypass (' + host + ')');
        };
        log('RootTrustManager hookado');
    } catch (e) {
        log('RootTrustManager indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 6) Conscrypt Platform
// ----------------------------------------------------------------------
function hookConscrypt() {
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        try {
            Platform.checkServerTrusted.overload(
                'javax.net.ssl.X509TrustManager',
                '[Ljava.security.cert.X509Certificate;',
                'java.lang.String',
                'com.android.org.conscrypt.AbstractConscryptSocket'
            ).implementation = function (tm, chain, host, socket) {
                log('Conscrypt Platform.checkServerTrusted bypass (' + host + ')');
            };
            log('Conscrypt Platform.checkServerTrusted hookado');
        } catch (e1) {
            Platform.checkServerTrusted.overload(
                'javax.net.ssl.X509TrustManager',
                '[Ljava.security.cert.X509Certificate;',
                'java.lang.String',
                'com.android.org.conscrypt.ConscryptEngine'
            ).implementation = function (tm, chain, host, engine) {
                log('Conscrypt Platform.checkServerTrusted bypass (' + host + ')');
            };
            log('Conscrypt Platform.checkServerTrusted hookado (engine)');
        }
    } catch (e) {
        log('Conscrypt Platform indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 8) WebView — onReceivedSslError -> proceed()
// ----------------------------------------------------------------------
function hookWebView() {
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            log('WebViewClient.onReceivedSslError -> proceed()');
            handler.proceed();
        };
        log('WebViewClient.onReceivedSslError hookado');
    } catch (e) {
        log('WebViewClient indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 9) Native — BoringSSL / OpenSSL (com captura de host via SNI)
// ----------------------------------------------------------------------
var servernameCache = {};

function servernameFn(lib) {
    try {
        if (!(lib in servernameCache)) {
            var addr = raspilotFindExport(lib, 'SSL_get_servername');
            servernameCache[lib] = (addr !== null)
                ? new NativeFunction(addr, 'pointer', ['pointer'])
                : null;
        }
        return servernameCache[lib];
    } catch (e) { return null; }
}

function hostFromSsl(lib, ssl) {
    try {
        var fn = servernameFn(lib);
        if (fn === null || fn === undefined || ssl === undefined || ssl.isNull()) {
            return '';
        }
        var p = fn(ssl);
        if (p.isNull()) { return ''; }
        return p.readCString() || '';
    } catch (e) { return ''; }
}

function hookNativeSsl() {
    var libs = ['libssl.so', 'libboringssl.so', 'libconscrypt_jni.so'];
    libs.forEach(function (lib) {
        // SSL_CTX_set_custom_verify (BoringSSL): callback sempre X509_V_OK.
        // Nota: args[0] é SSL_CTX* (não SSL*) — o host/SNI só é possível
        // dentro do callback, que recebe o SSL* real.
        try {
            var customVerify = raspilotFindExport(lib, 'SSL_CTX_set_custom_verify');
            if (customVerify !== null) {
                Interceptor.attach(customVerify, {
                    onEnter: function (args) {
                        this._ctx = args[0];
                        try {
                            var SSL_VERIFY_NONE = ptr(0);
                            args[2] = SSL_VERIFY_NONE; // modo
                            var callback = new NativeCallback(function (ssl, outAlert) {
                                try {
                                    var host = hostFromSsl(lib, ssl);
                                    markHost(host);
                                    logOnce(lib + '.custom_verify',
                                        lib + ': SSL_CTX_set_custom_verify interceptado' +
                                        (host ? ' (' + host + ')' : ''));
                                } catch (e) { /* best-effort */ }
                                return 0; // ssl_verify_ok
                            }, 'int', ['pointer', 'pointer']);
                            args[3] = callback;
                            this._keepalive = callback;
                        } catch (e) {
                            log(lib + ': custom_verify hook falhou: ' + e);
                        }
                    }
                });
                log(lib + ': SSL_CTX_set_custom_verify hookado');
            }
        } catch (e) { /* lib sem o export */ }

        // SSL_get_verify_result -> X509_V_OK (0) — loga só o primeiro disparo.
        try {
            var getVerifyResult = raspilotFindExport(lib, 'SSL_get_verify_result');
            if (getVerifyResult !== null) {
                Interceptor.attach(getVerifyResult, {
                    onEnter: function (args) {
                        this._host = hostFromSsl(lib, args[0]);
                    },
                    onLeave: function (retval) {
                        retval.replace(ptr(0)); // X509_V_OK
                        markHost(this._host);
                        logOnce(lib + '.get_verify_result',
                            lib + ': SSL_get_verify_result -> X509_V_OK' +
                            (this._host ? ' (' + this._host + ')' : ''));
                    }
                });
                log(lib + ': SSL_get_verify_result hookado');
            }
        } catch (e) { /* sem export */ }

        // SSL_CTX_set_verify -> SSL_VERIFY_NONE — loga só o primeiro disparo.
        try {
            var setVerify = raspilotFindExport(lib, 'SSL_CTX_set_verify');
            if (setVerify !== null) {
                Interceptor.attach(setVerify, {
                    onEnter: function (args) {
                        args[1] = ptr(0); // SSL_VERIFY_NONE
                        logOnce(lib + '.set_verify',
                            lib + ': SSL_CTX_set_verify -> SSL_VERIFY_NONE');
                    }
                });
                log(lib + ': SSL_CTX_set_verify hookado');
            }
        } catch (e) { /* sem export */ }
    });
}

// ----------------------------------------------------------------------
// 10) Flutter — ssl_verify_result + ber
// ----------------------------------------------------------------------
function hookFlutter() {
    var flutter = Process.findModuleByName('libflutter.so');
    if (flutter === null) {
        log('libflutter.so não carregado — hook Flutter pulado');
        return;
    }
    try {
        // ssl_verify_result: força o valor de retorno para 'ok'.
        var exports = flutter.enumerateExports();
        exports.forEach(function (exp) {
            if (exp.name.indexOf('ssl_verify_result') !== -1) {
                try {
                    Interceptor.attach(exp.address, {
                        onLeave: function (retval) {
                            retval.replace(ptr(0));
                            logOnce('flutter.' + exp.name, 'Flutter ' + exp.name + ' -> 0 (ok)');
                        }
                    });
                    log('Flutter ' + exp.name + ' hookado');
                } catch (e) {
                    log('Flutter ' + exp.name + ' hook falhou: ' + e);
                }
            }
            // Hook do ber interno usado na validação de certificado.
            if (exp.name.indexOf('ssl_crypto_x509_session_verify_cert_chain') !== -1) {
                try {
                    Interceptor.attach(exp.address, {
                        onLeave: function (retval) {
                            retval.replace(ptr(1)); // true
                            logOnce('flutter.' + exp.name, 'Flutter ' + exp.name + ' -> true');
                        }
                    });
                    log('Flutter ' + exp.name + ' hookado');
                } catch (e) { /* best-effort */ }
            }
        });
    } catch (e) {
        log('Flutter hook falhou: ' + e);
    }
}

// ----------------------------------------------------------------------
// Bootstrap — idempotente, cada bloco independente
// ----------------------------------------------------------------------
function main() {
    log('ssl_bypass.js carregado');

    var javaOk = raspilotPerformJava(function () {
        hookTrustManager();
        hookHostnameVerifier();
        hookOkHttpOnce(0);
        hookNetworkSecurityConfig();
        hookConscrypt();
        hookWebView();
    });
    if (!javaOk) {
        log('Java indisponível — apenas hooks nativos instalados');
    }
    scheduleOkHttpRetries();

    // Hooks nativos e Flutter podem ser needed independentemente do Java.
    setImmediate(function () {
        hookNativeSsl();
        hookFlutter();
    });
}

setImmediate(main);
