/*
 * RASPilot — SSL Pinning Bypass universal (script injetado via Frida).
 *
 * Cobre todas as camadas comuns de SSL pinning em apps Android:
 *   1.  Java TrustManager (X509TrustManager)
 *   2.  HostnameVerifier
 *   3.  OkHttp 3/4 CertificatePinner (overloads check / check$okhttp)
 *   4.  OkHttp CertificateChainCleaner
 *   5.  NetworkSecurityConfig (NetworkSecurityTrustManager, RootTrustManager)
 *   6.  Conscrypt (Platform.checkServerTrusted, TrustManagerImpl.verifyChain)
 *   7.  Apache HttpClient (AbstractVerifier.verify)
 *   8.  WebView (WebViewClient.onReceivedSslError -> proceed)
 *   9.  Native BoringSSL/OpenSSL (SSL_CTX_set_custom_verify, SSL_get_verify_result,
 *       SSL_CTX_set_verify)
 *   10. Flutter (libflutter.so — ssl_verify_result e o ber interno)
 *
 * Cada bloco é isolado em try/catch e o script é idempotente, para
 * funcionar em múltiplas versões de Android, libs e frameworks.
 * Mensagens de console são capturadas pelo RASPilot para evidência.
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// Hosts interceptados durante a sessão (para relatório).
var interceptedHosts = [];

function log(msg) {
    try {
        send({ type: 'ssl-bypass', message: msg });
        console.log('[RASPilot SSL] ' + msg);
    } catch (e) { /* host indisponível */ }
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
function hookTrustManager() {
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');

        // Forma objeto do registerClass: a bridge resolve os overloads da
        // interface automaticamente (a forma array exige argumentTypes
        // exatos e falha em versões novas da bridge).
        var noopInstance = null;
        try {
            var TrustManagerCls = Java.registerClass({
                name: 'org.raspilot.NoopX509TrustManager',
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            noopInstance = TrustManagerCls.$new();
        } catch (regErr) {
            // Classe já registrada (idempotência) — reutiliza.
            try {
                noopInstance = Java.use('org.raspilot.NoopX509TrustManager').$new();
            } catch (e2) {
                log('TrustManager noop indisponível: ' + e2);
            }
        }

        if (noopInstance !== null) {
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                log('SSLContext.init interceptado');
                this.init(km, [noopInstance], sr);
            };
            log('X509TrustManager + SSLContext.init hookados');
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
    } catch (e) { /* versão sem conscrypt exposta */ }
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
        log('HttpsURLConnection hostnameverifier neutralizado');
    } catch (e) {
        log('HostnameVerifier hook falhou: ' + e);
    }

    try {
        var AllowAllHostnameVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AllowAllHostnameVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function (host, valid, altnames, strict) {
            markHost(host);
            log('Apache AbstractVerifier.verify bypass (' + host + ')');
        };
        log('Apache AbstractVerifier.verify hookado');
    } catch (e) { /* Apache HttpClient ausente */ }
}

// ----------------------------------------------------------------------
// 3+4) OkHttp — CertificatePinner e CertificateChainCleaner
// ----------------------------------------------------------------------
function hookOkHttp() {
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peerCerts) {
            markHost(host);
            log('OkHttp CertificatePinner.check bypass (' + host + ')');
            return;
        };
        log('OkHttp CertificatePinner.check(String, List) hookado');
    } catch (e) { /* okhttp3 ausente */ }

    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        // OkHttp 4 (Kotlin): check$okhttp com Function0.
        CertificatePinner['check$okhttp'].implementation = function (host, cleanedChain, closure) {
            markHost(host);
            log('OkHttp CertificatePinner.check$okhttp bypass (' + host + ')');
            return;
        };
        log('OkHttp CertificatePinner.check$okhttp hookado');
    } catch (e) { /* sem overload $okhttp */ }

    try {
        var Builder = Java.use('okhttp3.CertificatePinner$Builder');
        Builder.add.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (pattern, pins) {
            log('CertificatePinner.Builder.add ignorado (' + pattern + ')');
            return this;
        };
    } catch (e) { /* sem Builder exposto */ }

    try {
        var CertificateChainCleaner = Java.use('okhttp3.internal.tls.CertificateChainCleaner');
        CertificateChainCleaner.clean.implementation = function (hostname, peerCertificates) {
            markHost(hostname);
            log('CertificateChainCleaner.clean bypass (' + hostname + ')');
            return peerCertificates;
        };
        log('CertificateChainCleaner.clean hookado');
    } catch (e) { /* variante diferente */ }
}

// ----------------------------------------------------------------------
// 5) NetworkSecurityConfig (Android 7+)
// ----------------------------------------------------------------------
function hookNetworkSecurityConfig() {
    try {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSTM.checkServerTrusted.implementation = function (chain, authType) {
            log('NetworkSecurityTrustManager.checkServerTrusted bypass');
        };
        log('NetworkSecurityTrustManager hookada');
    } catch (e) { /* API < 24 ou sem NSC */ }

    try {
        var RootTrustManager = Java.use('android.security.net.config.RootTrustManager');
        RootTrustManager.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
        ).implementation = function (chain, host) {
            markHost(host);
            log('RootTrustManager.checkServerTrusted bypass (' + host + ')');
        };
        log('RootTrustManager hookada');
    } catch (e) { /* variante ausente */ }
}

// ----------------------------------------------------------------------
// 6) Conscrypt Platform
// ----------------------------------------------------------------------
function hookConscrypt() {
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.implementation = function (x509TrustManagerImpl, bytes, s) {
            log('Conscrypt Platform.checkServerTrusted bypass');
        };
        log('Conscrypt Platform.checkServerTrusted hookado');
    } catch (e) { /* sem conscrypt Java */ }
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
    } catch (e) { /* webkit indisponível */ }
}

// ----------------------------------------------------------------------
// 9) Native — BoringSSL / OpenSSL
// ----------------------------------------------------------------------
function hookNativeSsl() {
    var libs = ['libssl.so', 'libboringssl.so', 'libconscrypt_jni.so'];
    libs.forEach(function (lib) {
        // SSL_CTX_set_custom_verify (BoringSSL): callback sempre X509_V_OK.
        try {
            var customVerify = Module.findExportByName(lib, 'SSL_CTX_set_custom_verify');
            if (customVerify !== null) {
                Interceptor.attach(customVerify, {
                    onEnter: function (args) {
                        this._ctx = args[0];
                        try {
                            var SSL_VERIFY_NONE = ptr(0);
                            args[2] = SSL_VERIFY_NONE; // modo
                            var callback = new NativeCallback(function (ssl, outAlert) {
                                return 0; // ssl_verify_ok
                            }, 'int', ['pointer', 'pointer']);
                            args[3] = callback;
                            this._keepalive = callback;
                            log(lib + ': SSL_CTX_set_custom_verify -> NONE/ok');
                        } catch (e) {
                            log(lib + ': custom_verify hook falhou: ' + e);
                        }
                    }
                });
            }
        } catch (e) { /* lib sem o export */ }

        // SSL_get_verify_result -> X509_V_OK (0).
        try {
            var getVerifyResult = Module.findExportByName(lib, 'SSL_get_verify_result');
            if (getVerifyResult !== null) {
                Interceptor.attach(getVerifyResult, {
                    onLeave: function (retval) {
                        retval.replace(ptr(0)); // X509_V_OK
                    }
                });
                log(lib + ': SSL_get_verify_result -> X509_V_OK');
            }
        } catch (e) { /* sem export */ }

        // SSL_CTX_set_verify -> SSL_VERIFY_NONE.
        try {
            var setVerify = Module.findExportByName(lib, 'SSL_CTX_set_verify');
            if (setVerify !== null) {
                Interceptor.attach(setVerify, {
                    onEnter: function (args) {
                        args[1] = ptr(0); // SSL_VERIFY_NONE
                    }
                });
                log(lib + ': SSL_CTX_set_verify -> SSL_VERIFY_NONE');
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
                        }
                    });
                    log('Flutter ' + exp.name + ' -> 0 (ok)');
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
                        }
                    });
                    log('Flutter ' + exp.name + ' -> true');
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

    if (typeof Java === 'undefined' || !Java.available) {
        log('Java indisponível — apenas hooks nativos instalados');
        hookNativeSsl();
        hookFlutter();
        return;
    }

    Java.perform(function () {
        hookTrustManager();
        hookHostnameVerifier();
        hookOkHttp();
        hookNetworkSecurityConfig();
        hookConscrypt();
        hookWebView();
    });

    // Hooks nativos e Flutter podem ser needed independentemente do Java.
    setImmediate(function () {
        hookNativeSsl();
        hookFlutter();
    });
}

setImmediate(main);
