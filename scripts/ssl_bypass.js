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

// true = apenas hooks Java (após resume); false = apenas nativos
// (antes do resume, sem bridge Java).
var RASPILOT_JAVA_ONLY = (typeof __RASPILOT_JAVA_ONLY__ !== 'undefined')
    ? __RASPILOT_JAVA_ONLY__
    : false;

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

// Extrai o hostname real de sockets/engines Conscrypt. NÃO confundir com
// authType: em checkServerTrusted(chain, authType) o 2º argumento é o
// tipo de autenticação (ex: "ECDHE_RSA"), não o host.
function hostFromTlsObject(obj) {
    try {
        if (obj === null || obj === undefined) { return ''; }
        if (typeof obj.getHostname === 'function') {
            return '' + obj.getHostname();
        }
    } catch (e) { /* best-effort */ }
    return '';
}

// ----------------------------------------------------------------------
// Helpers de tipo
// ----------------------------------------------------------------------

// Converte a cadeia de certificados em java.util.List.
//
// A cadeia recebida é um array Java (X509Certificate[]); os métodos que
// devolvem List esperam um List de verdade. Devolver o array faz a
// ponte lançar uma exceção de incompatibilidade, o que entrega um null
// ao app e quebra o handshake em vez de remover a validação.
function chainToList(chain) {
    try {
        // Alguns métodos já recebem uma List (em vez de array) e a
        // devolvem. Converter a lista em uma nova lista vazia apagaria
        // a cadeia e o handshake passaria a falhar por falta de
        // certificados confiáveis.
        if (chain !== null && chain !== undefined &&
                typeof chain.add === 'function') {
            return chain;
        }
        var ArrayList = Java.use('java.util.ArrayList');
        var list = ArrayList.$new();
        if (chain !== null && chain !== undefined) {
            var n = chain.length;
            for (var i = 0; i < n; i++) { list.add(chain[i]); }
        }
        return list;
    } catch (e) {
        return null;
    }
}

// Extrai o host dos argumentos de um método de validação.
//
// O nome do host aparece em argumentos diferentes conforme a
// implementação: em alguns é o terceiro parâmetro (String), em outros
// vem logo depois do authType.
function hostFromChainArgs(args) {
    try {
        for (var i = 1; i < args.length && i < 4; i++) {
            var v = args[i];
            if (v === null || v === undefined) { continue; }
            if (typeof v === 'string' || v instanceof String) {
                var s = '' + v;
                if (s.indexOf('.') !== -1 && s.indexOf('/') === -1 &&
                        s.indexOf(' ') === -1) {
                    return s;
                }
            }
        }
    } catch (e) { /* best-effort */ }
    return '';
}

// Hooka todos os overloads de um método.
//
// O mesmo nome pode existir em várias variantes — a mesma assinatura
// com tipos de retorno diferentes (a variante que devolve a cadeia e a
// que não devolve nada). Hookar apenas uma delas deixa o caminho real
// de pé, e devolver o tipo errado para a variante escolhida quebra a
// chamada. Cada overload recebe a implementação de acordo com o tipo
// de retorno declarado.
function hookAllOverloads(cls, methodName, impl) {
    var hooked = 0;
    try {
        var method = cls[methodName];
        var overloads = method.overloads;
        for (var i = 0; i < overloads.length; i++) {
            (function (ov) {
                var wantsList = ov.returnType === 'Ljava/util/List;' ||
                    ov.returnType === 'Ljava/util/ArrayList;';
                var isVoid = ov.returnType === 'V' || ov.returnType === 'void';
                ov.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    if (isVoid) {
                        // Método sem retorno: o valor devolvido é
                        // descartado pela ponte, e devolver a cadeia
                        // seria um descompasso entre o que o método
                        // promete e o que entrega.
                        impl(args);
                        return undefined;
                    }
                    var out = impl(args);
                    if (wantsList) {
                        var list = (out !== null && out !== undefined &&
                            typeof out.add === 'function') ? out : chainToList(args[0]);
                        return list;
                    }
                    return (out === undefined || out === null) ? undefined : out;
                };
                hooked++;
            })(overloads[i]);
        }
    } catch (e) {
        log('hookAllOverloads(' + methodName + ') falhou: ' + e);
    }
    return hooked;
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
            // Forma 3: registra no classloader do app. Alguns security SDKs
            // restringem o classloader padrão ("Permission denied").
            try {
                var found = null;
                Java.enumerateClassLoaders({
                    onMatch: function (loader) {
                        if (found !== null) { return; }
                        try {
                            var factory = Java.ClassFactory.get(loader);
                            var TM = factory.use('javax.net.ssl.X509TrustManager');
                            var cls3 = factory.registerClass({
                                name: 'org.raspilot.NoopX509TrustManager',
                                implements: [TM],
                                methods: {
                                    checkClientTrusted: {
                                        returnType: '',
                                        argumentTypes: [
                                            '[Ljava.security.cert.X509Certificate;',
                                            'java.lang.String'
                                        ],
                                        implementation: function (chain, authType) {}
                                    },
                                    checkServerTrusted: {
                                        returnType: '',
                                        argumentTypes: [
                                            '[Ljava.security.cert.X509Certificate;',
                                            'java.lang.String'
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
                            found = cls3.$new();
                        } catch (e) { /* outro classloader */ }
                    },
                    onComplete: function () {}
                });
                if (found !== null) { return found; }
            } catch (err3) { /* enumerate indisponível */ }

            // Classe já registrada (idempotência) — reutiliza.
            try {
                return Java.use('org.raspilot.NoopX509TrustManager').$new();
            } catch (err4) {
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

    // TrustManagerImpl (Conscrypt): todos os overloads de
    // checkServerTrusted e o verifyChain.
    //
    // A implementação precisa devolver exatamente o tipo declarado pelo
    // método. Os overloads de checkServerTrusted existem em duas
    // variantes com a mesma assinatura — uma que devolve a cadeia
    // (List) e uma void — e devolver o tipo errado faz a ponte lançar
    // uma exceção, o que entrega um null ao app e quebra o handshake
    // em vez de remover a validação.
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        var hooked = hookAllOverloads(
            TrustManagerImpl, 'checkServerTrusted', function (args) {
                var authType = '';
                try { authType = '' + args[1]; } catch (e) { }
                var host = hostFromChainArgs(args);
                markHost(host);
                log('TrustManagerImpl.checkServerTrusted bypass (' +
                    (host || 'authType=' + authType) + ')');
                return chainToList(args[0]);
            }
        );
        log('TrustManagerImpl.checkServerTrusted hookado (' + hooked +
            ' overloads)');

        var verifyChain = TrustManagerImpl.verifyChain;
        verifyChain.implementation = function (
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            markHost(host);
            log('TrustManagerImpl.verifyChain bypass (' + host + ')');
            return chainToList(untrustedChain);
        };
        log('TrustManagerImpl.verifyChain hookado');
    } catch (e) {
        log('TrustManagerImpl.verifyChain indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 2) Java — HostnameVerifier
// ----------------------------------------------------------------------
function registerAllowAllVerifier() {
    // Forma 1: classloader padrão.
    try {
        var Verifier = Java.use('javax.net.ssl.HostnameVerifier');
        var cls = Java.registerClass({
            name: 'org.raspilot.AllowAllHostnameVerifier',
            implements: [Verifier],
            methods: {
                verify: function (hostname, session) {
                    try {
                        markHost(hostname);
                        log('HostnameVerifier.verify bypass (' + hostname + ')');
                    } catch (e) { /* best-effort */ }
                    return true;
                }
            }
        });
        return cls.$new();
    } catch (e1) {
        // Forma 2: registra no classloader do app (RX/security SDK).
        try {
            var found = null;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    if (found !== null) { return; }
                    try {
                        var factory = Java.ClassFactory.get(loader);
                        var Verifier2 = factory.use('javax.net.ssl.HostnameVerifier');
                        var cls2 = factory.registerClass({
                            name: 'org.raspilot.AllowAllHostnameVerifier',
                            implements: [Verifier2],
                            methods: {
                                verify: function (hostname, session) {
                                    try {
                                        markHost(hostname);
                                        log('HostnameVerifier.verify bypass (' + hostname + ')');
                                    } catch (e) { /* best-effort */ }
                                    return true;
                                }
                            }
                        });
                        found = cls2.$new();
                    } catch (e) { /* outro classloader */ }
                },
                onComplete: function () {}
            });
            if (found !== null) { return found; }
        } catch (e2) { /* enumerate indisponível */ }

        // Forma 3: classe já registrada (idempotência).
        try {
            return Java.use('org.raspilot.AllowAllHostnameVerifier').$new();
        } catch (e3) {
            log('HostnameVerifier allow-all indisponível: ' + e1 + ' | fallback: ' + e3);
            return null;
        }
    }
}

function hookHostnameVerifier() {
    var allowAll = registerAllowAllVerifier();
    if (allowAll === null) {
        log('HostnameVerifier: nenhum verifier allow-all disponível');
    }

    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
            try {
                // Substitui o verifier do app por um allow-all, em vez de
                // apenas ignorar a chamada (que deixaria o anterior ativo).
                if (allowAll !== null) {
                    log('setDefaultHostnameVerifier -> allow-all');
                    return this.setDefaultHostnameVerifier(allowAll);
                }
            } catch (e) { /* best-effort */ }
            return this.setDefaultHostnameVerifier(v);
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
            try {
                if (allowAll !== null) {
                    log('setHostnameVerifier -> allow-all');
                    return this.setHostnameVerifier(allowAll);
                }
            } catch (e) { /* best-effort */ }
            return this.setHostnameVerifier(v);
        };
        log('HttpsURLConnection.setHostnameVerifier hookado');

        // O verificador padrão só é trocado se o app chamar o setter.
        // Trocando-o de fato, toda conexão criada depois passa a usar o
        // verificador permissivo — é o que cobre os apps que não
        // configuram verificador nenhum.
        if (allowAll !== null) {
            try {
                HttpsURLConnection.setDefaultHostnameVerifier(allowAll);
                log('HttpsURLConnection.setDefaultHostnameVerifier -> allow-all');
            } catch (e) {
                log('setDefaultHostnameVerifier falhou: ' + e);
            }
        }
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
var okhttpState = { check: false, checkVar: false, chain: false, hostname: false };

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

// Verificadores de host da plataforma.
//
// A verificação de nome é um passo separado da verificação da cadeia:
// um certificado válido para outro host passa pela cadeia e é recusado
// aqui. O verificador da plataforma é o que a JVM usa por padrão.
function hookPlatformHostnameVerifiers() {
    var candidates = [
        'com.android.org.conscrypt.ConscryptHostnameVerifier',
        'com.android.org.conscrypt.CompactHostnameVerifier'
    ];
    candidates.forEach(function (name) {
        try {
            var cls = Java.use(name);
            var n = hookAllOverloads(cls, 'verify', function (args) {
                var host = '';
                try { host = '' + args[0]; } catch (e) { }
                markHost(host);
                log(name + '.verify bypass (' + host + ')');
                return true;
            });
            if (n > 0) {
                log(name + ' hookado (' + n + ' overloads)');
            }
        } catch (e) { /* verificador ausente */ }
    });
}

function hookOkHttpOnce(attempt) {
    if (!okhttpState.check) {
        var CertificatePinner = useClassAnywhere('okhttp3.CertificatePinner');
        if (CertificatePinner !== null) {
            // Todas as assinaturas: a versão do OkHttp define a forma
            // (List, array ou varargs) e hookar só uma delas deixa o
            // caminho real de pé.
            var n = hookAllOverloads(
                CertificatePinner, 'check', function (args) {
                    var host = '';
                    try { host = '' + args[0]; } catch (e) { }
                    markHost(host);
                    log('OkHttp CertificatePinner.check bypass (' + host + ')');
                }
            );
            if (n > 0) {
                okhttpState.check = true;
                log('OkHttp CertificatePinner.check hookado (' + n +
                    ' overloads)' + retrySuffix(attempt));
            }
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

    if (!okhttpState.hostname) {
        // O verificador de host do OkHttp é o que rejeita o certificado
        // quando o nome não casa, mesmo sem pinning.
        var OkVerifier = useClassAnywhere('okhttp3.internal.tls.OkHostnameVerifier');
        if (OkVerifier !== null) {
            try {
                var n = hookAllOverloads(OkVerifier, 'verify', function (args) {
                    var host = '';
                    try { host = '' + args[0]; } catch (e) { }
                    markHost(host);
                    log('OkHttp OkHostnameVerifier.verify bypass (' + host + ')');
                    return true;
                });
                if (n > 0) {
                    okhttpState.hostname = true;
                    log('OkHttp OkHostnameVerifier hookado (' + n +
                        ' overloads)' + retrySuffix(attempt));
                }
            } catch (e) {
                log('OkHttp OkHostnameVerifier hook falhou: ' + e);
            }
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
    // Todos os overloads: a mesma assinatura aparece em variantes que
    // devolvem a cadeia e variantes void, e a variante com o host
    // explícito só existe em versões mais novas do Android.
    try {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        var n = hookAllOverloads(NSTM, 'checkServerTrusted', function (args) {
            var authType = '';
            try { authType = '' + args[1]; } catch (e) { }
            var host = hostFromChainArgs(args);
            markHost(host);
            log('NetworkSecurityTrustManager.checkServerTrusted bypass (' +
                (host || 'authType=' + authType) + ')');
            return chainToList(args[0]);
        });
        log('NetworkSecurityTrustManager hookado (' + n + ' overloads)');
    } catch (e) {
        log('NetworkSecurityTrustManager indisponível: ' + e);
    }

    try {
        var RootTrustManager = Java.use('android.security.net.config.RootTrustManager');
        var m = hookAllOverloads(RootTrustManager, 'checkServerTrusted', function (args) {
            var authType = '';
            try { authType = '' + args[1]; } catch (e) { }
            var host = hostFromChainArgs(args);
            markHost(host);
            log('RootTrustManager.checkServerTrusted bypass (' +
                (host || 'authType=' + authType) + ')');
            return chainToList(args[0]);
        });
        log('RootTrustManager hookado (' + m + ' overloads)');
    } catch (e) {
        log('RootTrustManager indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 6) Conscrypt Platform
// ----------------------------------------------------------------------
function hookConscrypt() {
    // A assinatura mudou entre versões do Conscrypt: as mais antigas
    // recebem o socket ou o engine, as mais recentes recebem o host.
    // Hookar todas as variantes cobre as duas.
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        var n = hookAllOverloads(Platform, 'checkServerTrusted', function (args) {
            var authType = '';
            try { authType = '' + args[2]; } catch (e) { }
            var host = '';
            for (var i = 1; i < args.length; i++) {
                var h = hostFromTlsObject(args[i]);
                if (h !== '') { host = h; break; }
            }
            if (host === '') { host = hostFromChainArgs(args); }
            markHost(host);
            log('Conscrypt Platform.checkServerTrusted bypass (' +
                (host || 'authType=' + authType) + ')');
            return chainToList(args[1]);
        });
        log('Conscrypt Platform.checkServerTrusted hookado (' + n +
            ' overloads)');
    } catch (e) {
        log('Conscrypt Platform indisponível: ' + e);
    }
}

// ----------------------------------------------------------------------
// 8) WebView — onReceivedSslError -> proceed()
// ----------------------------------------------------------------------
function hookWebView() {
    // A classe base não basta: o app quase sempre sobrescreve
    // onReceivedSslError, e a sobrescrita tem o próprio ArtMethod — o
    // gancho na base não é chamado.
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            log('WebViewClient.onReceivedSslError -> proceed()');
            handler.proceed();
        };
        log('WebViewClient.onReceivedSslError hookado (classe base)');
    } catch (e) {
        log('WebViewClient indisponível: ' + e);
    }

    // Procura as instâncias vivas e hooka a classe concreta de cada
    // uma, que é a que o WebView realmente invoca.
    try {
        var hookedClasses = {};
        Java.choose('android.webkit.WebViewClient', {
            onMatch: function (instance) {
                try {
                    var cls = instance.getClass();
                    var name = '' + cls.getName();
                    if (hookedClasses[name]) { return; }
                    hookedClasses[name] = true;
                    var concrete = Java.use(name);
                    concrete.onReceivedSslError.implementation = function (view, handler, error) {
                        log('WebViewClient[' + name + '].onReceivedSslError -> proceed()');
                        handler.proceed();
                    };
                    log('WebViewClient concreto hookado: ' + name);
                } catch (e) { /* classe sem o método */ }
            },
            onComplete: function () {
                log('varredura de WebViewClient concluída (' +
                    Object.keys(hookedClasses).length + ' classes)');
            }
        });
    } catch (e) {
        log('varredura de WebViewClient indisponível: ' + e);
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

// Callbacks nativos que precisam sobreviver à chamada que os criou.
var nativeCallbacks = [];

function hookNativeSsl() {
    var libs = ['libssl.so', 'libboringssl.so', 'libconscrypt_jni.so'];
    // A mesma função pode estar exportada por mais de uma biblioteca.
    // Hooká-la duas vezes cria dois interceptors para o mesmo endereço
    // e, no caso do verificador customizado, dois callbacks — o
    // segundo substitui o primeiro, que fica apontando para memória
    // liberada.
    var hookedAddresses = {};
    libs.forEach(function (lib) {
        // SSL_CTX_set_custom_verify (BoringSSL): callback sempre X509_V_OK.
        // Nota: args[0] é SSL_CTX* (não SSL*) — o host/SNI só é possível
        // dentro do callback, que recebe o SSL* real.
        try {
            var customVerify = raspilotFindExport(lib, 'SSL_CTX_set_custom_verify');
            if (customVerify !== null && !hookedAddresses[customVerify]) {
                hookedAddresses[customVerify] = true;
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
                            // O callback precisa sobreviver à chamada: a
                            // biblioteca guarda o ponteiro e o invoca no
                            // próximo handshake. Mantido em uma lista do
                            // módulo, um callback preso apenas ao
                            // contexto da chamada seria liberado e o
                            // contexto ficaria com um ponteiro inválido.
                            nativeCallbacks.push(callback);
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
            if (getVerifyResult !== null && !hookedAddresses[getVerifyResult]) {
                hookedAddresses[getVerifyResult] = true;
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
            if (setVerify !== null && !hookedAddresses[setVerify]) {
                hookedAddresses[setVerify] = true;
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

        // SSL_set_verify: variante por conexão. É a que as bibliotecas
        // nativas usam; sem ela a validação continua valendo mesmo com
        // o contexto neutralizado.
        try {
            var sslSetVerify = raspilotFindExport(lib, 'SSL_set_verify');
            if (sslSetVerify !== null && !hookedAddresses[sslSetVerify]) {
                hookedAddresses[sslSetVerify] = true;
                Interceptor.attach(sslSetVerify, {
                    onEnter: function (args) {
                        args[1] = ptr(0); // SSL_VERIFY_NONE
                        logOnce(lib + '.ssl_set_verify',
                            lib + ': SSL_set_verify -> SSL_VERIFY_NONE');
                    }
                });
                log(lib + ': SSL_set_verify hookado');
            }
        } catch (e) { /* sem export */ }

        // X509_verify_cert: verificação direta da cadeia, usada por
        // quem faz a validação por conta própria.
        try {
            var x509Verify = raspilotFindExport(lib, 'X509_verify_cert');
            if (x509Verify !== null && !hookedAddresses[x509Verify]) {
                hookedAddresses[x509Verify] = true;
                Interceptor.attach(x509Verify, {
                    onLeave: function (retval) {
                        retval.replace(ptr(1)); // X509_V_OK
                        logOnce(lib + '.x509_verify_cert',
                            lib + ': X509_verify_cert -> X509_V_OK');
                    }
                });
                log(lib + ': X509_verify_cert hookado');
            }
        } catch (e) { /* sem export */ }
    });
}

// ----------------------------------------------------------------------
// 10) Flutter — ssl_verify_result + ber
// ----------------------------------------------------------------------
var flutterState = { done: false };

function hookFlutter() {
    if (flutterState.done) { return; }
    var flutter = Process.findModuleByName('libflutter.so');
    if (flutter === null) {
        log('libflutter.so não carregado — hook Flutter pulado');
        return;
    }
    flutterState.done = true;
    try {
        // A BoringSSL costuma estar linkada estaticamente na
        // biblioteca do Flutter, com os símbolos sem visibilidade. O
        // caminho que resolve é o do verificador exportado.
        try {
            var verifyResult = flutter.findExportByName('SSL_get_verify_result');
            if (verifyResult !== null) {
                Interceptor.attach(verifyResult, {
                    onLeave: function (retval) {
                        retval.replace(ptr(0)); // X509_V_OK
                        logOnce('flutter.SSL_get_verify_result',
                            'Flutter SSL_get_verify_result -> X509_V_OK');
                    }
                });
                log('Flutter SSL_get_verify_result hookado');
            }
        } catch (e) { /* sem export */ }

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

    // Instalação SÍNCRONA: o host faz resume logo após script.load(). Se
    // os hooks fossem adiados com setImmediate, validações de certificado
    // da inicialização poderiam rodar antes deles.
    //
    // A camada Java, porém, é adiada: instalá-la durante o carregamento
    // bloqueia o load pelo tempo de inicialização do runtime Java no
    // processo alvo, e o agente descarta o script ao atingir o limite.
    var javaOk = raspilotDeferJava(function () {
        hookTrustManager();
        hookHostnameVerifier();
        hookPlatformHostnameVerifiers();
        hookOkHttpOnce(0);
        hookNetworkSecurityConfig();
        hookConscrypt();
        hookWebView();
    }, 'ssl-bypass');
    if (!javaOk) {
        log('Java indisponível — apenas hooks nativos instalados');
    }
    scheduleOkHttpRetries();

    if (!RASPILOT_JAVA_ONLY) {
        hookNativeSsl();
        hookFlutter();
        // Flutter pode carregar libflutter.so um pouco depois do spawn.
        [2500, 6000, 12000].forEach(function (delay) {
            setTimeout(function () {
                try {
                    if (!flutterState.done) {
                        hookFlutter();
                    }
                } catch (e) { /* best-effort */ }
            }, delay);
        });
    }
}

main();
