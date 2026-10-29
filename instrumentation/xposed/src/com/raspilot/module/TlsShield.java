package com.raspilot.module;

import android.content.Intent;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * Camada TLS genérica.
 *
 * Um proxy de auditoria (Burp, mitmproxy etc.) apresenta um CA próprio.
 * Apps que fixam certificado ou usam um TrustManager restritivo derrubam
 * o handshake antes de qualquer checagem de proxy. Esta camada neutraliza
 * a validação do lado do cliente para que o tráfego continue inspecionável.
 *
 * Não depende de pacote, host ou biblioteca específica: cobre as camadas
 * Java/OkHttp/Conscrypt/WebView mais comuns. Hooks nativos (BoringSSL,
 * Flutter) permanecem fora do módulo.
 */
public final class TlsShield {

    private TlsShield() {
    }

    /** TrustManager que aceita qualquer cadeia. */
    private static final class PermissiveTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    /**
     * Instala a camada TLS.
     *
     * @param classLoader ClassLoader do app alvo.
     */
    public static void install(ClassLoader classLoader) {
        hookSslContext();
        hookTrustManagerFactory();
        hookTrustManagerExtensions(classLoader);
        hookConscryptPlatform();
        hookOkHttpPinners(classLoader);
        hookHostnameVerifiers(classLoader);
        hookWebView(classLoader);
        filterNetworkEvents();
        Evidence.emit("neutralize", "tls", "TlsShield.install",
                "validação de certificado neutralizada");
    }

    private static TrustManager[] permissiveManagers() {
        return new TrustManager[]{new PermissiveTrustManager()};
    }

    private static void hookSslContext() {
        try {
            XposedHelpers.findAndHookMethod(
                    SSLContext.class, "init",
                    KeyManager[].class, TrustManager[].class, SecureRandom.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[1] = permissiveManagers();
                            Evidence.emit("neutralize", "tls",
                                    "SSLContext.init", "trust manager permissivo");
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("tls.SSLContext.init", error);
        }
    }

    private static void hookTrustManagerFactory() {
        try {
            XposedHelpers.findAndHookMethod(
                    TrustManagerFactory.class, "getTrustManagers",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            param.setResult(permissiveManagers());
                            Evidence.emit("neutralize", "tls",
                                    "TrustManagerFactory.getTrustManagers",
                                    "trust managers permissivos");
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("tls.TrustManagerFactory", error);
        }
    }

    private static void hookTrustManagerExtensions(ClassLoader classLoader) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(
                    "android.net.http.X509TrustManagerExtensions", classLoader);
            if (clazz == null) {
                return;
            }
            XposedBridge.hookAllMethods(clazz, "checkServerTrusted",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            param.setResult(Collections.emptyList());
                            Evidence.emit("neutralize", "tls",
                                    "X509TrustManagerExtensions.checkServerTrusted",
                                    "cadeia aceita");
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("tls.X509TrustManagerExtensions", error);
        }
    }

    private static void hookConscryptPlatform() {
        try {
            Class<?> clazz = Class.forName("com.android.org.conscrypt.Platform");
            XposedBridge.hookAllMethods(clazz, "checkServerTrusted",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(null);
                            Evidence.emit("neutralize", "tls",
                                    "Conscrypt.Platform.checkServerTrusted",
                                    "validação ignorada");
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("tls.ConscryptPlatform", error);
        }
    }

    private static void hookOkHttpPinners(ClassLoader classLoader) {
        for (String name : new String[]{
                "okhttp3.CertificatePinner",
                "com.android.okhttp.CertificatePinner",
        }) {
            try {
                Class<?> clazz = XposedHelpers.findClassIfExists(name, classLoader);
                if (clazz == null) {
                    continue;
                }
                for (String method : new String[]{
                        "check", "check$okhttp",
                }) {
                    XposedBridge.hookAllMethods(clazz, method,
                            new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam param) {
                                    param.setResult(null);
                                    Evidence.emit("neutralize", "tls",
                                            "CertificatePinner." + method,
                                            "pin ignorado");
                                }
                            });
                }
            } catch (Throwable error) {
                Evidence.error("tls.CertificatePinner", error);
            }
        }
    }

    private static void hookHostnameVerifiers(ClassLoader classLoader) {
        for (String name : new String[]{
                "okhttp3.internal.tls.OkHostnameVerifier",
                "org.apache.http.conn.ssl.AbstractVerifier",
        }) {
            try {
                Class<?> clazz = XposedHelpers.findClassIfExists(name, classLoader);
                if (clazz == null) {
                    continue;
                }
                XposedBridge.hookAllMethods(clazz, "verify",
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                param.setResult(true);
                                Evidence.emit("neutralize", "tls",
                                        "HostnameVerifier.verify",
                                        "hostname aceito");
                            }
                        });
            } catch (Throwable error) {
                Evidence.error("tls.HostnameVerifier", error);
            }
        }
        try {
            XposedHelpers.findAndHookMethod(
                    HostnameVerifier.class, "verify", String.class,
                    SSLSession.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(true);
                            Evidence.emit("neutralize", "tls",
                                    "HostnameVerifier.verify", "hostname aceito");
                        }
                    });
        } catch (Throwable ignored) {
            // A interface não é hookável em todas as versões; os
            // verificadores concretos acima continuam valendo.
        }
    }

    private static void hookWebView(ClassLoader classLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                    WebViewClient.class, "onReceivedSslError",
                    WebView.class, SslErrorHandler.class,
                    android.net.http.SslError.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            try {
                                XposedHelpers.callMethod(param.args[1], "proceed");
                                param.setResult(null);
                                Evidence.emit("neutralize", "tls",
                                        "WebViewClient.onReceivedSslError",
                                        "erro TLS ignorado");
                            } catch (Throwable error) {
                                Evidence.error("tls.WebView", error);
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("tls.WebView", error);
        }
    }

    /** Eventos de ameaça de rede/TLS que o app não precisa ver. */
    private static final String[] PROXY_TLS_EVENTS = {
            "NetworkProxyConfigured",
            "SslCertificateValidationFailed",
            "SslIntegrityCheckFail",
            "SslNonSslConnection",
    };

    private static void filterNetworkEvents() {
        try {
            Class<?> clazz = Class.forName("android.app.ContextImpl");
            XC_MethodHook callback = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    for (Object arg : param.args) {
                        if (!(arg instanceof Intent)) {
                            continue;
                        }
                        Intent intent = (Intent) arg;
                        String action = intent.getAction();
                        logNetworkEvent(intent, action);
                        if (isProxyTlsEvent(action)) {
                            param.setResult(null);
                            Evidence.emit("neutralize", "tls",
                                    "event", String.valueOf(action));
                            return;
                        }
                    }
                }
            };
            for (String name : new String[]{
                    "sendBroadcast",
                    "sendOrderedBroadcast",
                    "sendBroadcastAsUser",
                    "sendOrderedBroadcastAsUser",
            }) {
                XposedBridge.hookAllMethods(clazz, name, callback);
            }
        } catch (Throwable error) {
            Evidence.error("tls.ContextImpl", error);
        }
        try {
            Class<?> clazz = Class.forName(
                    "androidx.localbroadcastmanager.content.LocalBroadcastManager");
            XposedBridge.hookAllMethods(clazz, "sendBroadcast",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            for (Object arg : param.args) {
                                if (arg instanceof Intent
                                        && isProxyTlsEvent(
                                                ((Intent) arg).getAction())) {
                                    param.setResult(null);
                                    Evidence.emit("neutralize", "tls",
                                            "event-local",
                                            String.valueOf(((Intent) arg).getAction()));
                                    return;
                                }
                            }
                        }
                    });
        } catch (Throwable ignored) {
            // App pode não empacotar o LocalBroadcastManager.
        }
    }

    private static void logNetworkEvent(Intent intent, String action) {
        try {
            String reason = intent.getStringExtra("reasonCode");
            String external = intent.getStringExtra("externalID");
            if (reason == null && external == null) {
                return;
            }
            Evidence.emit("observe", "tls", "event",
                    "action=" + action + " external=" + external
                            + " reason=" + reason);
        } catch (Throwable ignored) {
            // Diagnóstico nunca derruba o processo.
        }
    }

    private static boolean isProxyTlsEvent(String action) {
        if (action == null) {
            return false;
        }
        for (String event : PROXY_TLS_EVENTS) {
            if (event.equals(action)) {
                return true;
            }
        }
        return false;
    }
}
