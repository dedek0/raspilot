package com.raspilot.module;

import android.content.ContentResolver;

import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * Camada de proxy/VPN.
 *
 * No modo probe o app enxerga um proxy e uma VPN; no modo bypass os
 * mesmos canais sao ocultados para que o app continue utilizavel sob um
 * proxy de auditoria. O modo observe apenas registra as consultas.
 */
public final class ProxyShield {

    private static final String PROBE_HOST = "127.0.0.1";
    private static final int PROBE_PORT = 8888;
    private static final String PROBE_VALUE = PROBE_HOST + ":" + PROBE_PORT;

    /** Transporte VPN em NetworkCapabilities. */
    private static final int TRANSPORT_VPN = 4;

    private ProxyShield() {
    }

    /**
     * Instala os hooks de proxy/VPN.
     *
     * @param config Configuracao efetiva do modulo.
     * @param classLoader ClassLoader do app alvo.
     */
    public static void install(RaspilotConfig config, ClassLoader classLoader) {
        boolean observe = RaspilotConfig.PROXY_OBSERVE.equals(config.proxyMode);
        boolean probe = config.proxyProbe();
        boolean bypass = config.proxyBypass();
        if (!observe && !probe && !bypass) {
            return;
        }
        hookSystemProperties(observe, probe, bypass);
        hookProxySelector(observe, probe, bypass);
        hookLegacyProxy(observe, probe, bypass);
        hookLinkProperties(observe, probe, bypass);
        hookNetworkCapabilities(observe, probe, bypass);
        hookSettings(observe, probe, bypass);
        hookNetworkInterfaces(observe, bypass);
        hookVpnService(observe, bypass);
        Evidence.emit("observe", "module", "ProxyShield.install",
                "modo=" + config.proxyMode);
    }

    private static String proxyProperty(String key) {
        if (key == null) {
            return null;
        }
        String lowered = key.toLowerCase(Locale.US);
        if (lowered.equals("http.proxyhost") || lowered.equals("https.proxyhost")
                || lowered.equals("socksproxyhost")) {
            return PROBE_HOST;
        }
        if (lowered.equals("http.proxyport") || lowered.equals("https.proxyport")
                || lowered.equals("socksproxyport")) {
            return String.valueOf(PROBE_PORT);
        }
        if (lowered.equals("java.net.usesystemproxies")) {
            return "true";
        }
        if (lowered.equals("http.nonproxyhosts")) {
            return "";
        }
        return null;
    }

    private static boolean isProxyProperty(String key) {
        if (key == null) {
            return false;
        }
        String lowered = key.toLowerCase(Locale.US);
        return lowered.contains("proxy");
    }

    private static void hookSystemProperties(final boolean observe,
                                             final boolean probe,
                                             final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.System", XposedBridge.BOOTCLASSLOADER,
                    "getProperty", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String key = param.args == null || param.args[0] == null
                                    ? null : param.args[0].toString();
                            if (!isProxyProperty(key)) {
                                return;
                            }
                            Evidence.emit("observe", "proxy:proxy",
                                    "System.getProperty", String.valueOf(key));
                            if (probe) {
                                String value = proxyProperty(key);
                                if (value != null) {
                                    param.setResult(value);
                                    Evidence.emit("spoof", "proxy:proxy",
                                            "System.getProperty", key + "=" + value);
                                }
                            } else if (bypass) {
                                param.setResult(null);
                                Evidence.emit("mask", "proxy:proxy",
                                        "System.getProperty", String.valueOf(key));
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("System.getProperty (proxy)", error);
        }
    }

    private static void hookProxySelector(final boolean observe,
                                          final boolean probe,
                                          final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.net.ProxySelector", XposedBridge.BOOTCLASSLOADER,
                    "select", URI.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object uri = param.args == null ? null : param.args[0];
                            Evidence.emit("observe", "proxy:proxy",
                                    "ProxySelector.select", String.valueOf(uri));
                            if (probe) {
                                param.setResult(Collections.singletonList(
                                        new Proxy(
                                                Proxy.Type.HTTP,
                                                new InetSocketAddress(
                                                        PROBE_HOST, PROBE_PORT))));
                                Evidence.emit("spoof", "proxy:proxy",
                                        "ProxySelector.select", PROBE_VALUE);
                            } else if (bypass) {
                                param.setResult(Collections.singletonList(
                                        Proxy.NO_PROXY));
                                Evidence.emit("mask", "proxy:proxy",
                                        "ProxySelector.select", "NO_PROXY");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("ProxySelector.select", error);
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "java.net.ProxySelector", XposedBridge.BOOTCLASSLOADER,
                    "getDefault",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            // getDefault apenas devolve o seletor; nao
                            // revela proxy por si so. Fica como canal
                            // fraco para nao contar como exposicao.
                            Evidence.emit("observe", "proxy:network",
                                    "ProxySelector.getDefault", "consulta");
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("ProxySelector.getDefault", error);
        }
    }

    private static void hookLegacyProxy(final boolean observe,
                                        final boolean probe,
                                        final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.Proxy", XposedBridge.BOOTCLASSLOADER,
                    "getDefaultHost",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Evidence.emit("observe", "proxy:proxy",
                                    "Proxy.getDefaultHost", "consulta");
                            if (probe) {
                                param.setResult(PROBE_HOST);
                                Evidence.emit("spoof", "proxy:proxy",
                                        "Proxy.getDefaultHost", PROBE_HOST);
                            } else if (bypass) {
                                param.setResult(null);
                                Evidence.emit("mask", "proxy:proxy",
                                        "Proxy.getDefaultHost", "null");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("Proxy.getDefaultHost", error);
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.Proxy", XposedBridge.BOOTCLASSLOADER,
                    "getDefaultPort",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Evidence.emit("observe", "proxy:proxy",
                                    "Proxy.getDefaultPort", "consulta");
                            if (probe) {
                                param.setResult(PROBE_PORT);
                                Evidence.emit("spoof", "proxy:proxy",
                                        "Proxy.getDefaultPort",
                                        String.valueOf(PROBE_PORT));
                            } else if (bypass) {
                                param.setResult(-1);
                                Evidence.emit("mask", "proxy:proxy",
                                        "Proxy.getDefaultPort", "-1");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("Proxy.getDefaultPort", error);
        }
    }

    private static void hookLinkProperties(final boolean observe,
                                           final boolean probe,
                                           final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.LinkProperties", XposedBridge.BOOTCLASSLOADER,
                    "getHttpProxy",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Evidence.emit("observe", "proxy:proxy",
                                    "LinkProperties.getHttpProxy", "consulta");
                            if (bypass) {
                                param.setResult(null);
                                Evidence.emit("mask", "proxy:proxy",
                                        "LinkProperties.getHttpProxy", "null");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("LinkProperties.getHttpProxy", error);
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.LinkProperties", XposedBridge.BOOTCLASSLOADER,
                    "getHttpProxyPort",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Evidence.emit("observe", "proxy:proxy",
                                    "LinkProperties.getHttpProxyPort", "consulta");
                            if (probe) {
                                param.setResult(PROBE_PORT);
                                Evidence.emit("spoof", "proxy:proxy",
                                        "LinkProperties.getHttpProxyPort",
                                        String.valueOf(PROBE_PORT));
                            } else if (bypass) {
                                param.setResult(-1);
                                Evidence.emit("mask", "proxy:proxy",
                                        "LinkProperties.getHttpProxyPort", "-1");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("LinkProperties.getHttpProxyPort", error);
        }
    }

    private static void hookNetworkCapabilities(final boolean observe,
                                                final boolean probe,
                                                final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.NetworkCapabilities", XposedBridge.BOOTCLASSLOADER,
                    "hasTransport", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object raw = param.args == null ? null : param.args[0];
                            int transport = raw instanceof Integer
                                    ? ((Integer) raw).intValue() : -1;
                            if (transport != TRANSPORT_VPN) {
                                return;
                            }
                            Evidence.emit("observe", "proxy:vpn",
                                    "NetworkCapabilities.hasTransport",
                                    "TRANSPORT_VPN");
                            if (probe) {
                                param.setResult(true);
                                Evidence.emit("spoof", "proxy:vpn",
                                        "NetworkCapabilities.hasTransport",
                                        "TRANSPORT_VPN=true");
                            } else if (bypass) {
                                param.setResult(false);
                                Evidence.emit("mask", "proxy:vpn",
                                        "NetworkCapabilities.hasTransport",
                                        "TRANSPORT_VPN=false");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("NetworkCapabilities.hasTransport", error);
        }
    }

    private static void hookSettings(final boolean observe,
                                     final boolean probe,
                                     final boolean bypass) {
        hookSettingsClass("android.provider.Settings$Global", observe, probe, bypass);
        hookSettingsClass("android.provider.Settings$Secure", observe, probe, bypass);
    }

    private static void hookSettingsClass(String className, final boolean observe,
                                          final boolean probe,
                                          final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    className, XposedBridge.BOOTCLASSLOADER,
                    "getString", ContentResolver.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object raw = param.args == null ? null : param.args[1];
                            String key = raw == null ? null : raw.toString();
                            if (!isProxyProperty(key)) {
                                return;
                            }
                            Evidence.emit("observe", "proxy:proxy",
                                    className + ".getString", String.valueOf(key));
                            if (probe) {
                                param.setResult(PROBE_VALUE);
                                Evidence.emit("spoof", "proxy:proxy",
                                        className + ".getString",
                                        key + "=" + PROBE_VALUE);
                            } else if (bypass) {
                                param.setResult(null);
                                Evidence.emit("mask", "proxy:proxy",
                                        className + ".getString",
                                        String.valueOf(key));
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error(className + ".getString", error);
        }
    }

    private static void hookNetworkInterfaces(final boolean observe,
                                              final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.net.NetworkInterface", XposedBridge.BOOTCLASSLOADER,
                    "getNetworkInterfaces",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object result = param.getResult();
                            if (!(result instanceof Enumeration)) {
                                return;
                            }
                            List<NetworkInterface> kept = new ArrayList<>();
                            boolean filtered = false;
                            Enumeration<?> items = (Enumeration<?>) result;
                            while (items.hasMoreElements()) {
                                Object item = items.nextElement();
                                if (!(item instanceof NetworkInterface)) {
                                    continue;
                                }
                                NetworkInterface network = (NetworkInterface) item;
                                String name = network.getName();
                                String lowered = name == null
                                        ? "" : name.toLowerCase(Locale.US);
                                boolean vpn = lowered.startsWith("tun")
                                        || lowered.startsWith("tap")
                                        || lowered.startsWith("ppp")
                                        || lowered.startsWith("wg")
                                        || lowered.startsWith("utun");
                                if (vpn) {
                                    Evidence.emit("observe", "proxy:vpn",
                                            "NetworkInterface.getNetworkInterfaces",
                                            name);
                                    filtered = true;
                                    if (!bypass) {
                                        kept.add(network);
                                    }
                                } else {
                                    kept.add(network);
                                }
                            }
                            if (filtered && bypass) {
                                param.setResult(Collections.enumeration(kept));
                                Evidence.emit("mask", "proxy:vpn",
                                        "NetworkInterface.getNetworkInterfaces",
                                        "interfaces VPN filtradas");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("NetworkInterface.getNetworkInterfaces", error);
        }
    }

    private static void hookVpnService(final boolean observe,
                                       final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.VpnService", XposedBridge.BOOTCLASSLOADER,
                    "prepare", android.content.Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Evidence.emit("observe", "proxy:vpn",
                                    "VpnService.prepare", "consulta");
                            if (bypass) {
                                param.setResult(null);
                                Evidence.emit("mask", "proxy:vpn",
                                        "VpnService.prepare", "null");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("VpnService.prepare", error);
        }
    }
}
