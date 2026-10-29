// RASPilot — probe/bypass de proxy/VPN.
//
// Modo "probe": o app enxerga um proxy HTTP e uma VPN.
// Modo "bypass": os mesmos canais sao ocultados.
// Modo "observe": apenas registra as consultas.
//
// Placeholders substituidos por script_loader: __RASPILOT_PROXY_MODE__.
'use strict';

(function () {
    var MODE = __RASPILOT_PROXY_MODE__;
    var PROBE_HOST = '127.0.0.1';
    var PROBE_PORT = 8888;
    var PROBE_VALUE = PROBE_HOST + ':' + PROBE_PORT;
    var seen = {};

    function sendEvent(kind, channel, method, detail) {
        try {
            send({
                type: 'proxy-detection',
                kind: kind,
                channel: channel,
                method: String(method || ''),
                detail: String(detail || '')
            });
        } catch (error) {
            // A evidencia nunca pode derrubar o agente.
        }
    }

    function note(message) {
        try {
            send({ type: 'proxy-note', message: String(message || '') });
        } catch (error) {
        }
    }

    function isProxyKey(key) {
        return String(key || '').toLowerCase().indexOf('proxy') >= 0;
    }

    function probeValue(key) {
        var lowered = String(key || '').toLowerCase();
        if (lowered === 'http.proxyhost' || lowered === 'https.proxyhost'
                || lowered === 'socksproxyhost') {
            return PROBE_HOST;
        }
        if (lowered === 'http.proxyport' || lowered === 'https.proxyport'
                || lowered === 'socksproxyport') {
            return String(PROBE_PORT);
        }
        if (lowered === 'java.net.usesystemproxies') {
            return 'true';
        }
        if (lowered === 'http.nonproxyhosts') {
            return '';
        }
        return null;
    }

    function emitOnce(kind, channel, method, detail) {
        var key = kind + '|' + channel + '|' + method + '|' + detail;
        if (seen[key]) {
            return;
        }
        seen[key] = true;
        sendEvent(kind, channel, method, detail);
    }

    if (typeof Java === 'undefined' || !Java.available) {
        note('Java bridge indisponivel; camada de proxy/VPN nao instalada');
        return;
    }

    Java.perform(function () {
        try {
            var SystemSetup = Java.use('java.lang.System');
            if (MODE === 'probe') {
                SystemSetup.setProperty('http.proxyHost', PROBE_HOST);
                SystemSetup.setProperty('http.proxyPort', String(PROBE_PORT));
                SystemSetup.setProperty('https.proxyHost', PROBE_HOST);
                SystemSetup.setProperty('https.proxyPort', String(PROBE_PORT));
                SystemSetup.setProperty('java.net.useSystemProxies', 'true');
            } else if (MODE === 'bypass') {
                SystemSetup.clearProperty('http.proxyHost');
                SystemSetup.clearProperty('http.proxyPort');
                SystemSetup.clearProperty('https.proxyHost');
                SystemSetup.clearProperty('https.proxyPort');
                SystemSetup.clearProperty('socksProxyHost');
                SystemSetup.clearProperty('socksProxyPort');
                SystemSetup.setProperty('java.net.useSystemProxies', 'false');
            }
        } catch (error) {
            note('System.setProperty: ' + error);
        }
        try {
            var System = Java.use('java.lang.System');
            var originalGetProperty = System.getProperty.overload(
                'java.lang.String'
            );
            System.getProperty.overload('java.lang.String').implementation =
                function (key) {
                    if (!isProxyKey(key)) {
                        return originalGetProperty.call(this, key);
                    }
                    emitOnce('query', 'proxy', 'System.getProperty', key);
                    if (MODE === 'probe') {
                        var value = probeValue(key);
                        if (value !== null) {
                            emitOnce('spoof', 'proxy',
                                'System.getProperty', key + '=' + value);
                            return value;
                        }
                    } else if (MODE === 'bypass') {
                        emitOnce('mask', 'proxy',
                            'System.getProperty', key);
                        return null;
                    }
                    return originalGetProperty.call(this, key);
                };
        } catch (error) {
            note('System.getProperty: ' + error);
        }

        try {
            var ProxySelector = Java.use('java.net.ProxySelector');
            var Collections = Java.use('java.util.Collections');
            var Proxy = Java.use('java.net.Proxy');
            var originalSelect = ProxySelector.select.overload('java.net.URI');
            ProxySelector.select.overload('java.net.URI').implementation =
                function (uri) {
                    emitOnce('query', 'proxy', 'ProxySelector.select',
                        String(uri));
                    if (MODE === 'probe') {
                        emitOnce('spoof', 'proxy', 'ProxySelector.select',
                            PROBE_VALUE);
                        return originalSelect.call(this, uri);
                    }
                    if (MODE === 'bypass') {
                        emitOnce('mask', 'proxy', 'ProxySelector.select',
                            'NO_PROXY');
                        return Collections.singletonList(
                            Proxy.NO_PROXY.value
                        );
                    }
                    return originalSelect.call(this, uri);
                };
        } catch (error) {
            note('ProxySelector.select: ' + error);
        }

        try {
            var AndroidProxy = Java.use('android.net.Proxy');
            var originalHost = AndroidProxy.getDefaultHost.overload();
            AndroidProxy.getDefaultHost.overload().implementation =
                function () {
                    emitOnce('query', 'proxy', 'Proxy.getDefaultHost', '');
                    if (MODE === 'probe') {
                        emitOnce('spoof', 'proxy',
                            'Proxy.getDefaultHost', PROBE_HOST);
                        return PROBE_HOST;
                    }
                    if (MODE === 'bypass') {
                        emitOnce('mask', 'proxy',
                            'Proxy.getDefaultHost', 'null');
                        return null;
                    }
                    return originalHost.call(this);
                };
            var originalPort = AndroidProxy.getDefaultPort.overload();
            AndroidProxy.getDefaultPort.overload().implementation =
                function () {
                    emitOnce('query', 'proxy', 'Proxy.getDefaultPort', '');
                    if (MODE === 'probe') {
                        emitOnce('spoof', 'proxy',
                            'Proxy.getDefaultPort', String(PROBE_PORT));
                        return PROBE_PORT;
                    }
                    if (MODE === 'bypass') {
                        emitOnce('mask', 'proxy',
                            'Proxy.getDefaultPort', '-1');
                        return -1;
                    }
                    return originalPort.call(this);
                };
        } catch (error) {
            note('android.net.Proxy: ' + error);
        }

        try {
            var LinkProperties = Java.use('android.net.LinkProperties');
            var originalProxy = LinkProperties.getHttpProxy.overload();
            LinkProperties.getHttpProxy.overload().implementation =
                function () {
                    emitOnce('query', 'proxy',
                        'LinkProperties.getHttpProxy', '');
                    if (MODE === 'bypass') {
                        emitOnce('mask', 'proxy',
                            'LinkProperties.getHttpProxy', 'null');
                        return null;
                    }
                    return originalProxy.call(this);
                };
            var originalProxyPort =
                LinkProperties.getHttpProxyPort.overload();
            LinkProperties.getHttpProxyPort.overload().implementation =
                function () {
                    emitOnce('query', 'proxy',
                        'LinkProperties.getHttpProxyPort', '');
                    if (MODE === 'probe') {
                        emitOnce('spoof', 'proxy',
                            'LinkProperties.getHttpProxyPort',
                            String(PROBE_PORT));
                        return PROBE_PORT;
                    }
                    if (MODE === 'bypass') {
                        emitOnce('mask', 'proxy',
                            'LinkProperties.getHttpProxyPort', '-1');
                        return -1;
                    }
                    return originalProxyPort.call(this);
                };
        } catch (error) {
            note('LinkProperties: ' + error);
        }

        try {
            var Capabilities = Java.use('android.net.NetworkCapabilities');
            var originalTransport = Capabilities.hasTransport.overload('int');
            Capabilities.hasTransport.overload('int').implementation =
                function (transport) {
                    if (transport !== 4) {
                        return originalTransport.call(this, transport);
                    }
                    emitOnce('query', 'vpn',
                        'NetworkCapabilities.hasTransport', 'TRANSPORT_VPN');
                    if (MODE === 'probe') {
                        emitOnce('spoof', 'vpn',
                            'NetworkCapabilities.hasTransport',
                            'TRANSPORT_VPN=true');
                        return true;
                    }
                    if (MODE === 'bypass') {
                        emitOnce('mask', 'vpn',
                            'NetworkCapabilities.hasTransport',
                            'TRANSPORT_VPN=false');
                        return false;
                    }
                    return originalTransport.call(this, transport);
                };
        } catch (error) {
            note('NetworkCapabilities: ' + error);
        }

        function hookSettings(className) {
            try {
                var Settings = Java.use(className);
                var original = Settings.getString.overload(
                    'android.content.ContentResolver', 'java.lang.String'
                );
                Settings.getString.overload(
                    'android.content.ContentResolver', 'java.lang.String'
                ).implementation = function (resolver, key) {
                    if (!isProxyKey(key)) {
                        return original.call(this, resolver, key);
                    }
                    emitOnce('query', 'proxy',
                        className + '.getString', key);
                    if (MODE === 'probe') {
                        emitOnce('spoof', 'proxy',
                            className + '.getString', key + '=' + PROBE_VALUE);
                        return PROBE_VALUE;
                    }
                    if (MODE === 'bypass') {
                        emitOnce('mask', 'proxy',
                            className + '.getString', key);
                        return null;
                    }
                    return original.call(this, resolver, key);
                };
            } catch (error) {
                note(className + ': ' + error);
            }
        }

        hookSettings('android.provider.Settings$Global');
        hookSettings('android.provider.Settings$Secure');

        try {
            var NetworkInterface = Java.use('java.net.NetworkInterface');
            var Collections2 = Java.use('java.util.Collections');
            var ArrayList = Java.use('java.util.ArrayList');
            var originalInterfaces =
                NetworkInterface.getNetworkInterfaces.overload();
            NetworkInterface.getNetworkInterfaces.overload().implementation =
                function () {
                    var enumeration = originalInterfaces.call(this);
                    if (!enumeration || MODE !== 'bypass') {
                        return enumeration;
                    }
                    var kept = ArrayList.$new();
                    var filtered = false;
                    while (enumeration.hasMoreElements()) {
                        var network = enumeration.nextElement();
                        var name = network.getName().toLowerCase();
                        var vpn = name.indexOf('tun') === 0
                            || name.indexOf('tap') === 0
                            || name.indexOf('ppp') === 0
                            || name.indexOf('wg') === 0
                            || name.indexOf('utun') === 0;
                        if (vpn) {
                            emitOnce('query', 'vpn',
                                'NetworkInterface.getNetworkInterfaces',
                                network.getName());
                            filtered = true;
                        } else {
                            kept.add(network);
                        }
                    }
                    if (filtered) {
                        emitOnce('mask', 'vpn',
                            'NetworkInterface.getNetworkInterfaces',
                            'interfaces VPN filtradas');
                    }
                    return Collections2.enumeration(kept);
                };
        } catch (error) {
            note('NetworkInterface: ' + error);
        }

        try {
            var VpnService = Java.use('android.net.VpnService');
            var originalPrepare = VpnService.prepare.overload(
                'android.content.Context'
            );
            VpnService.prepare.overload(
                'android.content.Context'
            ).implementation = function (context) {
                emitOnce('query', 'vpn', 'VpnService.prepare', '');
                if (MODE === 'bypass') {
                    emitOnce('mask', 'vpn', 'VpnService.prepare', 'null');
                    return null;
                }
                return originalPrepare.call(this, context);
            };
        } catch (error) {
            note('VpnService.prepare: ' + error);
        }

        note('camada instalada em modo ' + MODE);
    });
})();
