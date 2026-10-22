/*
 * RASPilot — Probe de aceitação de cadeia comprometida (eMudhra emSign ECC G3).
 *
 * Injetado pelo check `revoked_ca`. Conecta, a partir do processo do app,
 * a um servidor TLS local montado pelo host (exposto no device via
 * `adb reverse`) que apresenta um leaf assinado por um intermediário
 * eMudhra de chave fraca (bug Mozilla 2083449). O objetivo é medir se o
 * trust path do runtime ACEITA uma cadeia ancorada em CA comprometida e
 * revogada — sem tocar em pinning (é um teste de cadeia, não de unpinning).
 *
 * Dois probes, reportados separadamente:
 *   - system     : SSLContext novo com os CAs de plataforma (cacerts do
 *                  device) — responde "o trust store ainda confia na CA?"
 *   - app_default: javax.net.ssl.SSLContext.getDefault() do processo —
 *                  responde "o DEFAULT do app aceitaria o MITM?" (inclui
 *                  eventuais substituições feitas pelo app)
 *
 * Semântica das mensagens (importante para o veredito do check):
 *   - Instalação: "probe emudhra carregado" — diagnóstico, NUNCA conta.
 *   - Resultado: mensagens `emudhra-probe` com result "accepted"/"rejected".
 *     "accepted" = o handshake completou = a cadeia comprometida foi
 *     confiada. "rejected" = handshake falhou (ex: SSLHandshakeException).
 *
 * Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
 */

'use strict';

// Porta do servidor TLS de teste (host -> device via adb reverse).
var TEST_PORT = __RASPILOT_TEST_PORT__;
// URL de teste (SAN localhost/127.0.0.1 presente no leaf emitido).
var TEST_URL = '__RASPILOT_TEST_URL__';

function report(probe, result, detail) {
    try {
        send({ type: 'emudhra-probe', probe: probe, result: result, detail: detail || '' });
    } catch (e) { /* host indisponível */ }
}

function errText(e) {
    try {
        if (e !== null && e !== undefined && typeof e.getClass === 'function') {
            return '' + e.getClass().getName() + ': ' + e.getMessage();
        }
    } catch (ignored) { /* best-effort */ }
    return '' + e;
}

// Probe 1: trust store de plataforma (cacerts do device).
function probeSystem() {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TMF = Java.use('javax.net.ssl.TrustManagerFactory');
    var KeyStore = Java.use('java.security.KeyStore');
    var socket = null;
    try {
        var tmf = TMF.getInstance(TMF.getDefaultAlgorithm());
        // null = KeyStore default (cacerts de plataforma).
        tmf.init(KeyStore.nullValue());
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, tmf.getTrustManagers(), null);
        socket = ctx.getSocketFactory().createSocket('127.0.0.1', TEST_PORT);
        socket.setUseClientMode(true);
        var params = socket.getSSLParameters();
        // Endpoint identification = verificação de hostname padrão.
        params.setEndpointIdentificationAlgorithm('HTTPS');
        socket.setSSLParameters(params);
        socket.startHandshake();
        var chain = socket.getSession().getPeerCertificates();
        report('system', 'accepted', 'chain=' + chain.length);
    } catch (e) {
        report('system', 'rejected', errText(e));
    } finally {
        try { if (socket !== null) { socket.close(); } } catch (ignored) { /* best-effort */ }
    }
}

// Probe 2: SSLContext default do processo (pode conter customizações do app).
function probeAppDefault() {
    var URL = Java.use('java.net.URL');
    var conn = null;
    try {
        var url = URL.$new(TEST_URL);
        conn = url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestMethod('GET');
        var code = conn.getResponseCode(); // lança SSLHandshakeException se rejeitar
        report('app_default', 'accepted', 'http=' + code);
    } catch (e) {
        report('app_default', 'rejected', errText(e));
    } finally {
        try { if (conn !== null) { conn.disconnect(); } } catch (ignored) { /* best-effort */ }
    }
}

function runProbes() {
    try {
        probeSystem();
        probeAppDefault();
    } catch (e) {
        report('probe', 'error', errText(e));
    }
}

Java.perform(function () {
    report('loaded', 'loaded', 'probe emudhra carregado');
    // Os handshakes bloqueiam a thread: roda em thread Java própria para
    // não prender a thread do script (unload/detach no fim da janela).
    try {
        var Runnable = Java.use('java.lang.Runnable');
        var Runner = Java.registerClass({
            name: 'org.raspilot.emudhraProbe',
            implements: [Runnable],
            methods: {
                run: function () {
                    Java.perform(function () { runProbes(); });
                },
            },
        });
        var thread = Java.use('java.lang.Thread').$new(Runner.$new());
        thread.start();
    } catch (e) {
        // registerClass falha se a classe já existe (reinjeção): roda direto.
        runProbes();
    }
});
