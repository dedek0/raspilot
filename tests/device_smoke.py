#!/usr/bin/env python3
"""Teste de device: bypass de SSL pinning ponta a ponta.

Sobe um servidor HTTPS com certificado auto-assinado no host, expoe a
porta no dispositivo e faz uma requisicao HTTPS pelo proprio JVM do app
alvo:

- com o bypass ativo, a requisicao precisa ser aceita (codigo de
  resposta qualquer) — a validacao de cadeia e a de nome foram
  contornadas
- com o bypass desligado, a requisicao precisa falhar na validacao

O segundo passo e o controle: sem ele, um "sucesso" poderia vir de
qualquer outro motivo (o aparelho confiar no certificado, por exemplo).

O controle roda primeiro e em processo novo: os hooks vivem no processo
alvo, entao uma segunda execucao sem reiniciar encontraria o bypass da
primeira ainda instalado.

Uso::

    python tests/device_smoke.py --package <package> [--port 8443]

Requer um dispositivo conectado e o pacote instalado.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import argparse
import http.server
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from device_manager import DeviceManager  # noqa: E402
from script_loader import (  # noqa: E402
    COMPAT_PRELUDE,
    JAVA_BOOTSTRAP,
    java_bridge_prelude,
    render_script,
)

SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)

PROBE = r"""
send({ type: 'probe', op: 'start' });
setImmediate(function () {
    function mark(step, extra) {
        try { send({ type: 'probe', op: step, extra: extra }); }
        catch (e) { }
    }
    try {
        var URL = Java.use('java.net.URL');
        var url = URL.$new('https://localhost:__PORT__/');
        var conn = url.openConnection();
        var Https = Java.cast(conn, Java.use('javax.net.ssl.HttpsURLConnection'));
        Https.setConnectTimeout(10000);
        Https.setReadTimeout(10000);
        mark('http', 'status=' + Https.getResponseCode());
    } catch (e) {
        var d = '';
        try { d = '' + e.javaException; } catch (e2) {
            try { d = '' + e.message; } catch (e3) {
                try { d = String(e); } catch (e4) { }
            }
        }
        mark('http', 'erro=' + d);
    }
    mark('end');
});
"""


def _make_cert(directory: str) -> tuple:
    """Gera um par chave/certificado auto-assinado.

    Args:
        directory: Diretorio onde os arquivos sao gravados.

    Returns:
        Tupla com os caminhos do certificado e da chave.
    """
    cert = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key, "-out", cert, "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - nome exigido pela lib
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def _start_server(cert: str, key: str, port: int):
    """Sobe o servidor HTTPS local.

    Args:
        cert: Caminho do certificado.
        key: Caminho da chave.
        port: Porta de escuta.

    Returns:
        O servidor HTTP em execucao.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    httpd = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _fresh_session(dm: DeviceManager, package: str):
    """Reinicia o app e anexa a uma sessao nova.

    O bypass vive no processo alvo: sem reiniciar, uma segunda
    execucao sem bypass ainda encontraria os hooks instalados.

    Args:
        dm: Gerenciador do dispositivo.
        package: Pacote do app alvo.

    Returns:
        Sessao Frida anexada ao processo novo.
    """
    dm.run_shell(f"am force-stop {package}", timeout=10)
    time.sleep(1.5)
    dm.run_shell(
        f"monkey -p {package} -c android.intent.category.LAUNCHER 1", timeout=20
    )
    time.sleep(4.0)
    return dm.attach_app(package)


def _request(session, port: int, with_bypass: bool) -> str:
    """Faz a requisicao HTTPS e devolve o resultado.

    Args:
        session: Sessao Frida ativa.
        port: Porta do servidor no dispositivo.
        with_bypass: Se True, carrega o bypass antes da requisicao.

    Returns:
        ``status=<codigo>`` ou ``erro=<mensagem>``.
    """
    if with_bypass:
        src = render_script(
            open(os.path.join(SCRIPTS_DIR, "ssl_bypass.js"), encoding="utf-8").read(),
            {
                "__RASPILOT_FRIDA_PORT__": "27999",
                "__RASPILOT_FRIDA_PORT_HEX__": "6DDF",
                "__RASPILOT_JAVA_ONLY__": "true",
            },
        )
        full = java_bridge_prelude() + COMPAT_PRELUDE + JAVA_BOOTSTRAP + src
        script = session.create_script(full, name="ssl-bypass")
        script.load()
        time.sleep(2.0)

    result = {"value": ""}

    def on_message(message, data):
        if message.get("type") != "send":
            return
        payload = message.get("payload", {})
        if payload.get("op") == "http":
            result["value"] = str(payload.get("extra", ""))

    probe = session.create_script(
        java_bridge_prelude() + COMPAT_PRELUDE + JAVA_BOOTSTRAP
        + PROBE.replace("__PORT__", str(port)),
        name="probe",
    )
    probe.on("message", on_message)
    probe.load()
    for _ in range(24):
        time.sleep(0.5)
        if result["value"]:
            break
    try:
        probe.unload()
    except Exception:
        pass
    return result["value"]


def main() -> int:
    """Executa o teste e devolve o codigo de saida.

    Returns:
        0 se o comportamento for o esperado, 1 caso contrario.
    """
    parser = argparse.ArgumentParser(description="Teste de bypass de SSL pinning")
    parser.add_argument("--package", required=True, help="Pacote do app alvo")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        cert, key = _make_cert(tmp)
        httpd = _start_server(cert, key, args.port)

        dm = DeviceManager()
        dm.connect_adb()
        subprocess.run(
            ["adb", "-s", dm.device_id or "", "reverse",
             f"tcp:{args.port}", f"tcp:{args.port}"],
            check=False, capture_output=True,
        )
        dm.setup_frida_server()

        sem_bypass = _request(_fresh_session(dm, args.package), args.port,
                               with_bypass=False)
        print(f"sem bypass:    {sem_bypass}")

        com_bypass = _request(_fresh_session(dm, args.package), args.port,
                               with_bypass=True)
        print(f"com bypass:    {com_bypass}")

        dm.remove_frida_server()
        dm.run_shell(f"am force-stop {args.package}", timeout=10)
        httpd.shutdown()

    ok_bypass = com_bypass.startswith("status=")
    ok_control = sem_bypass.startswith("erro=")
    print()
    print(f"bypass contorna a validacao: {'SIM' if ok_bypass else 'NAO'}")
    print(f"sem bypass a validacao falha: {'SIM' if ok_control else 'NAO'}")
    return 0 if (ok_bypass and ok_control) else 1


if __name__ == "__main__":
    sys.exit(main())
