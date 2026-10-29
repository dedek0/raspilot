#!/usr/bin/env python3
"""RASPilot — Piloto Automático de Auditoria RASP para Android.

CLI principal do RASPilot. Orquestra a conexão com o dispositivo, o
ciclo de vida do Frida server e a execução do pipeline de verificações
RASP (Anti-Root, Anti-Frida, Anti-Emulador, Anti-Hooking e SSL
Pinning), gerando relatórios JSON e HTML estruturados.

Uso básico::

    python main.py --package com.example.app
    python main.py --package com.example.app --wifi 192.168.0.10:5555
    python main.py --package com.example.app --skip anti_emulator --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from typing import List, Optional

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from avd_manager import AvdConfig, AvdConfigError, AvdError, AvdManager
from device_manager import (
    TOOL_NAME,
    TOOL_VERSION,
    DeviceConnectionError,
    FridaSetupError,
)
from reporter import Reporter
from script_loader import set_js_runtime
from service import KNOWN_CHECKS, ProgressSink, RaspilotService, RunConfig
from sessions import SessionError, SessionState, SessionStore

# Console rich global — único ponto de saída visual do CLI.
console = Console()

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"



def setup_logging(verbose: bool = False) -> None:
    """Configura o logging estruturado do RASPilot.

    Args:
        verbose: Se True, nível DEBUG; caso contrário INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Silencia bibliotecas barulhentas para manter o output legível.
    for noisy in ("frida", "urllib3", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da CLI do RASPilot.

    Returns:
        Parser argparse pronto para uso.
    """
    parser = argparse.ArgumentParser(
        prog="raspilot",
        description=(
            "RASPilot — Piloto Automático de Auditoria RASP para Android. "
            "Verifica Anti-Root, Anti-Frida, Anti-Emulador, Anti-Hooking e "
            "SSL Pinning em apps Android e gera relatórios JSON/HTML."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--package",
        required=False,
        help=(
            "Package name do app alvo (ex: com.example.app). Pode ser "
            "omitido ao retomar uma sessão com --session."
        ),
    )
    parser.add_argument(
        "--device-id",
        default=None,
        help="Serial ADB do dispositivo (ex: emulator-5554)",
    )
    parser.add_argument(
        "--wifi",
        default=None,
        metavar="IP:PORTA",
        help="Endereço para `adb connect` (ex: 192.168.0.10:5555)",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/",
        help="Diretório onde salvar os relatórios",
    )
    parser.add_argument(
        "--stage",
        choices=("full", "static", "detect", "bypass", "report"),
        default="full",
        help=(
            "Etapa da análise: full=completo (default); static=só perfil "
            "do APK, sem Frida/spawn; detect=só detecção, sem bypass; "
            "bypass=detecção+bypass (exige detect na mesma sessão); "
            "report=regenera JSON/HTML do estado salvo, sem device"
        ),
    )
    parser.add_argument(
        "--only",
        action="append",
        choices=KNOWN_CHECKS,
        metavar="CHECK",
        help=(
            "Roda apenas o(s) check(s) informado(s); pode repetir. "
            "Alternativa explícita ao --skip."
        ),
    )
    parser.add_argument(
        "--apk",
        default=None,
        metavar="PATH",
        help=(
            "APK local do alvo (pula o adb pull). Útil para --stage static "
            "e para análises sem app instalado."
        ),
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Gera apenas o JSON (sem HTML), útil para automação/MCP",
    )
    parser.add_argument(
        "--session",
        default=None,
        metavar="ID",
        help=(
            "Retoma a sessão informada. Sem esta flag, cada execução cria "
            "uma sessão nova em --state-dir."
        ),
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        metavar="PATH",
        help=(
            "Diretório das sessões (default: $RASPILOT_STATE_DIR ou "
            "~/.raspilot/sessions)"
        ),
    )
    parser.add_argument(
        "--list-sessions",
        action="store_true",
        help="Lista as sessões salvas e sai (não executa auditoria)",
    )
    parser.add_argument(
        "--show-session",
        default=None,
        metavar="ID",
        help="Mostra o estado e os recursos de uma sessão e sai",
    )
    parser.add_argument(
        "--tamper-method",
        choices=("auto", "static", "frida", "repack"),
        default="auto",
        help=(
            "Método do anti-tampering: auto=estático + módulo/Frida; "
            "static=só análise do APK; frida=só sonda em memória; "
            "repack=re-assina/reinstala o APK (destrutivo)"
        ),
    )
    parser.add_argument(
        "--tamper-allow-reinstall",
        action="store_true",
        help=(
            "Autoriza o teste de repack a desinstalar/reinstalar o app. "
            "Os dados do app são perdidos; use device/AVD descartável."
        ),
    )
    parser.add_argument(
        "--tamper-variant",
        action="append",
        choices=("asset", "dex", "resource", "manifest", "gadget", "all"),
        help=(
            "Variante de modificação do repack; pode repetir. "
            "Default: asset e dex; use all para todas"
        ),
    )
    parser.add_argument(
        "--tamper-installer",
        default=None,
        metavar="PKG",
        help=(
            "Instalador simulado no repack (ex: com.android.vending). "
            "Default: o instalador atual do app"
        ),
    )
    parser.add_argument(
        "--tamper-no-restore",
        action="store_true",
        help="Não reinstala o APK original ao final do teste de repack",
    )
    parser.add_argument(
        "--tamper-keep-artifacts",
        action="store_true",
        help="Mantém os APKs original/modificados no diretório de saída",
    )
    parser.add_argument(
        "--tamper-timeout",
        type=int,
        default=600,
        help="Timeout por operação de build do repack (default 600s)",
    )
    parser.add_argument(
        "--tamper-gadget",
        default=None,
        metavar="PATH",
        help=(
            "Frida Gadget .so (ou .so.xz) para a variante gadget. "
            "Default: procura em ~/.raspilot/gadgets/"
        ),
    )
    parser.add_argument(
        "--tamper-gadget-port",
        type=int,
        default=27043,
        help="Porta local do Frida Gadget na variante gadget (default 27043)",
    )
    parser.add_argument(
        "--tamper-gadget-mode",
        choices=("listen", "wait", "script"),
        default="listen",
        help=(
            "Modo do Gadget: listen (host conecta), wait (app aguarda) "
            "ou script (executa --tamper-gadget-script)"
        ),
    )
    parser.add_argument(
        "--tamper-gadget-script",
        default=None,
        metavar="PATH",
        help="Script JS embutido na variante gadget (modo script)",
    )
    parser.add_argument(
        "--tamper-key",
        default=None,
        metavar="PATH",
        help=(
            "Keystore original para preservar o assinante no repack; "
            "sem ele usa a chave de debug"
        ),
    )
    parser.add_argument(
        "--tamper-key-alias",
        default="raspilot",
        help="Alias da chave em --tamper-key (default raspilot)",
    )
    parser.add_argument(
        "--tamper-key-pass",
        default="android",
        help="Senha da chave em --tamper-key (default android)",
    )
    parser.add_argument(
        "--tamper-store-pass",
        default="android",
        help="Senha do keystore em --tamper-key (default android)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Ativa logging em nível DEBUG",
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        default=[],
        metavar="CHECK",
        help=f"Checks a pular ({', '.join(KNOWN_CHECKS)})",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=15,
        metavar="SEG",
        help="Janela de observação em segundos nos checks dinâmicos",
    )
    parser.add_argument(
        "--baseline-window",
        type=int,
        default=5,
        metavar="SEG",
        help="Janela do baseline sem instrumentação (detecta morte/crash naturais)",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Não executa o baseline sem instrumentação antes dos checks dinâmicos",
    )
    parser.add_argument(
        "--mode",
        choices=("detect", "bypass", "stealth"),
        default="bypass",
        help="detect=só observação; bypass=observação+bypass; stealth=bypass com bootstrap nativo",
    )
    parser.add_argument(
        "--no-java",
        action="store_true",
        help="Não carrega hooks Java (evita bridge em apps com RASP agressivo)",
    )
    parser.add_argument(
        "--hook-method",
        choices=("frida", "module", "auto"),
        default="auto",
        help=(
            "Método do bypass anti-hook: frida=agente injetado; "
            "module=módulo (APK) de hooking no dispositivo, limitado ao "
            "pacote alvo; auto=usa o módulo quando há framework disponível"
        ),
    )
    parser.add_argument(
        "--emulator-method",
        choices=("frida", "module", "auto"),
        default="auto",
        help=(
            "Método do probe/bypass anti-emulador: frida=agente injetado; "
            "module=módulo (APK) de hooking no dispositivo; "
            "auto=usa o módulo quando há framework disponível"
        ),
    )
    parser.add_argument(
        "--proxy-method",
        choices=("frida", "module", "auto"),
        default="auto",
        help=(
            "Método do probe/bypass de proxy/VPN: frida=agente injetado; "
            "module=módulo (APK) de hooking no dispositivo; "
            "auto=usa o módulo quando há framework disponível"
        ),
    )
    parser.add_argument(
        "--module-apk",
        default=None,
        metavar="PATH",
        help=(
            "APK pré-construído do módulo de instrumentação (dispensa o "
            "build, que exige o SDK do Android)"
        ),
    )
    parser.add_argument(
        "--static-engine",
        choices=("auto", "asc", "builtin", "off"),
        default="auto",
        help=(
            "Motor da análise estática do APK: auto=ASC se instalado "
            "(fallback para varredura de bytes); asc=exige Droid ASC; "
            "builtin=só varredura de bytes; off=não analisa"
        ),
    )
    parser.add_argument(
        "--static-timeout",
        type=float,
        default=60.0,
        metavar="SEG",
        help="Timeout por consulta ao Droid ASC (padrão: 60s)",
    )
    parser.add_argument(
        "--java-timeout",
        type=float,
        default=30.0,
        metavar="SEG",
        help=(
            "Tempo máximo de carga dos scripts Java, em segundos. A carga "
            "da bridge é dominada pela inicialização do runtime Java no "
            "alvo e pela varredura de classloaders."
        ),
    )
    parser.add_argument(
        "--js-runtime",
        choices=("qjs", "v8"),
        default="qjs",
        help="Runtime JavaScript usado pelo Frida para os scripts",
    )
    parser.add_argument(
        "--avd",
        action="store_true",
        help=(
            "Audita contra o AVD configurado em vez do device físico: "
            "sobe o emulador, espera o boot e o encerra no final. "
            "Requer a configuração do ambiente (veja --avd-config)"
        ),
    )
    parser.add_argument(
        "--avd-config",
        default=None,
        metavar="PATH",
        help=(
            "Arquivo JSON com a configuração do ambiente emulado "
            "(default: ~/.raspilot/avd.json ou $RASPILOT_AVD_CONFIG)"
        ),
    )
    parser.add_argument(
        "--avd-name",
        default=None,
        metavar="NOME",
        help="Nome do AVD a usar, sobrescrevendo a configuração",
    )
    parser.add_argument(
        "--avd-check",
        action="store_true",
        help=(
            "Valida o ambiente emulado e mostra o que falta (sem rodar "
            "a auditoria)"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Faz o parse e valida os argumentos da linha de comando.

    Args:
        argv: Argumentos opcionais (default: ``sys.argv[1:]``).

    Returns:
        Namespace com os argumentos validados.

    Raises:
        SystemExit: se ``--skip`` contiver check desconhecido (via parser.error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (
        args.list_sessions
        or args.show_session
        or args.avd_check
        or args.session
        or args.package
    ):
        parser.error(
            "--package é obrigatório (exceto com --session, "
            "--list-sessions, --show-session ou --avd-check)"
        )
    if args.stage == "report" and not args.session:
        parser.error("--stage report exige --session ID")
    if args.stage == "bypass" and not args.session:
        parser.error(
            "--stage bypass exige --session ID: rode --stage detect "
            "primeiro (ou use --stage full)"
        )

    unknown = [c for c in args.skip if c not in KNOWN_CHECKS]
    if unknown:
        parser.error(
            f"checks desconhecidos em --skip: {', '.join(unknown)}. "
            f"Conhecidos: {', '.join(KNOWN_CHECKS)}"
        )
    if (
        args.tamper_method == "repack"
        and not args.tamper_allow_reinstall
        and args.stage not in ("static", "detect", "report")
        and args.mode != "detect"
        and "anti_tampering" not in args.skip
    ):
        parser.error(
            "--tamper-method repack desinstala e reinstala o app; "
            "use --tamper-allow-reinstall para confirmar que os dados "
            "podem ser perdidos"
        )
    return args


def print_banner() -> None:
    """Exibe o banner textual do RASPilot no terminal."""
    console.print(
        f"[bold cyan]{TOOL_NAME}[/] [dim]v{TOOL_VERSION}[/] "
        "— Piloto Automático de Auditoria RASP para Android"
    )


def _format_summary_value(value) -> str:
    """Formata um valor do resumo para leitura no terminal.

    Args:
        value: Valor vindo do resumo do relatório.

    Returns:
        Texto compacto (listas separadas por vírgula, textos truncados).
    """
    if isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value if item is not None]
        return ", ".join(items) if items else "—"
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items()) or "—"
    text = str(value)
    if len(text) > 180:
        text = text[:179].rstrip() + "…"
    return text


def print_summary_table(reporter: Reporter) -> None:
    """Exibe a tabela final de resumo no terminal.

    Args:
        reporter: Relatório com os resultados coletados.
    """
    doc = reporter.generate_json()
    table = Table(
        title=f"{TOOL_NAME} — Relatório de Auditoria RASP",
        title_style="bold cyan",
        header_style="bold",
    )
    table.add_column("Verificação", style="bold")
    table.add_column("Detecção", justify="center")
    table.add_column("Bypass", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Resumo")

    color_by_status = {
        "OK": "green",
        "FALHOU": "red",
        "ERROR": "magenta",
        "N/A": "dim",
        "SKIP": "dim",
    }
    color_by_detection = {
        "detected": "yellow",
        "indicated": "yellow",
        "suspected": "yellow",
        "not_detected": "dim",
        "inconclusive": "dim",
        "not_applicable": "dim",
        "error": "magenta",
    }
    color_by_bypass = {
        "bypassed": "red",
        "resisted": "green",
        "not_exercised": "dim",
        "not_applicable": "dim",
        "error": "magenta",
    }
    for name, summary in doc["summary"].items():
        status = summary.get("status", "?")
        color = color_by_status.get(status, "white")
        detection = summary.get("detection") or {}
        bypass = summary.get("bypass") or {}
        detection_status = detection.get("status", "?")
        bypass_status = bypass.get("status", "?")
        key_bits = [
            f"{k}={escape(_format_summary_value(v))}"
            for k, v in summary.items()
            if k not in ("status", "skipped", "detection", "bypass")
            and v is not None
            and v != []
            and v != {}
            and v != ""
        ]
        table.add_row(
            escape(name),
            f"[{color_by_detection.get(detection_status, 'white')}]"
            f"{escape(str(detection.get('label') or detection_status))}[/]",
            f"[{color_by_bypass.get(bypass_status, 'white')}]"
            f"{escape(str(bypass.get('label') or bypass_status))}[/]",
            f"[{color}]{status}[/{color}]",
            ", ".join(key_bits) or "—",
        )

    console.print()
    console.print(table)


def print_execution_log(reporter: Reporter) -> None:
    """Exibe a trilha detalhada de execução no terminal.

    A tabela responde, para cada etapa: o check, a fase, o que foi
    tentado, o que foi encontrado e o status final. É a mesma trilha
    gravada no JSON (``execution_log``) e no HTML.

    Args:
        reporter: Relatório com os resultados coletados.
    """
    doc = reporter.generate_json()
    steps = doc.get("execution_log") or []
    if not steps:
        return

    table = Table(
        title=f"{TOOL_NAME} — Log de execução",
        title_style="bold cyan",
        header_style="bold",
        show_lines=False,
    )
    table.add_column("Check / fase", style="bold", no_wrap=False)
    table.add_column("Tentativa", overflow="fold")
    table.add_column("Encontrado", overflow="fold")
    table.add_column("Reportado", justify="center", no_wrap=True)

    outcome_color = {
        "ok": "green",
        "success": "red",
        "failed": "red",
        "detected": "yellow",
        "suspected": "yellow",
        "blocked": "green",
        "resisted": "green",
        "not_detected": "green",
        "inconclusive": "yellow",
        "skipped": "dim",
        "not_applicable": "dim",
        "error": "magenta",
    }
    for step in steps:
        outcome = step.get("outcome", "?")
        color = outcome_color.get(outcome, "white")
        found = f"[{color}]{escape(outcome)}[/{color}]"
        details = step.get("details") or ""
        if details:
            found += "\n" + escape(details)
        evidence = step.get("evidence") or []
        if evidence:
            found += "\n[dim]evidências: " + escape(
                "; ".join(str(item) for item in evidence)
            ) + "[/dim]"
        reported = step.get("reported_status") or ""
        table.add_row(
            f"{escape(str(step.get('check', '?')))}\n"
            f"[dim]{escape(str(step.get('phase', '?')))}[/dim]",
            escape(str(step.get("action", "?"))),
            found,
            f"[{color}]{escape(reported)}[/{color}]" if reported else "—",
        )

    console.print()
    console.print(table)


def _load_avd_config(args: argparse.Namespace) -> AvdConfig:
    """Carrega a configuração do ambiente emulado.

    Args:
        args: Argumentos já parseados.

    Returns:
        Configuração carregada (com ``--avd-name`` aplicado).

    Raises:
        AvdConfigError: se a configuração estiver ausente ou inválida.
    """
    config = AvdConfig.load(args.avd_config)
    if args.avd_name:
        config.avd_name = args.avd_name
    return config


def run_avd_check(args: argparse.Namespace) -> int:
    """Valida o ambiente emulado e mostra o que falta.

    Não roda a auditoria: serve para confirmar que o AVD está pronto
    antes de gastar tempo com uma execução completa.

    Args:
        args: Argumentos já parseados.

    Returns:
        0 quando o ambiente está pronto, 1 caso contrário.
    """
    try:
        config = _load_avd_config(args)
    except AvdConfigError as exc:
        console.print(f"[bold red]✗[/] {exc}")
        return 1

    manager = AvdManager(config)
    env = manager.check()
    for key, value in env.details.items():
        console.print(f"    [dim]{key}:[/] {value}")
    if env.ok:
        console.print("[green]✓[/] Ambiente emulado pronto")
        return 0

    for problem in env.problems:
        console.print(f"[yellow]![/] {problem}")
    for hint in env.hints:
        console.print(f"    [dim]{hint}[/]")
    console.print(AvdConfig.setup_instructions(args.avd_config))
    return 1


class ConsoleProgress(ProgressSink):
    """Progresso com ``rich`` — única saída visual do CLI.

    O serviço é headless; esta classe traduz os eventos de progresso
    para o terminal sem acoplar o pipeline ao ``rich``.
    """

    def __init__(self, rich_console: Console) -> None:
        self.console = rich_console

    def status(self, message: str):
        return self.console.status(f"[cyan]{escape(message)}...[/]")

    def info(self, message: str) -> None:
        self.console.print(escape(message))

    def success(self, message: str) -> None:
        self.console.print(f"[green]✓[/] {escape(message)}")

    def warning(self, message: str) -> None:
        self.console.print(f"[yellow]![/] {escape(message)}")

    def check_done(self, check_name: str, result: dict) -> None:
        self.console.print(f"[green]✓[/] {escape(check_name)} concluído")

    def check_skipped(self, check_name: str, reason: str) -> None:
        self.console.print(
            f"[dim]–[/] {escape(check_name)}: {escape(reason)}"
        )


def _open_service(
    config: RunConfig,
    args: argparse.Namespace,
    store: SessionStore,
) -> RaspilotService:
    """Cria ou retoma o serviço ligado a uma sessão."""
    progress = ConsoleProgress(console)
    if config.session_id:
        service = RaspilotService.resume(
            config, store=store, progress=progress
        )
    else:
        service = RaspilotService.create(
            config, store=store, progress=progress
        )
    return service


def _print_session(state: Optional[SessionState]) -> None:
    """Exibe a sessão usada, sem poluir o JSON."""
    if state is None:
        return
    console.print(
        f"[dim]Sessão:[/] [bold]{state.session_id}[/] "
        f"[dim]({state.directory})[/]"
    )


def run_list_sessions(args: argparse.Namespace) -> int:
    """Lista as sessões salvas em ``--state-dir``."""
    store = SessionStore(getattr(args, "state_dir", None))
    states = store.list()
    if not states:
        console.print("[dim]Nenhuma sessão salva.[/]")
        return 0
    table = Table(title="RASPilot — Sessões", header_style="bold")
    table.add_column("Sessão", style="bold")
    table.add_column("Pacote")
    table.add_column("Etapa", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Device")
    table.add_column("Atualizada")
    for state in states:
        table.add_row(
            state.session_id,
            state.package,
            state.stage,
            state.status,
            str((state.device or {}).get("serial") or "—"),
            state.updated_at,
        )
    console.print(table)
    return 0


def run_show_session(args: argparse.Namespace) -> int:
    """Mostra o estado completo e os recursos de uma sessão."""
    store = SessionStore(getattr(args, "state_dir", None))
    state = store.load(args.show_session)
    doc = state.to_dict()
    doc["resources"] = store.resources(state)
    print(json.dumps(doc, ensure_ascii=False, indent=2))
    return 0


def run_report_stage(args: argparse.Namespace) -> int:
    """Regenera JSON/HTML a partir do estado salvo, sem device."""
    store = SessionStore(getattr(args, "state_dir", None))
    config = RunConfig.from_args(args)
    config.stage = "report"
    service = RaspilotService.resume(
        config, store=store, progress=ConsoleProgress(console)
    )
    result = service.generate_report(write_html=not args.json_only)
    print_summary_table(result.reporter)
    print_execution_log(result.reporter)
    _print_session(service.state)
    console.print(f"[green]✓[/] Relatório JSON: [bold]{result.json_path}[/]")
    if result.html_path:
        console.print(f"[green]✓[/] Relatório HTML: [bold]{result.html_path}[/]")
    return 0


def run_static_stage(args: argparse.Namespace) -> int:
    """Executa somente o perfil estático do APK.

    Não sobe frida-server nem inicia o app. Se ``--apk`` for informado,
    também não precisa de dispositivo conectado.

    Args:
        args: Argumentos da CLI.

    Returns:
        0 quando o perfil foi gerado; 1 quando o APK não pôde ser obtido.
    """
    logger = logging.getLogger("raspilot")
    store = SessionStore(getattr(args, "state_dir", None))
    config = RunConfig.from_args(args)
    service = _open_service(config, args, store)
    static = service.run_static()
    profile = static.profile
    package = service.config.package

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    os.makedirs(args.output_dir, exist_ok=True)
    base = f"{Reporter._slug(package)}_{stamp}_static"
    path = os.path.abspath(os.path.join(args.output_dir, base + ".json"))
    # ``static.json`` é sempre o perfil puro: o mesmo formato exposto
    # como recurso da sessão para o MCP. O invólucro antigo (metadata +
    # static_profile) foi removido para não haver dois schemas.
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    summary = profile.get("summary") or {}
    vectors = summary.get("vectors") or {}
    table = Table(title="RASPilot — Análise estática", header_style="bold")
    table.add_column("Vetor", style="bold")
    table.add_column("Presente", justify="center")
    table.add_column("Confiança", justify="center")
    table.add_column("Achados", justify="right")
    for name, item in vectors.items():
        table.add_row(
            name,
            "sim" if item.get("present") else "não",
            str(item.get("confidence") or "none"),
            str(item.get("total") or 0),
        )
    console.print(table)
    console.print(
        f"[green]✓[/] Estático: engine={profile.get('engine')} "
        f"classes={profile.get('classes_count') or 0} "
        f"cached={bool(profile.get('cached'))}"
    )
    console.print(f"[green]✓[/] Perfil JSON: [bold]{path}[/]")
    _print_session(service.state)
    logger.info("Perfil estático salvo em %s", path)
    return 0 if profile.get("available") else 1


def run_pipeline(args: argparse.Namespace) -> int:
    """Executa o pipeline completo de auditoria RASP.

    Toda a orquestração fica em :class:`service.RaspilotService`; esta
    função apenas converte a configuração, dispara a execução e imprime
    o resumo. O ``--stage static`` tem fluxo próprio.

    Args:
        args: Argumentos já parseados.

    Returns:
        Código de saída do processo (0 = sucesso parcial/total; o
        pipeline sempre tenta terminar).
    """
    if getattr(args, "stage", "full") == "static":
        return run_static_stage(args)

    service = _open_service(
        RunConfig.from_args(args),
        args,
        SessionStore(getattr(args, "state_dir", None)),
    )
    result = service.run_dynamic()

    print_summary_table(result.reporter)
    print_execution_log(result.reporter)
    _print_session(service.state)
    console.print(
        f"\n[green]✓[/] Relatório JSON: [bold]{result.json_path}[/]"
    )
    if result.html_path:
        console.print(
            f"[green]✓[/] Relatório HTML: [bold]{result.html_path}[/]"
        )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Ponto de entrada principal do RASPilot.

    Args:
        argv: Argumentos opcionais da CLI.

    Returns:
        Código de saída (0 = sucesso, 1 = erro).
    """
    args = parse_args(argv)
    setup_logging(verbose=args.verbose)
    if not (args.list_sessions or args.show_session):
        print_banner()

    logger = logging.getLogger("raspilot")
    logger.debug("Args: %s", args)
    set_js_runtime(args.js_runtime)

    # Garante cleanup (force-stop/remoção do frida-server) também quando
    # o processo recebe SIGTERM (ex: timeout do shell/CI).
    def _raise_interrupt(signum, frame):  # noqa: ANN001
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _raise_interrupt)
    except (ValueError, OSError):
        logger.debug("Não foi possível instalar handler de SIGTERM", exc_info=True)

    try:
        if args.avd_check:
            return run_avd_check(args)
        if args.list_sessions:
            return run_list_sessions(args)
        if args.show_session:
            return run_show_session(args)
        if args.stage == "report":
            return run_report_stage(args)
        return run_pipeline(args)
    except (DeviceConnectionError, FridaSetupError) as exc:
        console.print(f"[bold red]✗ Erro:[/] {exc}")
        logger.debug("Detalhes do erro:", exc_info=True)
        return 1
    except SessionError as exc:
        console.print(f"[bold red]✗ Sessão:[/] {exc}")
        logger.debug("Detalhes do erro de sessão:", exc_info=True)
        return 1
    except (AvdConfigError, AvdError) as exc:
        console.print(f"[bold red]✗ Ambiente emulado:[/] {exc}")
        logger.debug("Detalhes do erro:", exc_info=True)
        return 1
    except KeyboardInterrupt:
        console.print("[bold red]✗ Interrompido pelo usuário.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
