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
import logging
import sys
from typing import Callable, List, Optional

from rich.console import Console
from rich.table import Table

from checks.anti_emulator import AntiEmulatorCheck
from checks.anti_frida import AntiFridaCheck
from checks.anti_hooking import AntiHookingCheck
from checks.anti_root import AntiRootCheck
from checks.ssl_pinning import SSLPinningCheck
from device_manager import (
    TOOL_NAME,
    TOOL_VERSION,
    DeviceConnectionError,
    DeviceManager,
    FridaSetupError,
)
from reporter import Reporter

# Console rich global — único ponto de saída visual do CLI.
console = Console()

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"

# Checks conhecidos — usado para validar --skip e nomear o relatório.
KNOWN_CHECKS = ("anti_root", "anti_frida", "anti_emulator", "anti_hooking", "ssl_pinning")


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
        required=True,
        help="Package name do app alvo (ex: com.example.app)",
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

    unknown = [c for c in args.skip if c not in KNOWN_CHECKS]
    if unknown:
        parser.error(
            f"checks desconhecidos em --skip: {', '.join(unknown)}. "
            f"Conhecidos: {', '.join(KNOWN_CHECKS)}"
        )
    return args


def print_banner() -> None:
    """Exibe o banner textual do RASPilot no terminal."""
    console.print(
        f"[bold cyan]{TOOL_NAME}[/] [dim]v{TOOL_VERSION}[/] "
        "— Piloto Automático de Auditoria RASP para Android"
    )


def _run_step(
    reporter: Reporter,
    check_name: str,
    step: Callable[[], dict],
    skipped: bool = False,
) -> Optional[dict]:
    """Executa um passo do pipeline com isolamento de falhas.

    Falha em um check **não aborta** o pipeline: o erro é registrado no
    relatório como ``ERROR`` e a execução segue.

    Args:
        reporter: Instância do relatório para ``collect``.
        check_name: Nome do check no relatório.
        step: Callable que retorna o resultado do ``run_all()``.
        skipped: Se True, registra o check como pulado.

    Returns:
        O resultado do check ou ``None`` se pulado/erro.
    """
    logger = logging.getLogger("raspilot")
    if skipped:
        logger.info("Check %s pulado (--skip)", check_name)
        reporter.collect(check_name, {"skipped": True})
        return None

    with console.status(f"[cyan]Executando {check_name}...[/]"):
        try:
            result = step()
        except Exception as exc:  # isolamento total entre fases
            logger.warning("Check %s falhou: %s", check_name, exc, exc_info=True)
            reporter.collect(check_name, {"error": str(exc)})
            console.print(f"[yellow]![/] {check_name}: [red]ERROR[/] ({exc})")
            return None

    reporter.collect(check_name, result)
    console.print(f"[green]✓[/] {check_name} concluído")
    return result


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
    table.add_column("Status", justify="center")
    table.add_column("Resumo")

    color_by_status = {
        "OK": "green",
        "FALHOU": "red",
        "ERROR": "magenta",
        "N/A": "dim",
        "SKIP": "dim",
    }
    for name, summary in doc["summary"].items():
        status = summary.get("status", "?")
        color = color_by_status.get(status, "white")
        key_bits = [
            f"{k}={v}"
            for k, v in summary.items()
            if k not in ("status", "skipped") and v is not None
        ]
        table.add_row(name, f"[{color}]{status}[/{color}]", ", ".join(key_bits) or "—")

    console.print()
    console.print(table)


def run_pipeline(args: argparse.Namespace) -> int:
    """Executa o pipeline completo de auditoria RASP.

    Fluxo: conexão ADB → info do dispositivo → frida-server →
    anti_root → anti_emulator → spawn do app → anti_frida →
    anti_hooking → ssl_pinning → relatórios → tabela final → cleanup.

    Args:
        args: Argumentos já parseados.

    Returns:
        Código de saída do processo (0 = sucesso parcial/total; o
        pipeline sempre tenta terminar).
    """
    logger = logging.getLogger("raspilot")

    # 1) Conexão ADB (USB ou Wi-Fi).
    logger.info("Conectando ao dispositivo...")
    dm = DeviceManager(
        device_id=args.device_id,
        wifi_target=args.wifi,
        verbose=args.verbose,
    )
    dm.connect_adb()

    info = dm.get_device_info()
    console.print("[green]✓[/] Dispositivo conectado:")
    for key, value in info.items():
        console.print(f"    [dim]{key}:[/] {value}")

    # 2) Frida server.
    dm.setup_frida_server()
    console.print("[green]✓[/] frida-server instalado, iniciado e validado")

    # 3) Relatório.
    reporter = Reporter(
        device_info=info,
        package_name=args.package,
        output_dir=args.output_dir,
    )

    session = None
    pid = None
    try:
        # 4) Anti-Root (não requer app rodando).
        _run_step(
            reporter,
            "anti_root",
            lambda: AntiRootCheck(dm).run_all(),
            skipped="anti_root" in args.skip,
        )

        # 5) Anti-Emulador (não requer app rodando).
        _run_step(
            reporter,
            "anti_emulator",
            lambda: AntiEmulatorCheck(dm).run_all(),
            skipped="anti_emulator" in args.skip,
        )

        # 6) Spawn do app alvo (necessário para anti-frida e ssl).
        #    Spawn SUSPENSO: os hooks anti-frida são instalados antes do
        #    código do app rodar (detecções de RASP costumam executar na
        #    inicialização); o resume acontece via callback do check.
        if "anti_frida" not in args.skip or "ssl_pinning" not in args.skip:
            with console.status(f"[cyan]Spawning {args.package}...[/]"):
                session = dm.spawn_app(args.package, resume=False)
            pid = dm.get_app_pid(args.package)
            console.print(f"[green]✓[/] App spawnado suspenso (pid={pid})")

        # 7) Anti-Frida (requer session + pid; resume via callback).
        if pid is not None:
            _run_step(
                reporter,
                "anti_frida",
                lambda: AntiFridaCheck(dm).run_all(
                    session, pid, on_script_loaded=dm.resume_app,
                    window=args.window,
                ),
                skipped="anti_frida" in args.skip,
            )
        elif "anti_frida" not in args.skip:
            reporter.collect("anti_frida", {"error": "app não pôde ser spawnado"})
            console.print("[yellow]![/] anti_frida: [red]ERROR[/] (app não spawnado)")

        # 8) Anti-Hooking (spawn próprio interno: observação + bypass,
        #    como o ssl_pinning — não compartilha a sessão do anti_frida).
        _run_step(
            reporter,
            "anti_hooking",
            lambda: AntiHookingCheck(dm).run_all(args.package, window=args.window),
            skipped="anti_hooking" in args.skip,
        )

        # 9) SSL Pinning (spawn próprio interno no attempt_bypass).
        _run_step(
            reporter,
            "ssl_pinning",
            lambda: SSLPinningCheck(dm).run_all(args.package, window=args.window),
            skipped="ssl_pinning" in args.skip,
        )
    finally:
        # 10) Cleanup — nunca deixar resíduos no dispositivo.
        try:
            dm.resume_app()  # idempotente: destrava spawn suspenso, se houver
            if session is not None:
                session.detach()
        except Exception:
            logger.debug("Falha ao detach da sessão final", exc_info=True)
        try:
            dm.remove_frida_server()
            dm.run_shell(f"am force-stop {args.package}", timeout=10)
        except Exception:
            logger.warning("Falha no cleanup final do dispositivo", exc_info=True)

    # 11) Relatórios.
    json_path, html_path = reporter.save()
    print_summary_table(reporter)
    console.print(f"\n[green]✓[/] Relatório JSON: [bold]{json_path}[/]")
    console.print(f"[green]✓[/] Relatório HTML: [bold]{html_path}[/]")
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
    print_banner()

    logger = logging.getLogger("raspilot")
    logger.debug("Args: %s", args)

    try:
        return run_pipeline(args)
    except (DeviceConnectionError, FridaSetupError) as exc:
        console.print(f"[bold red]✗ Erro:[/] {exc}")
        logger.debug("Detalhes do erro:", exc_info=True)
        return 1
    except KeyboardInterrupt:
        console.print("[bold red]✗ Interrompido pelo usuário.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
