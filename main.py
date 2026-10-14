#!/usr/bin/env python3
"""RASPilot — Piloto Automático de Auditoria RASP para Android.

CLI principal do RASPilot. Orquestra a conexão com o dispositivo, o
ciclo de vida do Frida server e a execução do pipeline de verificações
RASP (Anti-Root, Anti-Frida, Anti-Emulador e SSL Pinning), gerando
relatórios JSON e HTML estruturados.

Uso básico::

    python main.py --package com.example.app
    python main.py --package com.example.app --wifi 192.168.0.10:5555
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from rich.console import Console

from device_manager import (
    TOOL_NAME,
    TOOL_VERSION,
    DeviceConnectionError,
    DeviceManager,
    FridaSetupError,
)

# Console rich global — único ponto de saída visual do CLI.
console = Console()

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"

# Checks conhecidos — usado para validar --skip.
KNOWN_CHECKS = ("anti_root", "anti_frida", "anti_emulator", "ssl_pinning")


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
            "Verifica Anti-Root, Anti-Frida, Anti-Emulador e SSL Pinning "
            "em apps Android e gera relatórios JSON/HTML."
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
        "— Piloto Automático de Auditoria RASP para Android",
        style=None,
    )


def run_phase1(args: argparse.Namespace) -> int:
    """Executa o pipeline da Fase 1: conexão ADB + setup do Frida server.

    Args:
        args: Argumentos já parseados.

    Returns:
        Código de saída do processo (0 = sucesso).
    """
    logger = logging.getLogger("raspilot")

    dm = DeviceManager(
        device_id=args.device_id,
        wifi_target=args.wifi,
        verbose=args.verbose,
    )

    logger.info("Conectando ao dispositivo...")
    dm.connect_adb()

    info = dm.get_device_info()
    console.print("[green]✓[/] Dispositivo conectado:")
    for key, value in info.items():
        console.print(f"    [dim]{key}:[/] {value}")

    if dm.setup_frida_server():
        console.print("[green]✓[/] frida-server instalado, iniciado e validado")

    # Limitação da Fase 1: só valida o ambiente. Pipeline completo na Fase 6.
    console.print(
        "[yellow]·[/] Fase 1 concluída. "
        "Pipeline de checks completo disponível nas fases seguintes."
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
    print_banner()

    logger = logging.getLogger("raspilot")
    logger.debug("Args: %s", args)

    try:
        return run_phase1(args)
    except (DeviceConnectionError, FridaSetupError) as exc:
        console.print(f"[bold red]✗ Erro:[/] {exc}")
        logger.debug("Detalhes do erro:", exc_info=True)
        return 1
    except KeyboardInterrupt:
        console.print("[bold red]✗ Interrompido pelo usuário.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
