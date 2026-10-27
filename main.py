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
import os
import signal
import sys
import time
from typing import Callable, List, Optional

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from avd_manager import AvdConfig, AvdConfigError, AvdError, AvdManager
from checks.anti_emulator import AntiEmulatorCheck
from checks.anti_frida import AntiFridaCheck
from checks.anti_hooking import AntiHookingCheck
from checks.anti_root import AntiRootCheck
from checks.combined import run_combined_bypass, run_combined_observation
from checks.ssl_pinning import SSLPinningCheck
from checks.static import build_static_profile
from device_manager import (
    TOOL_NAME,
    TOOL_VERSION,
    DeviceConnectionError,
    DeviceManager,
    FridaSetupError,
)
from reporter import Reporter
from script_loader import safe_detach, set_js_runtime
from instrumentation import XposedManager

# Console rich global — único ponto de saída visual do CLI.
console = Console()

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"

# Checks conhecidos — usado para validar --skip e nomear o relatório.
KNOWN_CHECKS = (
    "anti_root", "anti_frida", "anti_emulator", "anti_hooking",
    "ssl_pinning",
)


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
            f"{k}={escape(_format_summary_value(v))}"
            for k, v in summary.items()
            if k not in ("status", "skipped")
            and v is not None
            and v != []
            and v != {}
            and v != ""
        ]
        table.add_row(
            escape(name),
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


def _script_hashes() -> dict:
    """Calcula o sha256 de cada script de injeção.

    Os scripts JS definem a superfície de ataque efetiva da ferramenta:
    um resultado só é reproduzível se os hooks aplicados forem os mesmos.

    Returns:
        Mapa ``nome do arquivo -> sha256``.
    """
    import hashlib

    scripts_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "scripts"
    )
    hashes: dict = {}
    try:
        names = sorted(os.listdir(scripts_dir))
    except OSError:
        return hashes
    for name in names:
        if not name.endswith(".js"):
            continue
        path = os.path.join(scripts_dir, name)
        try:
            with open(path, "rb") as fh:
                hashes[name] = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            continue
    return hashes


def _build_run_context(args: argparse.Namespace, dm: "DeviceManager") -> dict:
    """Monta os metadados que permitem reproduzir a execução.

    Args:
        args: Argumentos já parseados.
        dm: Gerenciador do dispositivo.

    Returns:
        Dict com os metadados da execução.
    """
    try:
        import frida

        frida_version = frida.__version__
    except Exception:
        frida_version = None

    baseline = getattr(dm, "baseline", None)
    return {
        "cli_args": {
            "mode": args.mode,
            "no_java": bool(args.no_java),
            "window": args.window,
            "baseline_window": args.baseline_window,
            "java_timeout": args.java_timeout,
            "js_runtime": args.js_runtime,
            "skip": list(args.skip or []),
            "device_id": args.device_id,
            "wifi": args.wifi,
            "hook_method": getattr(args, "hook_method", "auto"),
            "emulator_method": getattr(args, "emulator_method", "auto"),
            "module_apk": getattr(args, "module_apk", None),
            "static_engine": getattr(args, "static_engine", "auto"),
            "static_timeout": getattr(args, "static_timeout", 60.0),
            "avd": {
                "enabled": bool(getattr(args, "avd", False)),
                "config_path": getattr(args, "avd_config", None),
                "avd_name": getattr(args, "avd_name", None),
            },
        },
        "frida_client_version": frida_version,
        "frida_port": getattr(dm, "frida_port", None),
        "script_sha256": _script_hashes(),
        "baseline": baseline if isinstance(baseline, dict) else None,
        "logcat_capture": {
            "available": bool(getattr(dm, "_logcat_available", False)),
        },
    }


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


def _activate_avd(args: argparse.Namespace) -> Optional[AvdManager]:
    """Ativa o ambiente emulado configurado.

    Sobe o AVD, espera o boot completo e devolve o gerenciador (que
    encerra o emulador no final da auditoria).

    Args:
        args: Argumentos já parseados.

    Returns:
        Gerenciador do AVD, ou None se ``--avd`` não foi informado.
    """
    if not args.avd:
        return None
    config = _load_avd_config(args)
    manager = AvdManager(config)
    with console.status(f"[cyan]Iniciando AVD {config.avd_name}...[/]"):
        serial = manager.start()
    console.print(f"[green]✓[/] AVD online: {serial}")
    return manager


def run_pipeline(args: argparse.Namespace) -> int:
    """Executa o pipeline completo de auditoria RASP.

    Fluxo: conexão ADB → info do dispositivo → frida-server →
    anti_root → baseline → spawn do app → anti_frida → bypass combinado
    → anti_hooking → ssl_pinning → anti_emulador (probe + bypass) →
    relatórios → tabela final → cleanup.

    O anti-emulador roda por último e com spawns próprios: o probe faz o
    app enxergar um emulador, o que contaminaria a observação dos demais
    checks.

    Com ``--avd``, o alvo é o emulador configurado em vez do device
    físico: ele é iniciado antes da conexão ADB e encerrado no cleanup.

    Args:
        args: Argumentos já parseados.

    Returns:
        Código de saída do processo (0 = sucesso parcial/total; o
        pipeline sempre tenta terminar).
    """
    logger = logging.getLogger("raspilot")

    # 0) Ambiente emulado (opcional): o alvo passa a ser o AVD.
    avd_manager = None
    try:
        avd_manager = _activate_avd(args)
        if avd_manager is not None:
            args.device_id = avd_manager.serial
    except Exception:
        if avd_manager is not None:
            avd_manager.stop()
        raise

    # 1) Conexão ADB (USB ou Wi-Fi).
    logger.info("Conectando ao dispositivo...")
    try:
        dm = DeviceManager(
            device_id=args.device_id,
            wifi_target=args.wifi,
            verbose=args.verbose,
        )
        dm.connect_adb()
    except Exception:
        # O emulador subiu antes da conexão: sem este cuidado ele
        # ficaria rodando sem ninguém para encerrá-lo.
        if avd_manager is not None:
            avd_manager.stop()
        raise

    info = dm.get_device_info()
    console.print("[green]✓[/] Dispositivo conectado:")
    for key, value in info.items():
        console.print(f"    [dim]{key}:[/] {value}")

    # 2) Frida server.
    dm.setup_frida_server()
    console.print("[green]✓[/] frida-server instalado, iniciado e validado")

    # Captura contínua de logcat: fonte independente de evidência para
    # correlação de mortes, crashes e mensagens de segurança.
    if dm.start_logcat_capture():
        logger.info("Captura de logcat ativa")
    else:
        logger.warning("Captura de logcat indisponível (seguindo sem ela)")

    # 3) Relatório.
    reporter = Reporter(
        device_info=info,
        package_name=args.package,
        output_dir=args.output_dir,
        run_context=_build_run_context(args, dm),
    )

    # 3.1) Perfil estático do APK (uma única vez, compartilhado pelos
    #      checks). Roda antes de qualquer spawn: não depende do app vivo.
    static_profile = None
    if getattr(args, "static_engine", "auto") != "off":
        with console.status("[cyan]Analisando o APK (estático)...[/]"):
            try:
                static_profile = build_static_profile(
                    dm,
                    args.package,
                    engine=getattr(args, "static_engine", "auto"),
                    timeout=getattr(args, "static_timeout", 60.0),
                )
            except Exception as exc:  # o ASC não pode derrubar o pipeline
                logger.warning("Análise estática falhou", exc_info=True)
                static_profile = None
                console.print(
                    f"[yellow]![/] Estático indisponível: {escape(str(exc))}"
                )
        if static_profile and static_profile.get("available"):
            summary = static_profile.get("summary") or {}
            present = summary.get("vectors_present") or []
            engine = summary.get("engine") or "?"
            console.print(
                f"[green]✓[/] Estático ({engine}): "
                f"{len(present)} vetor(es) com indícios"
                + (f" — {', '.join(present)}" if present else "")
            )
            reporter.run_context["static"] = {
                "available": True,
                "engine": summary.get("engine"),
                "version": static_profile.get("version"),
                "vectors_present": present,
                "rasp_sdks": summary.get("rasp_sdks") or [],
                "classes_count": static_profile.get("classes_count"),
                "cached": bool(static_profile.get("cached")),
            }
        elif static_profile:
            reason = (static_profile.get("summary") or {}).get("error") or "indisponível"
            console.print(f"[yellow]![/] Estático: {escape(str(reason))}")
            reporter.run_context["static"] = {
                "available": False,
                "engine": static_profile.get("engine"),
                "error": reason,
            }

    session = None
    pid = None
    xposed: Optional[XposedManager] = None
    try:
        # 4) Anti-Root (não requer app rodando).
        _run_step(
            reporter,
            "anti_root",
            lambda: AntiRootCheck(
                dm, mode=args.mode, no_java=args.no_java
            ).run_all(
                static_profile=static_profile,
                package_name=args.package,
                window=args.window,
            ),
            skipped="anti_root" in args.skip,
        )

        # 5) Baseline sem instrumentação (antes de qualquer spawn Frida):
        #    estabelece se o app já morre sozinho, evitando classificar
        #    crash/lifecycle normal como reação do RASP.
        dynamic = any(
            check not in args.skip
            for check in (
                "anti_frida", "anti_hooking", "ssl_pinning", "anti_emulator",
            )
        )
        if dynamic and not args.no_baseline:
            with console.status("[cyan]Executando baseline sem instrumentação...[/]"):
                dm.baseline = dm.run_app_baseline(
                    args.package, window=max(1, args.baseline_window)
                )
            if dm.baseline.get("available"):
                console.print(
                    f"[green]✓[/] Baseline: pid={dm.baseline.get('pid')} "
                    f"vivo={dm.baseline.get('alive_at_end')} "
                    f"morte={dm.baseline.get('death_cause', {}).get('summary') if dm.baseline.get('death_cause') else 'não'}"
                )
            else:
                console.print(
                    "[yellow]![/] Baseline indisponível "
                    f"({dm.baseline.get('reason', 'sem pid')})"
                )

        # 7) Spawn único para observação combinada (anti-Frida + anti-hooking).
        #    Spawn SUSPENSO: os hooks nativos são instalados antes do
        #    código do app rodar; o resume acontece após essa instalação.
        frida_logcat_mark = dm.logcat_mark()
        frida_detection = None
        hook_detection = None
        hook_method = getattr(args, "hook_method", "auto")
        emulator_method = getattr(args, "emulator_method", "auto")

        # Módulo de instrumentação: usado pelos checks de hooking e de
        # emulador quando o método escolhido é "module" ou "auto".
        if hook_method != "frida" or emulator_method != "frida":
            xposed = XposedManager(
                dm,
                args.package,
                apk_path=getattr(args, "module_apk", None),
            )
            framework = xposed.detect()
            reporter.run_context["xposed"] = {
                "framework": framework.get("name"),
                "version": framework.get("version"),
                "available": bool(framework.get("available")),
                "details": framework.get("details"),
            }
            if framework.get("available"):
                console.print(
                    f"[green]✓[/] Framework de hooking: "
                    f"{framework.get('name')} {framework.get('version') or ''}"
                )
            else:
                console.print(
                    "[yellow]![/] Framework de hooking indisponível "
                    f"({framework.get('details')}) — usando Frida"
                )

        need_combined = any(
            check not in args.skip for check in ("anti_frida", "anti_hooking")
        )
        if need_combined:
            with console.status(f"[cyan]Spawning {args.package}...[/]"):
                session = dm.spawn_app(args.package, resume=False)
            pid = dm.get_app_pid(args.package)
            console.print(f"[green]✓[/] App spawnado suspenso (pid={pid})")
            reporter.run_context["target_pid"] = pid
            if pid is not None:
                with console.status("[cyan]Observando camadas em sessão única...[/]"):
                    frida_detection, hook_detection = run_combined_observation(
                        dm,
                        session,
                        pid,
                        args.package,
                        args.window,
                        frida_logcat_mark,
                        dm.resume_app,
                        mode=args.mode,
                        no_java=args.no_java,
                        java_timeout=args.java_timeout,
                    )

        # 8) Anti-Frida (usa a detecção combinada; vetores de dispositivo
        #    rodam em seguida, com o app já retomado).
        if "anti_frida" not in args.skip:
            if pid is not None and frida_detection is not None:
                _run_step(
                    reporter,
                    "anti_frida",
                    lambda: AntiFridaCheck(
                        dm, mode=args.mode, no_java=args.no_java
                    ).run_all(
                        session, pid,
                        window=args.window,
                        package_name=args.package,
                        logcat_mark=frida_logcat_mark,
                        app_detection=frida_detection,
                        static_profile=static_profile,
                    ),
                )
            else:
                reporter.collect("anti_frida", {"error": "app não pôde ser spawnado"})
                console.print("[yellow]![/] anti_frida: [red]ERROR[/] (app não spawnado)")

        # 9) Bypass combinado (anti-hooking + SSL) em um único spawn.
        hooking_bypass = None
        ssl_bypass = None
        if (
            "anti_hooking" not in args.skip
            and "ssl_pinning" not in args.skip
            and args.mode != "detect"
            and not args.no_java
            and hook_method == "frida"
        ):
            with console.status("[cyan]Executando bypass combinado...[/]"):
                hooking_bypass, ssl_bypass = run_combined_bypass(
                    dm, args.package, args.window,
                    mode=args.mode, no_java=args.no_java,
                    java_timeout=args.java_timeout,
                )

        # 10) Anti-Hooking (usa detecção e bypass combinados quando houver).
        _run_step(
            reporter,
            "anti_hooking",
            lambda: AntiHookingCheck(
                dm, mode=args.mode, no_java=args.no_java,
                method=hook_method, xposed=xposed,
            ).run_all(
                args.package,
                window=args.window,
                precomputed_detection=hook_detection,
                precomputed_bypass=hooking_bypass,
                static_profile=static_profile,
            ),
            skipped="anti_hooking" in args.skip,
        )

        # 11) SSL Pinning (usa bypass combinado quando houver).
        _run_step(
            reporter,
            "ssl_pinning",
            lambda: SSLPinningCheck(dm, mode=args.mode, no_java=args.no_java).run_all(
                args.package, window=args.window,
                precomputed_bypass=ssl_bypass,
                static_profile=static_profile,
            ),
            skipped="ssl_pinning" in args.skip,
        )

        # 12) Anti-Emulador (detecção + bypass).
        #
        # Roda por último e com spawns próprios: o probe faz o app
        # enxergar um emulador, e o bypass oculta os artefatos decisivos.
        # Um spawn compartilhado com a observação combinada contaminaria
        # os outros checks — o app reagiria ao ambiente emulado, não à
        # instrumentação.
        _run_step(
            reporter,
            "anti_emulator",
            lambda: AntiEmulatorCheck(
                dm, mode=args.mode, no_java=args.no_java,
                java_timeout=args.java_timeout,
                method=emulator_method, xposed=xposed,
            ).run_all(
                args.package,
                window=args.window,
                static_profile=static_profile,
            ),
            skipped="anti_emulator" in args.skip,
        )
    finally:
        # 13) Cleanup — nunca deixar resíduos no dispositivo.
        try:
            dm.stop_logcat_capture()
        except Exception:
            logger.debug("Falha ao encerrar captura de logcat", exc_info=True)
        try:
            dm.resume_app()  # idempotente: destrava spawn suspenso, se houver
            safe_detach(session)
        except Exception:
            logger.debug("Falha ao detach da sessão final", exc_info=True)
        if xposed is not None:
            try:
                for action in xposed.finish():
                    logger.info(
                        "Cleanup do módulo (%s): ok=%s %s",
                        action.get("step"), action.get("ok"), action.get("detail"),
                    )
            except Exception:
                logger.warning("Falha no cleanup do módulo", exc_info=True)
        try:
            dm.remove_frida_server()
            dm.run_shell(f"am force-stop {args.package}", timeout=10)
            # Alguns apps reiniciam um processo logo após o force-stop;
            # uma segunda passada garante o encerramento.
            time.sleep(1)
            dm.run_shell(f"am force-stop {args.package}", timeout=10)
        except Exception:
            logger.warning("Falha no cleanup final do dispositivo", exc_info=True)
        if avd_manager is not None:
            # O emulador que esta execução subiu é encerrado aqui; um
            # AVD que já estava rodando antes é preservado.
            try:
                avd_manager.stop()
            except Exception:
                logger.warning("Falha ao encerrar o AVD", exc_info=True)

    # 14) Relatórios.
    json_path, html_path = reporter.save()
    print_summary_table(reporter)
    print_execution_log(reporter)
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
        return run_pipeline(args)
    except (DeviceConnectionError, FridaSetupError) as exc:
        console.print(f"[bold red]✗ Erro:[/] {exc}")
        logger.debug("Detalhes do erro:", exc_info=True)
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
