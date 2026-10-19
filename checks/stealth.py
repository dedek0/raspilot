"""RASPilot — Bootstrap nativo de stealth antes do resume.

Carrega, sem a bridge Java e antes do app executar, os hooks nativos que
escondem os artefatos da instrumentação:

- ``proc_filter.js``: maps, TracerPid, portas, threads/comm, readlink,
  ptrace e syscalls diretas para arquivos de ``/proc``.
- ``anti_frida_bypass.js`` (somente camada nativa): strings, paths,
  portas, threads e ``File.exists``/exec via camada nativa.

A bridge Java é carregada depois do resume, reduzindo o risco de
``start timeout`` e dando ao app menos tempo para reagir à injeção.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Dict, List, Optional, Tuple

from script_loader import load_script_file, safe_unload

logger = logging.getLogger("raspilot.checks.stealth")

SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)
PROC_FILTER_SCRIPT = os.path.join(SCRIPTS_DIR, "proc_filter.js")
ANTI_FRIDA_BYPASS_SCRIPT = os.path.join(SCRIPTS_DIR, "anti_frida_bypass.js")


def load_stealth(
    session: object,
    on_message: Optional[Callable] = None,
    replacements: Optional[Dict[str, str]] = None,
    include_proc_filter: bool = True,
    load_native_frida: bool = True,
    load_timeout: float = 5.0,
) -> List[Tuple[str, object]]:
    """Instala o bootstrap nativo de stealth na sessão.

    Deve ser chamado antes de ``resume``. Usa ``with_java_bridge=False``
    e ``__RASPILOT_JAVA_ONLY__=false`` em todos os scripts.

    Args:
        session: Sessão Frida ativa.
        on_message: Callback de mensagens dos scripts.
        replacements: Placeholders (porta real etc.).
        include_proc_filter: Se False, não carrega o filtro de ``/proc``.
        load_native_frida: Se False, não carrega a evasão anti-Frida
            nativa. Desligar mantém a reação do app visível, que é o
            comportamento desejado na modo de observação pura.
        load_timeout: Timeout por script.

    Returns:
        Lista de tuplas ``(caminho, script)`` carregadas com sucesso.
    """
    loaded: List[Tuple[str, object]] = []
    scripts: List[tuple] = []
    if include_proc_filter:
        scripts.append((PROC_FILTER_SCRIPT, "raspilot-stealth-proc"))
    if load_native_frida:
        scripts.append((ANTI_FRIDA_BYPASS_SCRIPT, "raspilot-stealth-frida"))

    for path, name in scripts:
        reps = dict(replacements or {})
        reps["__RASPILOT_JAVA_ONLY__"] = "false"
        try:
            script = load_script_file(
                session,
                path,
                on_message=on_message,
                replacements=reps,
                with_java_bridge=False,
                name=name,
                load_timeout=load_timeout,
            )
            loaded.append((path, script))
        except Exception:
            logger.warning("Script de stealth %s indisponível", name, exc_info=True)

    logger.debug(
        "Bootstrap stealth carregado: %s",
        [os.path.basename(path) for path, _ in loaded],
    )
    return loaded


def unload_stealth(loaded: List[Tuple[str, object]]) -> None:
    """Descarrega scripts de stealth com tolerância a sessão encerrada."""
    for _, script in loaded or []:
        safe_unload(script)
