"""RASPilot — Renderização do script de hook de veredito.

Monta o código do gancho de veredito a partir do catálogo de vendors
(:mod:`rasp_vendors`) e o carrega na sessão.

O catálogo vira dado do script: os nomes de método e as classes
conhecidas são substituídos no carregamento, de modo que o script
permanece genérico e o catálogo pode crescer sem tocar no JavaScript.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from rasp_vendors import (
    BOOLEAN_VERDICT_METHODS,
    VENDORS,
    verdict_method_names,
)
from script_loader import load_script_file

logger = logging.getLogger("raspilot.verdict_hook")

SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)
VERDICT_HOOK_SCRIPT = os.path.join(SCRIPTS_DIR, "verdict_hook.js")


def _js_string_list(values) -> str:
    """Serializa uma sequência de strings como array JavaScript.

    Args:
        values: Strings a serializar.

    Returns:
        Literal JavaScript com o array.
    """
    items = []
    for value in values:
        escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
        items.append("'" + escaped + "'")
    return "[" + ", ".join(items) + "]"


def vendor_class_names() -> List[str]:
    """Retorna as classes Java conhecidas dos vendors do catálogo.

    Os tokens de classe dos vendors são usados como nomes de classe
    candidatos: o gancho tenta resolvê-los e ignora os que não existem.

    Returns:
        Lista de nomes de classe.
    """
    names: List[str] = []
    for vendor in VENDORS:
        for token in vendor.tokens:
            if "." not in token:
                continue
            if token in names:
                continue
            names.append(token)
    return names


def build_replacements() -> dict:
    """Monta os placeholders do script de veredito.

    Returns:
        Mapa de placeholders para substituição.
    """
    return {
        "__RASPILOT_VERDICT_METHODS__": _js_string_list(verdict_method_names()),
        "__RASPILOT_BOOLEAN_VERDICT_METHODS__": _js_string_list(
            BOOLEAN_VERDICT_METHODS
        ),
        "__RASPILOT_VENDOR_CLASSES__": _js_string_list(vendor_class_names()),
    }


def load_verdict_hook(
    session: object,
    on_message: Optional[object] = None,
    load_timeout: float = 20.0,
) -> Optional[object]:
    """Carrega o script de hook de veredito na sessão.

    Args:
        session: Sessão Frida ativa.
        on_message: Callback de mensagens do script.
        load_timeout: Timeout de carga do script.

    Returns:
        O script carregado, ou ``None`` se não foi possível.
    """
    try:
        return load_script_file(
            session,
            VERDICT_HOOK_SCRIPT,
            on_message=on_message,
            replacements=build_replacements(),
            with_java_bridge=True,
            name="raspilot-verdict-hook",
            load_timeout=load_timeout,
        )
    except Exception:
        logger.warning("Hook de veredito indisponível", exc_info=True)
        return None
