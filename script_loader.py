"""RASPilot — Carregador de scripts Frida com bridge Java.

No Frida 17+ a bridge Java deixou de ser um global embutido: scripts
precisam importar ``frida-java-bridge`` via módulos dinâmicos ou fazer
o handshake ``frida:load-bridge`` com o host. Para manter os scripts
do RASPilot funcionando de forma simples e determinística, este módulo
prepende a bridge pré-compilada que o ``frida-tools`` já distribui em
``frida_tools/bridges/java.js`` e a expõe como ``Java`` no mesmo scope
do script.

Compatibilidade: em instalações antigas (frida <= 16, sem o diretório
``bridges/``), o script é carregado cru — a bridge global ``Java``
existia nativamente nesses versions.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Optional

logger = logging.getLogger("raspilot.script_loader")

try:
    import frida_tools
    from pathlib import Path

    _BRIDGES_DIR = Path(frida_tools.__file__).parent / "bridges"
except ImportError:  # pragma: no cover - frida-tools é dependência obrigatória
    _BRIDGES_DIR = None  # type: ignore[assignment]


def java_bridge_available() -> bool:
    """Verifica se a bridge Java pré-compilada do frida-tools existe.

    Returns:
        True se ``frida_tools/bridges/java.js`` está presente.
    """
    return bool(_BRIDGES_DIR and (_BRIDGES_DIR / "java.js").is_file())


def java_bridge_prelude() -> str:
    """Retorna o prelúdio que define ``Java`` a partir da bridge do frida-tools.

    O ``bridges/java.js`` define ``var bridge = ...``; o epílogo
    ``var Java = bridge`` torna o uso nos scripts idêntico ao Frida 16.

    Returns:
        Código JS do prelúdio (string vazia se a bridge não existir).
    """
    if not java_bridge_available():
        return ""
    try:
        bridge_src = (_BRIDGES_DIR / "java.js").read_text(encoding="utf-8")
    except OSError:
        logger.warning("Falha ao ler bridge Java; script será carregado cru")
        return ""
    return bridge_src + "\nvar Java = bridge;\n"


def prepare_script(source: str) -> str:
    """Prepara o código-fonte de um script Frida para injeção.

    Args:
        source: Código JS do check/bypass (usa o global ``Java``).

    Returns:
        Código com o prelúdio da bridge prependado (ou o original).
    """
    prelude = java_bridge_prelude()
    if not prelude:
        logger.debug("Bridge Java indisponível — usando script cru")
        return source
    return prelude + source


def load_script(
    session: object,
    source: str,
    on_message: Optional[Callable] = None,
    name: Optional[str] = None,
) -> object:
    """Cria e carrega um script Frida preparado (com bridge Java).

    Args:
        session: Sessão Frida ativa.
        source: Código JS do script.
        name: Nome opcional do script (aparece em depuração).
        on_message: Callback de mensagens do script.

    Returns:
        O objeto ``frida.core.Script`` carregado.

    Raises:
        Exception: erros do próprio Frida propagam ao chamador (que os
            converte em resultado estruturado).
    """
    prepared = prepare_script(source)
    kwargs = {"name": name} if name else {}
    script = session.create_script(prepared, **kwargs)
    if on_message is not None:
        script.on("message", on_message)
    script.load()
    logger.debug("Script carregado%s ( %d bytes preparados)",
                 f" '{name}'" if name else "", len(prepared))
    return script


def load_script_file(
    session: object,
    path: str,
    on_message: Optional[Callable] = None,
) -> object:
    """Lê um arquivo .js e o carrega via :func:`load_script`.

    Args:
        session: Sessão Frida ativa.
        path: Caminho do arquivo JS.
        on_message: Callback de mensagens.

    Returns:
        O ``Script`` carregado.

    Raises:
        OSError: se o arquivo não puder ser lido.
    """
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return load_script(session, source, on_message=on_message, name=os.path.basename(path))
