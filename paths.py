"""RASPilot — diretórios de estado e cache.

Centraliza a resolução de caminhos para que CLI, testes e (na próxima
fase) o servidor MCP usem a mesma raiz. Variáveis de ambiente:

- ``RASPILOT_HOME``: raiz alternativa (default ``~/.raspilot``).
- ``RASPILOT_CACHE_DIR``: raiz alternativa só para caches.
- ``RASPILOT_STATIC_CACHE_DIR``: diretório do cache estático (legado).
- ``RASPILOT_STATE_DIR``: diretório das sessões (default
  ``$RASPILOT_HOME/sessions``).

Nenhuma função cria diretórios; quem grava é responsável por isso.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, "os.PathLike[str]"]


def home() -> Path:
    """Raiz de dados do RASPilot.

    Returns:
        ``$RASPILOT_HOME`` ou ``~/.raspilot``.
    """
    explicit = os.environ.get("RASPILOT_HOME")
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / ".raspilot"


def cache_dir(*parts: str) -> Path:
    """Diretório de cache, com partes opcionais.

    Args:
        *parts: Subdiretórios (ex: ``"static"``, ``"apk"``).

    Returns:
        ``$RASPILOT_CACHE_DIR``/parts ou ``$RASPILOT_HOME/cache``/parts.
    """
    explicit = os.environ.get("RASPILOT_CACHE_DIR")
    base = Path(explicit).expanduser() if explicit else home() / "cache"
    return base.joinpath(*parts)


def static_cache_dir() -> Path:
    """Diretório do cache de perfis/consultas estáticas.

    Mantém compatibilidade com ``RASPILOT_STATIC_CACHE_DIR``.
    """
    explicit = os.environ.get("RASPILOT_STATIC_CACHE_DIR")
    if explicit:
        return Path(explicit).expanduser()
    return cache_dir("static")


def state_dir(explicit: Optional[PathLike] = None) -> Path:
    """Diretório das sessões persistentes.

    Args:
        explicit: Caminho informado por ``--state-dir``.

    Returns:
        O caminho explícito, ``$RASPILOT_STATE_DIR`` ou
        ``$RASPILOT_HOME/sessions``.
    """
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("RASPILOT_STATE_DIR")
    if env:
        return Path(env).expanduser()
    return home() / "sessions"


def keys_dir() -> Path:
    """Diretório de keystores do repack."""
    return home() / "keys"


def gadgets_dir() -> Path:
    """Diretório de Frida Gadgets."""
    return home() / "gadgets"


def repack_dir() -> Path:
    """Diretório padrão de artefatos do repack."""
    return home() / "repack"


def avd_config_path() -> Path:
    """Caminho padrão da configuração do AVD."""
    return home() / "avd.json"
