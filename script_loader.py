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
from typing import Callable, List, Optional

logger = logging.getLogger("raspilot.script_loader")

try:
    import frida_tools
    from pathlib import Path

    _BRIDGES_DIR = Path(frida_tools.__file__).parent / "bridges"
except ImportError:  # pragma: no cover - frida-tools é dependência obrigatória
    _BRIDGES_DIR = None  # type: ignore[assignment]

# Script mínimo de enumeração de módulos. A API host do Frida 17+ NÃO
# expõe ``Session.enumerate_modules`` — módulos só são visíveis de dentro
# do processo, via ``Process.enumerateModules()``. Expomos a lista por RPC.
MODULE_ENUM_SCRIPT = """
'use strict';

rpc.exports = {
    listmodules: function () {
        var names = [];
        try {
            Process.enumerateModules().forEach(function (m) {
                if (m && m.name) { names.push(m.name); }
            });
        } catch (e) { /* best-effort */ }
        return names;
    }
};
"""

# Prelúdio de compatibilidade entre versões do Frida, sempre prependido
# (junto com a bridge Java) aos scripts do RASPilot:
#
# - Frida 17 removeu o ``Module.findExportByName`` estático → usamos os
#   métodos de instância (``Process.getModuleByName``) e o global
#   ``Module.findGlobalExportByName``, com fallback para a API antiga.
# - Em spawn suspenso (Frida 17 + QuickJS) ``Java.perform`` pode
#   enfileirar o callback sem nunca executá-lo → preferimos
#   ``Java.performNow``, que roda imediatamente.
COMPAT_PRELUDE = """
'use strict';

function raspilotFindExport(moduleName, exportName) {
    try {
        if (typeof Process !== 'undefined' && typeof Process.getModuleByName === 'function') {
            var mod = Process.getModuleByName(moduleName);
            if (mod !== null && typeof mod.findExportByName === 'function') {
                var addr = mod.findExportByName(exportName);
                if (addr !== null) { return addr; }
            }
        }
    } catch (e) { /* módulo não carregado */ }
    try {
        if (typeof Module !== 'undefined' && typeof Module.findGlobalExportByName === 'function') {
            var globalAddr = Module.findGlobalExportByName(exportName);
            if (globalAddr !== null) { return globalAddr; }
        }
    } catch (e) { /* best-effort */ }
    try {
        if (typeof Module !== 'undefined' && typeof Module.findExportByName === 'function') {
            return Module.findExportByName(moduleName, exportName); // Frida <= 16
        }
    } catch (e) { /* best-effort */ }
    return null;
}

function raspilotPerformJava(fn) {
    try {
        if (typeof Java === 'undefined' || !Java.available) { return false; }
        if (typeof Java.performNow === 'function') {
            Java.performNow(fn);
            return true;
        }
        Java.perform(fn);
        return true;
    } catch (e) {
        try {
            send({ type: 'raspilot-script-error', message: 'hooks Java: ' + e });
        } catch (e2) { /* host indisponível */ }
        return false;
    }
}
"""


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

    Concatena (1) a bridge Java do frida-tools quando disponível,
    (2) o prelúdio de compatibilidade Frida 16/17 e (3) o código do
    check/bypass.

    Args:
        source: Código JS do check/bypass (usa os globals ``Java`` e
            ``raspilotFindExport``/``raspilotPerformJava``).

    Returns:
        Código preparado para ``session.create_script``.
    """
    return java_bridge_prelude() + COMPAT_PRELUDE + source


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


def safe_unload(script: Optional[object]) -> None:
    """Descarrega um script Frida tolerando scripts já destruídos.

    Quando o processo alvo se encerra (reação típica de RASP), o Frida
    destrói o script e um ``script.unload()`` subsequente levanta
    ``frida.InvalidOperationError``. Esse é um caso **esperado** no
    RASPilot, então não deve virar ruído/traceback no log.

    Args:
        script: Objeto ``frida.core.Script`` (ou ``None``).

    Returns:
        None.
    """
    if script is None:
        return
    try:
        script.unload()
    except Exception as exc:  # noqa: BLE001 - script destruído é esperado
        logger.debug("Unload ignorado (%s: %s)", type(exc).__name__, exc)


def enumerate_module_names(session: object) -> List[str]:
    """Lista os nomes dos módulos carregados no processo da sessão.

    Usa ``session.enumerate_modules()`` quando existir (compat com
    sessões fake/legadas) e, no Frida 17+ (onde esse método não existe),
    injeta :data:`MODULE_ENUM_SCRIPT` e lê a lista via RPC.

    Args:
        session: Sessão Frida ativa.

    Returns:
        Lista com os nomes dos módulos (possivelmente vazia).

    Raises:
        Exception: erros do Frida propagam ao chamador (que os converte
            em resultado estruturado).
    """
    legacy = getattr(session, "enumerate_modules", None)
    if callable(legacy):
        return [mod.name for mod in legacy()]

    script = session.create_script(MODULE_ENUM_SCRIPT)
    script.load()
    try:
        names = script.exports.listmodules()
    finally:
        safe_unload(script)
    return list(names or [])
