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
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence

logger = logging.getLogger("raspilot.script_loader")

# Conteúdo da bridge Java cacheado por caminho absoluto.
_BRIDGE_CACHE: Dict[str, str] = {}

# Runtime JavaScript padrão usado pelo Frida nos scripts do RASPilot.
# Definido uma vez pela CLI (``--js-runtime``) e aplicável a todos os
# carregamentos, sem precisar propagar o parâmetro por cada check.
_JS_RUNTIME: Optional[str] = None


def set_js_runtime(runtime: Optional[str]) -> None:
    """Define o runtime JavaScript padrão dos próximos scripts.

    Args:
        runtime: ``"qjs"``, ``"v8"`` ou ``None`` para usar o padrão do
            Frida.
    """
    global _JS_RUNTIME
    _JS_RUNTIME = runtime


def js_runtime() -> Optional[str]:
    """Retorna o runtime JavaScript padrão configurado.

    Returns:
        ``"qjs"``, ``"v8"`` ou ``None``.
    """
    return _JS_RUNTIME

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

// Executa um callback na thread principal do app.
//
// A thread do JavaScript do Frida não é uma thread Java: a ponte Java a
// anexa ao runtime sob demanda, e a resolução de classes nesse contexto
// pode não concluir. Executar na thread principal do app é o caminho
// suportado pela ponte e o que as ferramentas de instrumentação usam.
function raspilotPerformJavaOnMain(fn) {
    try {
        if (typeof Java === 'undefined' || !Java.available) { return false; }
        if (typeof Java.perform === 'function') {
            Java.perform(fn);
            return true;
        }
        return raspilotPerformJava(fn);
    } catch (e) {
        try {
            send({ type: 'raspilot-script-error', message: 'hooks Java: ' + e });
        } catch (e2) { /* host indisponível */ }
        return false;
    }
}

// Agenda a instalação dos hooks Java para depois do carregamento do
// script.
//
// O script.load() só retorna quando o código de primeiro nível termina.
// Instalar os hooks Java sincronamente faz o load bloquear pelo tempo
// de inicialização do runtime Java no processo alvo — em apps com muitos
// dex isso passa de meio minuto e o carregamento é interrompido pelo
// limite do agente, que descarta o script no meio da execução.
//
// Adiar a instalação devolve o load imediatamente e deixa os hooks
// entrarem em background. O script sinaliza a prontidão com
// 'raspilot-java-ready'.
function raspilotDeferJava(fn, label) {
    try {
        setImmediate(function () {
            try {
                if (typeof Java === 'undefined' || !Java.available) {
                    try {
                        send({ type: 'raspilot-java-unavailable', label: label || '' });
                    } catch (e) { /* host indisponível */ }
                    return;
                }
                raspilotPerformJavaOnMain(fn);
                try {
                    send({ type: 'raspilot-java-ready', label: label || '' });
                } catch (e) { /* host indisponível */ }
            } catch (e) {
                try {
                    send({ type: 'raspilot-script-error', message: 'hooks Java: ' + e });
                } catch (e2) { /* host indisponível */ }
            }
        });
        return true;
    } catch (e) {
        return false;
    }
}
"""

# Bootstrap da bridge Java, executado no topo de todo script Java.
#
# A bridge grava as classes geradas por ``Java.registerClass`` em um DEX
# temporário dentro de ``Java.classFactory.cacheDir``. O diretório padrão
# da bridge fica fora do sandbox do app, e o processo alvo roda com o uid
# do próprio app: a gravação falha e ``registerClass`` deixa de funcionar.
#
# Este bootstrap redireciona o cache para um diretório gravável pelo app
# (o code_cache do próprio app), o que torna ``registerClass`` utilizável.
# O nome do arquivo temporário também é neutralizado, porque o DEX gerado
# é um artefato observável pelo app.
JAVA_BOOTSTRAP = """
'use strict';

// O bootstrap é adiado: tocar em ``Java.classFactory`` dispara a
// inicialização do runtime Java no processo alvo, que em apps com muitos
// dex leva dezenas de segundos. Feito no topo do script, ele bloqueia o
// carregamento e o agente descarta o script ao atingir o limite.
setImmediate(function () {
    if (typeof Java === 'undefined' || !Java.available) { return; }
    if (typeof Java.classFactory === 'undefined') { return; }

    function applyDir(dir) {
        if (!dir) { return false; }
        try {
            Java.classFactory.cacheDir = dir;
            Java.classFactory.codeCacheDir = dir;
            return true;
        } catch (e) { return false; }
    }

    function currentApplication() {
        try {
            var AT = Java.use('android.app.ActivityThread');
            var app = AT.currentApplication();
            if (app !== null) { return app; }
        } catch (e) { /* sem ActivityThread */ }
        try {
            var AG = Java.use('android.app.AppGlobals');
            var app = AG.getInitialApplication();
            if (app !== null) { return app; }
        } catch (e) { /* sem AppGlobals */ }
        return null;
    }

    function appCacheDir(app) {
        if (app === null) { return null; }
        try {
            if ('getCodeCacheDir' in app) {
                var d = app.getCodeCacheDir();
                if (d !== null) { return d.getCanonicalPath(); }
            }
        } catch (e) { /* sem code_cache */ }
        try {
            var d = app.getFilesDir();
            if (d !== null) { return d.getCanonicalPath(); }
        } catch (e) { /* sem files dir */ }
        return null;
    }

    var app = currentApplication();
    var dir = appCacheDir(app);
    if (dir === null) {
        // O app ainda não foi criado (spawn muito cedo): deriva o diretório
        // de dados do processo a partir do link simbólico do cwd, que
        // pertence ao uid do app.
        try {
            var pid = Process.id;
            var link = Memory.allocUtf8String('/proc/' + pid + '/cwd');
            var buf = Memory.alloc(1024);
            var rl = new NativeFunction(
                Module.findGlobalExportByName('readlink'), 'pointer',
                ['pointer', 'pointer', 'pointer'], { exceptions: 'propagate' });
            var n = rl(link, buf, ptr(1024)).toInt32();
            if (n > 0) {
                var cwd = buf.readUtf8String(n);
                var idx = cwd.lastIndexOf('/');
                if (idx > 0) {
                    dir = cwd.substring(0, idx) + '/code_cache';
                }
            }
        } catch (e) { /* best-effort */ }
    }

    if (applyDir(dir)) {
        try {
            Java.classFactory.tempFileNaming = { prefix: 'opt', suffix: '' };
        } catch (e) { /* best-effort */ }
        try {
            send({
                type: 'raspilot-java-bootstrap',
                message: 'classFactory cacheDir: ' + dir
            });
        } catch (e) { /* host indisponível */ }
    }
});
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

    O conteúdo é cacheado por caminho: a bridge tem centenas de KB e é
    lida por todo script Java carregado na mesma execução.

    Returns:
        Código JS do prelúdio (string vazia se a bridge não existir).
    """
    if not java_bridge_available():
        return ""
    path = _BRIDGES_DIR / "java.js"
    key = str(path)
    bridge_src = _BRIDGE_CACHE.get(key)
    if bridge_src is None:
        try:
            bridge_src = path.read_text(encoding="utf-8")
        except OSError:
            logger.warning("Falha ao ler bridge Java; script será carregado cru")
            return ""
        _BRIDGE_CACHE[key] = bridge_src
    return bridge_src + "\nvar Java = bridge;\n"


def render_script(source: str, replacements: Optional[Dict[str, str]] = None) -> str:
    """Substitui placeholders de configuração no código JS.

    Usado para injetar a porta real do frida-server nos scripts sem
    duplicar arquivos por configuração.

    Args:
        source: Código JS original.
        replacements: Mapa ``{placeholder: valor}``.

    Returns:
        Código com os placeholders substituídos.
    """
    if not replacements:
        return source
    rendered = source
    for key, value in replacements.items():
        rendered = rendered.replace(key, str(value))
    return rendered


def prepare_script(
    source: str,
    replacements: Optional[Dict[str, str]] = None,
    with_java_bridge: bool = True,
) -> str:
    """Prepara o código-fonte de um script Frida para injeção.

    Concatena (1) a bridge Java do frida-tools quando disponível e
    solicitada, (2) o prelúdio de compatibilidade Frida 16/17, (3) o
    bootstrap da bridge Java e (4) o código do check/bypass. Placeholders
    de configuração são resolvidos antes.

    Scripts puramente nativos (ex: ``proc_filter.js``) podem desativar a
    bridge com ``with_java_bridge=False``. Isso reduz drasticamente o
    tempo de ``script.load()`` — importante para não estourar o
    ``start timeout`` do ActivityManager enquanto o app está suspenso.

    Args:
        source: Código JS do check/bypass (usa os globals ``Java`` e
            ``raspilotFindExport``/``raspilotPerformJava``).
        replacements: Mapa opcional de placeholders ``__RASPILOT_*__``.
        with_java_bridge: Se True (default), prepende a bridge Java.

    Returns:
        Código preparado para ``session.create_script``.
    """
    rendered = render_script(source, replacements)
    if not with_java_bridge:
        return COMPAT_PRELUDE + rendered
    return java_bridge_prelude() + COMPAT_PRELUDE + JAVA_BOOTSTRAP + rendered


def iife(source: str) -> str:
    """Encapsula um script em IIFE para evitar colisão de globais.

    Usado para compor múltiplos scripts no mesmo ``create_script``: cada
    um ganha seu próprio escopo, evitando que um script sobrescreva
    ``rpc.exports`` ou variáveis globais de outro.

    Args:
        source: Código JS do script.

    Returns:
        Código encapsulado em IIFE.
    """
    return "(function(){\n" + source + "\n})();\n"


def load_script(
    session: object,
    source: str,
    on_message: Optional[Callable] = None,
    name: Optional[str] = None,
    replacements: Optional[Dict[str, str]] = None,
    with_java_bridge: bool = True,
    load_timeout: Optional[float] = None,
    runtime: Optional[str] = None,
) -> object:
    """Cria e carrega um script Frida preparado (com bridge Java).

    Args:
        session: Sessão Frida ativa.
        source: Código JS do script.
        name: Nome opcional do script (aparece em depuração).
        on_message: Callback de mensagens do script.
        replacements: Mapa opcional de placeholders ``__RASPILOT_*__``.
        with_java_bridge: Se False, não prepende a bridge Java (scripts
            puramente nativos carregam muito mais rápido).
        load_timeout: Timeout opcional (segundos) para ``script.load()``.
            Evita travar o pipeline quando o alvo bloqueia a bridge.
        runtime: Runtime JavaScript opcional (``"qjs"`` ou ``"v8"``).
            ``None`` usa o padrão do Frida.

    Returns:
        O objeto ``frida.core.Script`` carregado.

    Raises:
        Exception: erros do próprio Frida propagam ao chamador (que os
            converte em resultado estruturado).
    """
    prepared = prepare_script(
        source,
        replacements=replacements,
        with_java_bridge=with_java_bridge,
    )
    kwargs: Dict[str, object] = {}
    if name:
        kwargs["name"] = name
    effective_runtime = runtime or _JS_RUNTIME
    if effective_runtime:
        kwargs["runtime"] = effective_runtime
    started = time.monotonic()
    script = session.create_script(prepared, **kwargs)
    if on_message is not None:
        script.on("message", on_message)

    if load_timeout is None:
        script.load()
    else:
        errors: List[BaseException] = []

        def _do_load() -> None:
            try:
                script.load()
            except BaseException as exc:  # noqa: BLE001 - repassado ao chamador
                errors.append(exc)

        loader = threading.Thread(target=_do_load, name="raspilot-script-load", daemon=True)
        loader.start()
        loader.join(load_timeout)
        if loader.is_alive():
            # O load ainda está em curso. Descarregar em paralelo corrompe a
            # sessão: o script é destruído no meio da execução e os hooks
            # instalados até ali desaparecem. Aguarda a conclusão e só então
            # descarta, em background, para não bloquear o pipeline.
            def _discard() -> None:
                loader.join()
                try:
                    script.unload()
                except Exception:
                    logger.debug("Descarte do script com timeout falhou", exc_info=True)

            threading.Thread(
                target=_discard, name="raspilot-script-discard", daemon=True
            ).start()
            raise TimeoutError(
                f"script.load() excedeu {load_timeout}s"
                + (f" ({name})" if name else "")
            )
        if errors:
            raise errors[0]

    elapsed = time.monotonic() - started
    logger.debug(
        "Script carregado%s (%d bytes preparados, %.2fs)",
        f" '{name}'" if name else "", len(prepared), elapsed,
    )
    return script


def load_java_bundle(
    session: object,
    sources: Sequence[str],
    on_message: Optional[Callable] = None,
    name: Optional[str] = None,
    replacements: Optional[Dict[str, str]] = None,
    load_timeout: Optional[float] = None,
    runtime: Optional[str] = None,
) -> object:
    """Carrega vários scripts Java em um único ``create_script``.

    A bridge Java pré-compilada do frida-tools tem hundreds de KB e o
    ``script.load()`` paga o custo de compilação a cada script. Como a
    bridge é obrigatória para qualquer hook Java, ela é compilada uma vez
    por sessão e os demais scripts são composed como IIFEs no mesmo
    script — o que reduz o custo de carga de forma proporcional ao
    número de scripts agrupados.

    Args:
        session: Sessão Frida ativa.
        sources: Códigos JS a carregar (cada um em seu próprio escopo).
        on_message: Callback de mensagens do script.
        name: Nome opcional do script.
        replacements: Mapa opcional de placeholders ``__RASPILOT_*__``.
        load_timeout: Timeout opcional (segundos) para ``script.load()``.
        runtime: Runtime JavaScript opcional (``"qjs"`` ou ``"v8"``).

    Returns:
        O objeto ``frida.core.Script`` carregado.

    Raises:
        Exception: erros do próprio Frida propagam ao chamador.
    """
    if not sources:
        raise ValueError("load_java_bundle exige ao menos um source")
    composed = "".join(iife(src) for src in sources)
    return load_script(
        session,
        composed,
        on_message=on_message,
        name=name,
        replacements=replacements,
        with_java_bridge=True,
        load_timeout=load_timeout,
        runtime=runtime,
    )


def load_script_file(
    session: object,
    path: str,
    on_message: Optional[Callable] = None,
    replacements: Optional[Dict[str, str]] = None,
    with_java_bridge: bool = True,
    name: Optional[str] = None,
    load_timeout: Optional[float] = None,
    runtime: Optional[str] = None,
) -> object:
    """Lê um arquivo .js e o carrega via :func:`load_script`.

    Args:
        session: Sessão Frida ativa.
        path: Caminho do arquivo JS.
        on_message: Callback de mensagens.
        replacements: Mapa opcional de placeholders ``__RASPILOT_*__``.
        with_java_bridge: Se False, não prepende a bridge Java.
        name: Nome opcional do script (default: basename do arquivo).
        load_timeout: Timeout opcional (segundos) para ``script.load()``.
        runtime: Runtime JavaScript opcional (``"qjs"`` ou ``"v8"``).

    Returns:
        O ``Script`` carregado.

    Raises:
        OSError: se o arquivo não puder ser lido.
    """
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return load_script(
        session,
        source,
        on_message=on_message,
        name=name or os.path.basename(path),
        replacements=replacements,
        with_java_bridge=with_java_bridge,
        load_timeout=load_timeout,
        runtime=runtime,
    )


def load_java_bundle_files(
    session: object,
    paths: Sequence[str],
    on_message: Optional[Callable] = None,
    name: Optional[str] = None,
    replacements: Optional[Dict[str, str]] = None,
    load_timeout: Optional[float] = None,
    runtime: Optional[str] = None,
) -> object:
    """Carrega vários arquivos JS em um único script com a bridge Java.

    Variante de :func:`load_java_bundle` que lê os scripts de disco.

    Args:
        session: Sessão Frida ativa.
        paths: Caminhos dos arquivos JS a carregar.
        on_message: Callback de mensagens do script.
        name: Nome opcional do script.
        replacements: Mapa opcional de placeholders ``__RASPILOT_*__``.
        load_timeout: Timeout opcional (segundos) para ``script.load()``.
        runtime: Runtime JavaScript opcional (``"qjs"`` ou ``"v8"``).

    Returns:
        O ``Script`` carregado.

    Raises:
        OSError: se algum arquivo não puder ser lido.
        ValueError: se ``paths`` for vazio.
    """
    if not paths:
        raise ValueError("load_java_bundle_files exige ao menos um path")
    sources: List[str] = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            sources.append(fh.read())
    return load_java_bundle(
        session,
        sources,
        on_message=on_message,
        name=name,
        replacements=replacements,
        load_timeout=load_timeout,
        runtime=runtime,
    )


def wait_for_java_ready(ready: "threading.Event", timeout: float = 30.0) -> bool:
    """Aguarda a camada Java ficar ativa na sessão.

    A instalação dos hooks Java é adiada para depois do carregamento do
    script, para que ``script.load()`` não fique bloqueado pelo tempo de
    inicialização do runtime Java no processo alvo. O script sinaliza a
    prontidão com a mensagem ``raspilot-java-ready``.

    Args:
        ready: Evento sinalizado pelo callback de mensagens quando a
            camada Java fica pronta.
        timeout: Tempo máximo de espera em segundos.

    Returns:
        True se a camada Java ficou pronta dentro do tempo limite.
    """
    return ready.wait(max(0.0, timeout))


def safe_unload(script: Optional[object], timeout: float = 2.0) -> None:
    """Descarrega um script Frida tolerando scripts destruídos/presos.

    Quando o processo alvo se encerra (reação típica de RASP), o Frida
    destrói o script e um ``script.unload()`` subsequente levanta
    ``frida.InvalidOperationError``. Esse é um caso **esperado** no
    RASPilot, então não deve virar ruído/traceback no log.

    Se a sessão estiver degradada (ex: ``script.load`` com timeout), o
    unload pode bloquear; por isso ele roda em thread com timeout.

    Args:
        script: Objeto ``frida.core.Script`` (ou ``None``).
        timeout: Tempo máximo em segundos.

    Returns:
        None.
    """
    if script is None:
        return
    done = threading.Event()

    def _unload() -> None:
        try:
            script.unload()
        except Exception as exc:  # noqa: BLE001 - script destruído é esperado
            logger.debug("Unload ignorado (%s: %s)", type(exc).__name__, exc)
        finally:
            done.set()

    threading.Thread(target=_unload, name="raspilot-unload", daemon=True).start()
    if not done.wait(timeout):
        logger.warning("Unload não concluiu em %.1fs; seguindo", timeout)


def safe_detach(session: Optional[object], timeout: float = 2.0) -> None:
    """Faz detach com timeout para não travar em sessão degradada.

    Args:
        session: Sessão Frida (ou ``None``).
        timeout: Tempo máximo em segundos.

    Returns:
        None.
    """
    if session is None:
        return
    done = threading.Event()

    def _detach() -> None:
        try:
            session.detach()
        except Exception:
            logger.debug("Detach falhou", exc_info=True)
        finally:
            done.set()

    threading.Thread(target=_detach, name="raspilot-detach", daemon=True).start()
    if not done.wait(timeout):
        logger.warning("Detach não concluiu em %.1fs; seguindo", timeout)


def enumerate_module_names(session: object, timeout: float = 3.0) -> List[str]:
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
    names: List[str] = []
    errors: List[BaseException] = []

    def _call() -> None:
        try:
            names.extend(script.exports.listmodules() or [])
        except BaseException as exc:  # noqa: BLE001 - repassado
            errors.append(exc)

    worker = threading.Thread(target=_call, name="raspilot-rpc", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        safe_unload(script)
        raise TimeoutError(f"enumerate_modules excedeu {timeout}s")
    safe_unload(script)
    if errors:
        raise errors[0]
    return list(names)
