"""RASPilot — adaptador para o Droid ASC.

O ``AscEngine`` executa o CLI do ``droidasc`` em um subprocesso isolado,
com timeout e cache em disco. O subprocesso é preferido à importação
direta dos módulos internos do ASC por dois motivos:

- o ASC ainda está na série 0.1.x e a API interna pode mudar;
- uma falha do decompilador não derruba o processo do RASPilot.

A única dependência obrigatória é o próprio ``droidasc`` (extra
opcional). Quando ele não está instalado, o perfil estático usa
:func:`checks.apk_utils.scan_apk` como fallback.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
from importlib import metadata, util
from typing import Any, Dict, List, Optional

logger = logging.getLogger("raspilot.static.engine")

# Versão usada como referência de compatibilidade. A instalação não é
# forçada: qualquer 0.1.x é aceita, mas a versão encontrada entra na
# chave do cache e no relatório.
ASC_MIN_PYTHON = (3, 10)
CACHE_SCHEMA = "asc-cache-v1"


def asc_available() -> bool:
    """Informa se o Droid ASC pode ser usado neste interpretador.

    Returns:
        True quando o pacote ``droidasc`` está instalado e o Python é
        >= 3.10 (requisito do ASC).
    """
    if sys.version_info < ASC_MIN_PYTHON:
        return False
    try:
        return util.find_spec("droidasc") is not None
    except (ImportError, ValueError):
        return False


def asc_version() -> Optional[str]:
    """Retorna a versão instalada do ``droidasc``, se houver."""
    try:
        return metadata.version("droidasc")
    except Exception:  # pragma: no cover - depende do ambiente
        return None


def _cache_root() -> str:
    """Diretório de cache dos resultados do ASC.

    Respeita ``RASPILOT_STATIC_CACHE_DIR`` e ``RASPILOT_CACHE_DIR`` para
    que o operador possa isolar o cache em testes/CI.
    """
    explicit = os.environ.get("RASPILOT_STATIC_CACHE_DIR")
    if explicit:
        return explicit
    base = os.environ.get("RASPILOT_CACHE_DIR")
    if base:
        return os.path.join(base, "static")
    return os.path.join(os.path.expanduser("~"), ".raspilot", "cache", "static")


def _cache_enabled() -> bool:
    """Cache ligado por padrão; ``RASPILOT_STATIC_CACHE=0`` desliga."""
    return os.environ.get("RASPILOT_STATIC_CACHE", "1") != "0"


def apk_digest(paths: List[str]) -> str:
    """Calcula um SHA-256 estável para um conjunto de APKs.

    O hash cobre o conteúdo e o nome de cada APK (o nome diferencia
    ``base.apk`` de ``split_config.arm64_v8a.apk``). O caminho absoluto
    não entra, para que o cache sobreviva a mudanças de diretório.
    """
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(os.path.basename(path).encode("utf-8", errors="replace"))
        digest.update(b"\0")
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def parse_findrefs(stdout: str, limit: int = 500) -> List[dict]:
    """Converte a saída de ``droidasc findrefs`` em registros.

    O formato é ``<dex> | <classe>-><método> | matched=(...)`` para
    referências de código e ``<dex> | <classe> extends <alvo>`` para
    ``extends``/``impl``.

    Args:
        stdout: Saída textual do comando.
        limit: Número máximo de linhas interpretadas.

    Returns:
        Lista de dicts com ``dex``, ``class``, ``method``, ``matched``
        e ``raw``.
    """
    hits: List[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or " | " not in line:
            continue
        parts = [part.strip() for part in line.split(" | ")]
        if len(parts) < 2:
            continue
        dex, member = parts[0], parts[1]
        matched = " | ".join(parts[2:]) if len(parts) > 2 else member
        cls = member
        method = ""
        if " extends " in member or " implements " in member:
            cls = member.split(" ", 1)[0]
        elif "->" in member:
            cls, method = member.split("->", 1)
        hits.append(
            {
                "dex": dex,
                "class": cls,
                "method": method,
                "matched": matched,
                "raw": line,
            }
        )
        if len(hits) >= limit:
            break
    return hits


class AscEngine:
    """Executa consultas ao Droid ASC com cache e timeout.

    Args:
        timeout: Timeout padrão por comando, em segundos.
        cache: Se False, ignora o cache em disco.
        python: Interpretador alternativo (por padrão ``sys.executable``).
        max_workers: Repassado ao ASC via ``--threads`` quando aplicável.
    """

    def __init__(
        self,
        timeout: float = 60.0,
        cache: bool = True,
        python: Optional[str] = None,
        max_workers: int = 8,
    ) -> None:
        self.timeout = max(1.0, float(timeout))
        self.cache = bool(cache) and _cache_enabled()
        self.python = python or sys.executable
        self.max_workers = max(1, int(max_workers))
        self.cache_dir = _cache_root()
        self._memo: Dict[tuple, dict] = {}
        self._digests: Dict[str, str] = {}

    @property
    def version(self) -> Optional[str]:
        """Versão instalada do ASC."""
        return asc_version()

    def _digest(self, apk: str) -> str:
        """Hash do APK, memoizado por caminho dentro desta instância."""
        if apk not in self._digests:
            self._digests[apk] = apk_digest([apk])
        return self._digests[apk]

    def _cache_path(self, apk: str, args: List[str]) -> str:
        """Caminho do arquivo de cache para uma consulta."""
        key = hashlib.sha256(
            json.dumps(
                [
                    CACHE_SCHEMA,
                    self.version,
                    self._digest(apk),
                    args,
                ],
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return os.path.join(self.cache_dir, key + ".json")

    def _execute(self, args: List[str], timeout: float) -> dict:
        """Executa ``python -m droidasc ...`` e normaliza o retorno."""
        command = [self.python, "-m", "droidasc"] + args
        env = os.environ.copy()
        env.setdefault("PYTHONIOENCODING", "utf-8")
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                errors="replace",
                env=env,
            )
        except subprocess.TimeoutExpired:
            logger.warning("ASC excedeu o timeout de %.1fs: %s", timeout, args[0])
            return {
                "ok": False,
                "rc": None,
                "stdout": "",
                "stderr": f"timeout após {timeout:.1f}s",
                "cmd": command,
                "cached": False,
            }
        except (OSError, ValueError) as exc:
            logger.warning("Falha ao executar o ASC: %s", exc)
            return {
                "ok": False,
                "rc": None,
                "stdout": "",
                "stderr": str(exc),
                "cmd": command,
                "cached": False,
            }
        return {
            "ok": proc.returncode == 0,
            "rc": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "cmd": command,
            "cached": False,
        }

    def command(
        self, apk: str, args: List[str], timeout: Optional[float] = None
    ) -> dict:
        """Executa (ou lê do cache) um comando do ASC para um APK.

        Args:
            apk: Caminho local do APK.
            args: Argumentos do CLI, sem o executável.
            timeout: Timeout específico; usa o padrão da instância se None.

        Returns:
            Dict com ``ok``, ``rc``, ``stdout``, ``stderr``, ``cmd`` e
            ``cached``.
        """
        memo_key = (apk, tuple(args))
        if memo_key in self._memo:
            return dict(self._memo[memo_key], cached=True)

        effective_timeout = self.timeout if timeout is None else max(1.0, float(timeout))
        cache_path = ""
        if self.cache:
            try:
                cache_path = self._cache_path(apk, args)
                with open(cache_path, "r", encoding="utf-8") as handle:
                    cached = json.load(handle)
                if isinstance(cached, dict) and cached.get("ok") is not None:
                    cached["cached"] = True
                    self._memo[memo_key] = cached
                    return dict(cached, cached=True)
            except (OSError, ValueError):
                pass

        result = self._execute(args, effective_timeout)
        self._memo[memo_key] = result
        if self.cache and result.get("ok") and cache_path:
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as handle:
                    json.dump(result, handle, ensure_ascii=False)
            except OSError:
                logger.debug("Não foi possível gravar o cache do ASC", exc_info=True)
        return result

    def get_manifest(self, apk: str, timeout: Optional[float] = None) -> dict:
        """Decodifica o ``AndroidManifest.xml`` do APK."""
        return self.command(apk, ["getmanifest", apk], timeout=timeout)

    def list_classes(
        self,
        apk: str,
        prefix: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> dict:
        """Lista classes do APK; ``prefix`` filtra por pacote/classe."""
        args = ["listclass", apk]
        if prefix:
            args += ["--prefix", prefix]
        return self.command(apk, args, timeout=timeout)

    def find_refs(
        self,
        apk: str,
        kind: str,
        value: Optional[str] = None,
        class_name: Optional[str] = None,
        fuzzy_class: bool = False,
        timeout: Optional[float] = None,
    ) -> dict:
        """Procura referências de string/tipo/método/campo em todos os DEX.

        Args:
            apk: Caminho local do APK.
            kind: ``string``, ``type``, ``method``, ``field``,
                ``extends`` ou ``impl``.
            value: Valor consultado. Para ``method``/``field`` pode ser
                vazio quando ``class_name`` é informado.
            class_name: Classe (Dalvik ou pontilhada) para
                ``method``/``field``.
            fuzzy_class: Trata ``class_name`` como prefixo/fuzzy.
            timeout: Timeout específico.

        Returns:
            Dict normalizado do comando.
        """
        kind = (kind or "").strip().lower()
        args = ["findrefs", apk, kind]
        if kind in ("string", "type", "extends", "impl"):
            if not value:
                return {
                    "ok": False,
                    "rc": None,
                    "stdout": "",
                    "stderr": f"consulta {kind} exige um valor",
                    "cmd": [],
                    "cached": False,
                }
            args.append(str(value))
        else:
            if value:
                args.append(str(value))
            if class_name:
                args += ["--class", str(class_name)]
            if fuzzy_class:
                args.append("--fuzzy-class")
        return self.command(apk, args, timeout=timeout)

    def find_refs_parsed(
        self,
        apk: str,
        kind: str,
        value: Optional[str] = None,
        class_name: Optional[str] = None,
        fuzzy_class: bool = False,
        timeout: Optional[float] = None,
    ) -> dict:
        """Executa :meth:`find_refs` e devolve os hits já parseados."""
        result = self.find_refs(
            apk,
            kind,
            value=value,
            class_name=class_name,
            fuzzy_class=fuzzy_class,
            timeout=timeout,
        )
        if not result.get("ok"):
            return {"ok": False, "hits": [], "error": result.get("stderr"), "raw": result}
        return {
            "ok": True,
            "hits": parse_findrefs(result.get("stdout") or ""),
            "error": None,
            "raw": result,
        }

    def parse_classes(self, result: dict) -> List[str]:
        """Extrai descritores de classe da saída de ``listclass``."""
        if not result.get("ok"):
            return []
        classes = []
        for line in (result.get("stdout") or "").splitlines():
            name = line.strip()
            if name.startswith("L") and name.endswith(";") and "/" in name:
                classes.append(name)
        return classes


__all__ = [
    "ASC_MIN_PYTHON",
    "AscEngine",
    "apk_digest",
    "asc_available",
    "asc_version",
    "parse_findrefs",
]
