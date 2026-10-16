"""RASPilot — Utilitários compartilhados de análise de APK.

Funções reutilizadas pelos checks que inspecionam o APK baixado do
dispositivo (SSL Pinning e Anti-Hooking): download via ``pm path`` +
``adb pull``, busca de assinaturas (ASCII e UTF-16LE) e varredura das
entradas relevantes (Manifest binário, DEX, libs nativas e assets).

Mantém os dois checks com exatamente o mesmo comportamento de scan,
sem duplicar a lógica de leitura/early-stop do zip.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
import zipfile
from typing import Dict, List, Tuple

logger = logging.getLogger("raspilot.checks.apk_utils")

# Forma das assinaturas: (tipo, [(needle_bytes, descrição), ...]).
# A ordem das needles define a prioridade de evidências dentro do tipo.
Signature = Tuple[str, List[Tuple[bytes, str]]]

# Teto de bytes lidos por entrada do APK (Manifest/DEX relevantes ficam
# bem abaixo disso; blobs maiores só desperdiçam memória do host).
BLOB_CAP = 8 * 1024 * 1024


def contains_bytes(blob: bytes, needle: bytes) -> bool:
    """Procura um needle (ASCII ou UTF-16LE) em um blob de bytes.

    O AndroidManifest.binário pode armazenar strings em UTF-16LE
    (API < 30) ou UTF-8 — por isso a dupla busca.

    Args:
        blob: Bytes a inspecionar.
        needle: Padrão ASCII a localizar.

    Returns:
        True se encontrado em qualquer codificação.
    """
    utf16 = needle.decode("ascii", errors="ignore").encode("utf-16le")
    if needle in blob:
        return True
    return bool(utf16) and utf16 in blob


def pull_apk(dm: object, package_name: str, dest_dir: str) -> List[str]:
    """Baixa o(s) APK(s) de um app para o host.

    Args:
        dm: Instância de ``DeviceManager`` (ou fake compatível).
        package_name: Package name do app alvo.
        dest_dir: Diretório local de destino.

    Returns:
        Lista de caminhos locais dos APKs baixados (vazia se falhar).
    """
    res = dm.run_shell(f"pm path {package_name}", timeout=15)
    if not res["ok"] or not res["stdout"]:
        logger.warning("pm path falhou para %s: %s", package_name, res["stderr"])
        return []

    local_paths: List[str] = []
    for line in res["stdout"].splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        remote = line[len("package:"):]
        local = os.path.join(
            dest_dir, os.path.basename(remote) or f"{package_name}.apk"
        )
        try:
            # APKs modernos podem ser grandes — timeout generoso.
            dm._run_adb(["pull", remote, local], timeout=300)
            if os.path.isfile(local):
                local_paths.append(local)
        except Exception:
            logger.warning("Falha ao baixar %s", remote, exc_info=True)
    return local_paths


def _is_scannable_entry(name: str) -> bool:
    """Define quais entradas do APK valem a pena ler.

    Args:
        name: Caminho da entrada dentro do zip.

    Returns:
        True para Manifest binário, DEX, libs nativas e assets/res XML.
    """
    return (
        name == "AndroidManifest.xml"
        or name.endswith(".dex")
        or name.startswith("lib/") and name.endswith(".so")
        or name.startswith("assets/flutter_assets")
        or name.startswith("res/xml/")
    )


def scan_apk(apk_path: str, signatures: List[Signature]) -> Dict[str, List[str]]:
    """Inspeciona um APK por assinaturas.

    Procura as assinaturas nas entradas relevantes (ver
    :func:`_is_scannable_entry`) e também nos nomes das entradas (ex:
    ``lib/arm64-v8a/libflutter.so``). O scan para cedo quando todas as
    assinaturas casam e processa um blob por vez (sem acumular centenas
    de MB do APK em memória).

    Args:
        apk_path: Caminho local do APK.
        signatures: Lista ``(tipo, [(needle, descrição), ...])``.

    Returns:
        Dict ``{tipo: [evidências]}`` apenas com tipos encontrados.

    Raises:
        zipfile.BadZipFile: se o arquivo não for um APK válido.
    """
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise zipfile.BadZipFile(f"{apk_path}: {exc}") from exc

    found: Dict[str, List[str]] = {}
    pending = [
        (sig_type, needle, description)
        for sig_type, needles in signatures
        for needle, description in needles
    ]
    interesting: List[str] = []

    def _scan_blob(blob: bytes) -> None:
        nonlocal pending
        remaining = []
        for sig_type, needle, description in pending:
            if contains_bytes(blob, needle):
                found.setdefault(sig_type, []).append(description)
            else:
                remaining.append((sig_type, needle, description))
        pending = remaining

    with zf:
        for info in zf.infolist():
            if not pending:
                break
            name = info.filename
            if _is_scannable_entry(name):
                interesting.append(name)
                try:
                    _scan_blob(zf.read(name)[:BLOB_CAP])
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    logger.debug("Não foi possível ler %s do APK", name)

        # Nomes das entradas também são evidência (ex: lib/libflutter.so).
        if pending and interesting:
            _scan_blob("\n".join(interesting).encode("utf-8", errors="ignore"))

    return found
