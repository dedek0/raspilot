"""RASPilot — construção do perfil estático do APK.

O perfil responde a três perguntas por vetor de proteção:

1. o APK contém artefatos/classes/strings associados ao vetor?
2. em quais classes/métodos esses artefatos aparecem? (ASC/uplink)
3. os hooks do bypass atual cobrem as técnicas encontradas?

Ele **não** responde se a checagem foi executada. A execução continua
sendo medida pela camada dinâmica; o perfil serve para evitar vereditos
como "bypass venceu" quando o app não tem proteção nenhuma ou quando a
técnica usada está fora do alcance dos hooks.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from checks.apk_utils import pull_apk, scan_apk
from checks.static.engine import AscEngine, apk_digest, asc_available
from checks.taxonomy import is_app_evidence, marker_owner, owner_counts
from checks.static.queries import (
    ASC_QUERIES,
    BYPASS_HOOKS,
    FRIDA_SIGNATURES,
    NATIVE_HINTS,
    PROFILE_VERSION,
    ROOT_SIGNATURES,
    TAMPER_SIGNATURES,
    VECTOR_LABELS,
    VECTORS,
)
from rasp_vendors import VENDORS

logger = logging.getLogger("raspilot.static.profile")

_CONFIDENCE_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}

# Marcadores de frameworks/SDKs que não estão no catálogo de vendors.
_KNOWN_MARKERS: Tuple[Tuple[str, str, str], ...] = (
    ("hooking", "XposedBridge", "Xposed"),
    ("hooking", "de.robv.android.xposed", "Xposed"),
    ("hooking", "LSPosed", "LSPosed"),
    ("hooking", "LSPlant", "LSPlant"),
    ("hooking", "Substrate", "Cydia Substrate"),
    ("hooking", "SandHook", "SandHook"),
    ("hooking", "YAHFA", "YAHFA"),
    ("hooking", "libdobby", "Dobby"),
    ("hooking", "shadowhook", "ShadowHook"),
    ("hooking", "libbytehook", "ByteHook"),
    ("root", "RootBeer", "RootBeer"),
    ("root", "SafetyNet", "SafetyNet"),
    ("root", "Play Integrity", "Play Integrity"),
    ("pinning", "CertificatePinner", "OkHttp CertificatePinner"),
    ("pinning", "TrustKit", "TrustKit"),
    ("tamper", "IntegrityToken", "Play Integrity"),
    ("tamper", "SafetyNet", "SafetyNet"),
    ("pinning", "PinningTrustManager", "PinningTrustManager"),
    ("emulator", "DexGuardEmulatorDetected", "DexGuard"),
    ("emulator", "isRunningOnEmulator", "detecção de emulador"),
    ("emulator", "goldfish", "goldfish"),
    ("emulator", "ranchu", "ranchu"),
    ("frida", "frida", "Frida"),
)

_PROFILE_MEMO: Dict[tuple, dict] = {}


def _now_iso() -> str:
    """Timestamp UTC em ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


def _confidence_max(values: Iterable[str]) -> str:
    """Retorna a maior confiança de uma coleção."""
    best = "none"
    for value in values:
        if _CONFIDENCE_ORDER.get(value, 0) > _CONFIDENCE_ORDER.get(best, 0):
            best = value
    return best


def _finding(
    vector: str,
    source: str,
    kind: str,
    value: str,
    evidence: str,
    confidence: str = "medium",
    class_name: str = "",
    method: str = "",
    label: str = "",
    owner: str = "unknown",
) -> dict:
    """Monta um achado estático normalizado."""
    return {
        "vector": vector,
        "source": source,
        "kind": kind,
        "value": value,
        "evidence": evidence,
        "confidence": confidence,
        "class": class_name,
        "method": method,
        "label": label or value,
        "owner": owner,
    }


def _dedupe(findings: List[dict]) -> List[dict]:
    """Remove achados duplicados preservando a ordem e a maior confiança."""
    seen: Dict[tuple, int] = {}
    out: List[dict] = []
    for item in findings:
        key = (
            item.get("vector"),
            item.get("source"),
            item.get("kind"),
            item.get("value"),
            item.get("class"),
            item.get("method"),
        )
        if key in seen:
            index = seen[key]
            if _CONFIDENCE_ORDER.get(item.get("confidence"), 0) > _CONFIDENCE_ORDER.get(
                out[index].get("confidence"), 0
            ):
                out[index] = item
            continue
        seen[key] = len(out)
        out.append(item)
    return out


def _builtin_signatures() -> List[tuple]:
    """Combina as assinaturas de bytes de todos os checks em uma lista.

    A varredura é feita uma única vez por APK; cada assinatura leva o
    nome do vetor a que pertence.

    Returns:
        Lista ``(vetor, [(needle, descrição), ...])``.
    """
    signatures: List[tuple] = [
        ("frida", FRIDA_SIGNATURES),
        ("root", ROOT_SIGNATURES),
        ("tamper", TAMPER_SIGNATURES),
    ]
    try:
        from checks.anti_hooking import STATIC_SIGNATURES as hook_signatures
        from checks.anti_emulator import STATIC_SIGNATURES as emulator_signatures
        from checks.ssl_pinning import STATIC_SIGNATURES as ssl_signatures
    except Exception:  # pragma: no cover - proteção contra import circular
        logger.debug("Não foi possível importar todas as assinaturas", exc_info=True)
        return signatures

    for signature_type, needles in hook_signatures:
        # O grupo "frida" do anti-hooking descreve um artefato de
        # instrumentação, não uma checagem anti-hook. Ele é coberto pelo
        # vetor frida; misturar os dois contamina o veredito.
        if signature_type == "frida":
            continue
        signatures.append(
            (
                "hooking",
                [
                    (needle, f"{signature_type}: {description}")
                    for needle, description in needles
                ],
            )
        )
    for signature_type, needles in emulator_signatures:
        signatures.append(
            (
                "emulator",
                [
                    (needle, f"{signature_type}: {description}")
                    for needle, description in needles
                ],
            )
        )
    for signature_type, needles in ssl_signatures:
        signatures.append(
            (
                "pinning",
                [
                    (needle, f"{signature_type}: {description}")
                    for needle, description in needles
                ],
            )
        )
    # O bloco <pin-set> é o sinal forte de pinning no network security
    # config; o atributo networkSecurityConfig sozinho só indica que o
    # app usa a configuração (pode não ter pin).
    signatures.append(
        (
            "pinning",
            [
                (b"pin-set", "elemento <pin-set> em network security config"),
                (b"certificate-pinning", "certificate-pinning em configuração de rede"),
            ],
        )
    )
    return signatures


def _builtin_confidence(vector: str, description: str) -> str:
    """Atribui confiança a uma assinatura de bytes.

    A mesma string pode significar coisas diferentes: `Flutter` prova que
    o app usa Flutter, não que ele faz pinning; `Runtime.exec` é usado por
    qualquer app. A confiança alta fica reservada a artefatos específicos
    do vetor.
    """
    text = (description or "").lower()
    if vector == "frida":
        if any(token in text for token in ("re.frida.server", "gum-js-loop", "libfrida", "linjector", "frida-gadget")):
            return "high"
        return "low"
    if vector == "hooking":
        if any(token in text for token in ("xposed", "lsposed", "lsplant", "sandhook", "yahfa", "dobby", "bytehook", "shadowhook", "substrate", "edxposed")):
            return "high"
        if "frida" in text:
            return "low"
        return "low"
    if vector == "root":
        if any(token in text for token in ("rootbeer", "magisk", "superuser", "system/xbin/su", "system/bin/su", "test-keys", "isdevicerooted", "isrooted", "safetynet", "play integrity", "busybox")):
            return "high"
        return "low"
    if vector == "emulator":
        if any(token in text for token in ("dexguard", "emulatordetected", "isrunningonemulator", "emulatorfound", "ro.kernel.qemu", "goldfish", "ranchu", "sdk_gphone", "vbox86", "qemu_pipe")):
            return "high"
        return "low"
    if vector == "tamper":
        if any(token in text for token in ("get_signatures", "get_signing_certificates", "checksignatures", "signinginfo", "play integrity", "safetynet", "integritytoken")):
            return "high"
        if any(token in text for token in ("messagedigest", "getpackagecodepath", "getpackageresourcepath", "crc32", "checksum")):
            return "medium"
        return "low"
    if vector == "pinning":
        if any(token in text for token in ("trustkit", "pinningtrustmanager", "ssl_ctx_set_custom_verify", "publickeypinner", "pin-set", "certificate-pinning")):
            return "high"
        if any(token in text for token in ("networksecuritytrustmanager", "roottrustmanager")):
            return "medium"
        # okhttp3/CertificatePinner, Flutter e Conscrypt podem estar
        # empacotados sem que o app faça pinning.
        return "low"
    return "medium"


def _scan_builtin(apks: List[str]) -> List[dict]:
    """Varre os APKs por assinaturas de bytes (sempre disponível)."""
    signatures = _builtin_signatures()
    findings: List[dict] = []
    for apk in apks:
        try:
            found = scan_apk(apk, signatures)
        except (zipfile.BadZipFile, OSError) as exc:
            logger.warning("APK inválido para varredura estática: %s", exc)
            continue
        for vector, descriptions in found.items():
            for description in descriptions:
                findings.append(
                    _finding(
                        vector=vector,
                        source="apk_bytes",
                        kind="signature",
                        value=description,
                        evidence=f"[APK] {description}",
                        confidence=_builtin_confidence(vector, description),
                        label=description,
                        owner="apk",
                    )
                )
    return findings


def _parse_manifest(xml_text: str) -> dict:
    """Extrai dados de segurança do manifesto decodificado."""
    manifest: dict = {
        "available": bool(xml_text),
        "package": None,
        "debuggable": False,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
        "extract_native_libs": None,
        "network_security_config": None,
        "meta_data": [],
        "permissions": [],
    }
    if not xml_text:
        return manifest

    match = re.search(r'<manifest[^>]*\bpackage="([^"]+)"', xml_text)
    if match:
        manifest["package"] = match.group(1)

    def _attr(name: str) -> Optional[str]:
        match = re.search(r'android:%s="([^"]+)"' % re.escape(name), xml_text)
        return match.group(1) if match else None

    manifest["debuggable"] = (_attr("debuggable") or "").lower() == "true"
    manifest["allow_backup"] = _attr("allowBackup")
    manifest["uses_cleartext_traffic"] = _attr("usesCleartextTraffic")
    manifest["extract_native_libs"] = _attr("extractNativeLibs")
    manifest["network_security_config"] = _attr("networkSecurityConfig")
    manifest["meta_data"] = re.findall(
        r'<meta-data[^>]*android:name="([^"]+)"', xml_text
    )[:50]
    manifest["permissions"] = re.findall(
        r'<uses-permission[^>]*android:name="([^"]+)"', xml_text
    )[:80]
    return manifest


def _classes_from_apks(engine: AscEngine, apks: List[str], errors: List[str]) -> List[str]:
    """Lista classes de todos os APKs, deduplicando descritores."""
    classes: List[str] = []
    seen = set()
    for apk in apks:
        result = engine.list_classes(apk)
        if not result.get("ok"):
            errors.append(f"listclass {os.path.basename(apk)}: {result.get('stderr')}")
            continue
        for name in engine.parse_classes(result):
            if name not in seen:
                seen.add(name)
                classes.append(name)
    return classes


def _matches_frida_class(lowered: str) -> bool:
    """Evita marcar o pacote de um app cujo nome contém "frida".

    ``com.exemplo.fridaplayer`` não é uma classe de detecção; ``FridaDetector``
    e ``AntiFrida`` são. O teste olha segmentos da classe, não substring.
    """
    if re.search(r"(^|[.$])(anti)?frida([.$]|$)", lowered):
        return True
    return bool(
        re.search(
            r"(^|[.$])(anti)?frida(detect|detection|check|scan|hook|trace|guard|shield)",
            lowered,
        )
    )


def _class_findings(classes: List[str], package_name: str = "") -> List[dict]:
    """Transforma classes conhecidas em achados por vetor."""
    findings: List[dict] = []
    for name in classes:
        normalized = name.replace("/", ".").strip("L;")
        lowered = normalized.lower()
        for vector, marker, label in _KNOWN_MARKERS:
            if marker.lower() == "frida" and not _matches_frida_class(lowered):
                continue
            if marker.lower() in lowered:
                confidence = "low" if marker.lower() == "frida" else "medium"
                owner = marker_owner(name, package_name)
                if vector == "pinning" and owner in ("library", "third_party_sdk"):
                    # A biblioteca pode estar empacotada sem que o app a use
                    # para fixar certificados.
                    confidence = "low"
                    label = f"{label} (classe de biblioteca)"
                findings.append(
                    _finding(
                        vector=vector,
                        source="asc",
                        kind="class",
                        value=name,
                        evidence=f"classe {normalized} contém '{marker}'",
                        confidence=confidence,
                        class_name=name,
                        label=label,
                        owner=owner,
                    )
                )
    return findings


def _rasp_sdks(classes: List[str]) -> List[dict]:
    """Mapeia classes encontradas para o catálogo de SDKs de RASP."""
    results: Dict[str, dict] = {}
    for vendor in VENDORS:
        for token in vendor.tokens:
            if "." not in token:
                continue
            needle = token.lower()
            matches = [
                name
                for name in classes
                if needle in name.replace("/", ".").strip("L;").lower()
            ]
            if not matches:
                continue
            entry = results.setdefault(
                vendor.name,
                {"name": vendor.name, "tokens": [], "classes": []},
            )
            if token not in entry["tokens"]:
                entry["tokens"].append(token)
            for name in matches[:5]:
                if name not in entry["classes"]:
                    entry["classes"].append(name)
    return sorted(results.values(), key=lambda item: item["name"])


def _has_dex(apk: str) -> bool:
    """Informa se o APK contém pelo menos um ``classes*.dex``."""
    try:
        with zipfile.ZipFile(apk) as archive:
            return any(name.endswith(".dex") for name in archive.namelist())
    except (OSError, zipfile.BadZipFile):
        return False


def _has_manifest(apk: str) -> bool:
    """Informa se o APK contém ``AndroidManifest.xml``."""
    try:
        with zipfile.ZipFile(apk) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def _asc_profile(
    engine: AscEngine,
    apks: List[str],
    errors: List[str],
    package_name: str = "",
) -> dict:
    """Executa as consultas de alto sinal no ASC."""
    dex_apks = [apk for apk in apks if _has_dex(apk)] or apks
    manifest_apk = next((apk for apk in apks if _has_manifest(apk)), apks[0])
    findings: List[dict] = []
    manifest: dict = {"available": False}
    classes: List[str] = []

    eng_manifest = engine.get_manifest(manifest_apk)
    if eng_manifest.get("ok"):
        manifest = _parse_manifest(eng_manifest.get("stdout") or "")
    else:
        errors.append(f"getmanifest: {eng_manifest.get('stderr')}")

    classes = _classes_from_apks(engine, dex_apks, errors)
    findings.extend(_class_findings(classes, package_name))

    for query in ASC_QUERIES:
        for apk in dex_apks:
            result = engine.find_refs_parsed(
                apk,
                query["kind"],
                value=query.get("value"),
                class_name=query.get("class_name"),
                fuzzy_class=bool(query.get("fuzzy_class")),
            )
            if not result.get("ok"):
                errors.append(
                    "findrefs %s %s (%s): %s"
                    % (
                        query["kind"],
                        query.get("value") or query.get("class_name"),
                        os.path.basename(apk),
                        result.get("error"),
                    )
                )
                continue
            for hit in result.get("hits") or []:
                member = hit.get("method") or hit.get("class")
                hit_class = hit.get("class") or ""
                if query["vector"] == "pinning" and query["kind"] == "type":
                    # Referências dentro da própria biblioteca (okhttp,
                    # TrustKit) não provam que o app use pinning; o que
                    # importa é uma referência a partir de código do app.
                    if hit_class.startswith(
                        ("Lokhttp3/", "Lcom/datatheorem/android/trustkit/")
                    ):
                        continue
                confidence = query.get("confidence") or (
                    "high" if hit.get("method") else "medium"
                )
                label = query.get("label") or ""
                if query["vector"] == "frida":
                    context = " ".join(
                        [
                            hit.get("matched") or "",
                            hit.get("method") or "",
                            hit_class,
                        ]
                    ).lower()
                    usage_tokens = (
                        "frida-server",
                        "frida-inject",
                        "download",
                        "install",
                        "launch",
                        "start ",
                        "stop ",
                        "activate",
                        "deactivate",
                        "ui/",
                        "screen",
                        "about",
                    )
                    detection_tokens = (
                        "detection",
                        "detected",
                        "anti-frida",
                        "tamper",
                        "security",
                        "protect",
                        "found",
                        "threat",
                        "hook",
                        "trace",
                        "debug",
                        "monitor",
                    )
                    if any(token in context for token in usage_tokens):
                        confidence = "low"
                        label = "referência de uso do Frida (não é detecção)"
                    elif any(token in context for token in detection_tokens):
                        confidence = "high"
                        label = "detecção de Frida"
                    else:
                        confidence = "medium"
                        label = "referência a Frida (pode ser detecção)"
                if query["vector"] == "pinning" and query["kind"] == "impl":
                    cls = hit_class.lower()
                    if any(
                        token in cls
                        for token in (
                            "trustall",
                            "allowall",
                            "noop",
                            "insecure",
                            "permissive",
                            "bypass",
                        )
                    ):
                        confidence = "low"
                        label = "TrustManager permissivo (não é pinning)"
                    elif any(
                        token in cls
                        for token in (
                            "pinning",
                            "trustkit",
                            "certificate",
                            "publickey",
                            "sslpin",
                        )
                    ):
                        confidence = "high"
                        label = "TrustManager com indício de pinning"
                    else:
                        # Implementação de X509TrustManager é comum em
                        # apps que só querem um TrustManager próprio.
                        confidence = "low"
                        label = "TrustManager customizado (não prova pinning)"
                findings.append(
                    _finding(
                        vector=query["vector"],
                        source="asc",
                        kind="%s_ref" % query["kind"],
                        value=query.get("value") or query.get("class_name") or "",
                        evidence=(
                            f"{hit.get('class') or member} referencia "
                            f"{query.get('display') or query.get('value') or query.get('class_name')}"
                        ),
                        confidence=confidence,
                        class_name=hit_class,
                        method=hit.get("method") or "",
                        label=label,
                        owner=marker_owner(hit_class, package_name),
                    )
                )

    return {
        "manifest": manifest,
        "classes_count": len(classes),
        "classes": classes,
        "rasp_sdks": _rasp_sdks(classes),
        "findings": findings,
    }


def _summarize(findings: List[dict], vectors: List[str]) -> Dict[str, dict]:
    """Agrupa achados por vetor e calcula presença/confiança."""
    summary: Dict[str, dict] = {}
    for vector in vectors:
        items = [item for item in findings if item.get("vector") == vector]
        items.sort(
            key=lambda item: (
                _CONFIDENCE_ORDER.get(item.get("confidence"), 0),
                item.get("kind") != "signature",
            ),
            reverse=True,
        )
        counts = {"high": 0, "medium": 0, "low": 0}
        for item in items:
            confidence = item.get("confidence") or "low"
            if confidence in counts:
                counts[confidence] += 1
        sources = sorted({item.get("source") for item in items if item.get("source")})
        owners = owner_counts(item.get("owner") for item in items)
        app_evidence = any(
            item.get("source") == "asc"
            and item.get("confidence") in ("medium", "high")
            and is_app_evidence(item.get("owner"))
            for item in items
        )
        techniques = []
        for item in items:
            label = item.get("label") or item.get("value")
            if label and label not in techniques:
                techniques.append(label)
        summary[vector] = {
            "present": bool(items),
            "confidence": _confidence_max(item.get("confidence") for item in items),
            "counts": counts,
            "sources": sources,
            "owners": owners,
            "app_evidence": app_evidence,
            "techniques": techniques[:12],
            "findings": items[:60],
            "total": len(items),
        }
    return summary


def _coverage(vectors: Dict[str, dict], engine: str) -> Dict[str, dict]:
    """Cruza as técnicas estáticas com os hooks do bypass."""
    coverage: Dict[str, dict] = {}
    for vector, summary in vectors.items():
        blob = " ".join(
            "{} {} {}".format(
                item.get("value", ""),
                item.get("label", ""),
                item.get("evidence", ""),
            ).lower()
            for item in summary.get("findings", [])
        )
        gaps = []
        for hint in NATIVE_HINTS.get(vector, ()):
            if hint in blob:
                gaps.append(
                    "possível checagem nativa/fora da camada Java "
                    f"(indício: {hint})"
                )
        if engine != "asc":
            gaps.append(
                "ASC indisponível: sem manifesto decodificado, classes ou xrefs"
            )
        coverage[vector] = {
            "bypass_hooks": list(BYPASS_HOOKS.get(vector, [])),
            "possible_gaps": gaps,
            "static_present": bool(summary.get("present")),
            "app_evidence": bool(summary.get("app_evidence")),
        }
    return coverage


def _profile_cache_path(digest: str, engine: str, version: Optional[str], vectors: List[str]) -> str:
    """Caminho do cache em disco para um perfil."""
    root = os.environ.get("RASPILOT_STATIC_CACHE_DIR")
    if not root:
        base = os.environ.get("RASPILOT_CACHE_DIR")
        root = os.path.join(base, "static") if base else os.path.join(
            os.path.expanduser("~"), ".raspilot", "cache", "static"
        )
    key = "-".join(
        [
            "profile",
            digest[:32],
            engine or "none",
            (version or "unknown").replace("/", "_"),
            str(PROFILE_VERSION),
            ",".join(sorted(vectors)),
        ]
    )
    return os.path.join(root, key + ".json")


def _unavailable(engine: str, reason: str, package_name: str = "") -> dict:
    """Perfil mínimo para quando a análise não pôde rodar."""
    return {
        "available": False,
        "engine": engine,
        "version": None,
        "package": package_name or None,
        "vectors": {},
        "coverage": {},
        "manifest": {"available": False},
        "rasp_sdks": [],
        "classes_count": 0,
        "summary": {
            "available": False,
            "engine": engine,
            "vectors_present": [],
            "vectors": {},
            "error": reason,
        },
        "limitations": [
            "análise estática não executada; vereditos dinâmicos não foram ajustados",
        ],
        "errors": [reason] if reason else [],
        "timestamp": _now_iso(),
        "cached": False,
    }


def build_static_profile(
    dm: object,
    package_name: str,
    apk_path: Optional[str] = None,
    engine: str = "auto",
    timeout: float = 60.0,
    cache: bool = True,
    vectors: Optional[Iterable[str]] = None,
) -> dict:
    """Constrói o perfil estático de um app.

    Args:
        dm: ``DeviceManager`` (ou fake compatível) para ``adb pull``.
        package_name: Package name do app.
        apk_path: APK local opcional (pula o pull).
        engine: ``auto`` (ASC se disponível), ``asc`` (exige ASC),
            ``builtin`` (só varredura de bytes) ou ``off``.
        timeout: Timeout por comando do ASC.
        cache: Habilita cache em memória/disco.
        vectors: Vetores a incluir; padrão todos.

    Returns:
        Perfil serializável. Nunca lança por falha do ASC: erros viram
        ``available=False`` ou entram em ``errors``.
    """
    requested = [vector for vector in (vectors or VECTORS) if vector in VECTORS]
    if not requested:
        requested = list(VECTORS)
    cache = bool(cache) and os.environ.get("RASPILOT_STATIC_CACHE", "1") != "0"

    mode = (engine or "auto").strip().lower()
    if mode == "off":
        return _unavailable("off", "análise estática desativada", package_name)

    asc_ok = asc_available()
    if mode == "asc" and not asc_ok:
        return _unavailable(
            "asc",
            "droidasc não instalado ou Python < 3.10",
            package_name,
        )
    effective_engine = "asc" if (mode in ("auto", "asc") and asc_ok) else "builtin"
    version = AscEngine().version if asc_ok else None

    with tempfile.TemporaryDirectory(prefix="raspilot_static_") as tmp:
        apks = [apk_path] if apk_path else pull_apk(dm, package_name, tmp)
        apks = [apk for apk in apks if apk and os.path.isfile(apk)]
        if not apks:
            return _unavailable(
                effective_engine,
                f"Não foi possível obter o APK de {package_name}",
                package_name,
            )

        digest = apk_digest(apks)
        memo_key = (digest, effective_engine, version, tuple(sorted(requested)))
        if cache and memo_key in _PROFILE_MEMO:
            cached = json.loads(json.dumps(_PROFILE_MEMO[memo_key]))
            cached["cached"] = True
            return cached

        cache_path = _profile_cache_path(digest, effective_engine, version, requested)
        if cache:
            try:
                with open(cache_path, "r", encoding="utf-8") as handle:
                    cached = json.load(handle)
                if isinstance(cached, dict) and cached.get("available") is not None:
                    cached["cached"] = True
                    _PROFILE_MEMO[memo_key] = cached
                    return cached
            except (OSError, ValueError):
                pass

        errors: List[str] = []
        findings = _scan_builtin(apks)
        asc_data = {
            "manifest": {"available": False},
            "classes_count": 0,
            "classes": [],
            "rasp_sdks": [],
            "findings": [],
        }
        if effective_engine == "asc":
            asc_engine = AscEngine(timeout=timeout, cache=cache)
            try:
                asc_data = _asc_profile(
                    asc_engine, apks, errors, package_name=package_name
                )
            except Exception as exc:  # o ASC não pode derrubar o pipeline
                logger.warning("Perfil ASC falhou", exc_info=True)
                errors.append(f"ASC: {exc}")
        asc_usable = bool(
            (asc_data.get("manifest") or {}).get("available")
            or asc_data.get("classes_count")
            or asc_data.get("findings")
        )
        if effective_engine == "asc" and not asc_usable:
            effective_engine = "builtin"
            errors.append("ASC não retornou dados; usando a varredura de bytes")
        findings.extend(asc_data.get("findings") or [])
        findings = _dedupe(findings)

        vectors_summary = _summarize(findings, requested)
        coverage = _coverage(vectors_summary, effective_engine)
        present = [vector for vector in requested if vectors_summary[vector]["present"]]
        limitations = [
            "a análise estática vê o APK instalado; código nativo, DEX "
            "empacotado/criptografado e DEX carregado em runtime não são "
            "cobertos",
            "presença de uma checagem no APK não prova que ela foi "
            "executada na janela de observação",
        ]
        if effective_engine != "asc":
            limitations.append(
                "ASC indisponível: sem manifesto decodificado, lista de "
                "classes ou referências de método"
            )

        profile = {
            "available": True,
            "engine": effective_engine,
            "version": version,
            "package": package_name,
            "vectors": vectors_summary,
            "coverage": coverage,
            "manifest": asc_data.get("manifest") or {"available": False},
            "rasp_sdks": asc_data.get("rasp_sdks") or [],
            "classes_count": asc_data.get("classes_count") or 0,
            "summary": {
                "available": True,
                "engine": effective_engine,
                "vectors_present": present,
                "vectors": {
                    vector: {
                        "present": vectors_summary[vector]["present"],
                        "confidence": vectors_summary[vector]["confidence"],
                        "total": vectors_summary[vector]["total"],
                        "owners": vectors_summary[vector].get("owners") or {},
                        "app_evidence": bool(vectors_summary[vector].get("app_evidence")),
                    }
                    for vector in requested
                },
                "rasp_sdks": [item["name"] for item in asc_data.get("rasp_sdks") or []],
            },
            "limitations": limitations,
            "errors": errors,
            "timestamp": _now_iso(),
            "cached": False,
        }

        if cache and not errors:
            _PROFILE_MEMO[memo_key] = json.loads(json.dumps(profile))
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as handle:
                    json.dump(profile, handle, ensure_ascii=False)
            except OSError:
                logger.debug("Não foi possível gravar o perfil estático", exc_info=True)
        return profile


def vector_view(profile: Optional[dict], name: str) -> Optional[dict]:
    """Retorna a visão resumida de um vetor do perfil.

    Args:
        profile: Perfil retornado por :func:`build_static_profile`.
        name: ``frida``, ``hooking``, ``root``, ``emulator``,
            ``pinning`` ou ``tamper``.

    Returns:
        Dict com ``present``, ``confidence``, ``findings`` e metadados do
        motor, ou None quando não há perfil disponível.
    """
    if not isinstance(profile, dict) or not profile.get("available"):
        return None
    vector = (profile.get("vectors") or {}).get(name)
    if not isinstance(vector, dict):
        return None
    view = dict(vector)
    view["static_detected"] = bool(vector.get("present"))
    view["effective"] = bool(
        vector.get("present")
        and vector.get("confidence") in ("medium", "high")
    )
    view["engine"] = profile.get("engine")
    view["version"] = profile.get("version")
    view["available"] = True
    view["coverage"] = (profile.get("coverage") or {}).get(name)
    view["owners"] = dict(vector.get("owners") or {})
    view["app_evidence"] = bool(vector.get("app_evidence"))
    view["findings"] = list(vector.get("findings") or [])[:20]
    return view


def merge_signature_detection(detection: Optional[dict], view: Optional[dict]) -> dict:
    """Combina a detecção por assinaturas com a visão ASC.

    Args:
        detection: Resultado de ``detect_static``/``detect_pinning``.
        view: Visão do vetor no perfil estático.

    Returns:
        Cópia enriquecida de ``detection``; nunca None.
    """
    merged = dict(detection or {})
    merged.setdefault("static_detected", False)
    merged.setdefault("evidence", [])
    merged.setdefault("types", [])
    if not view:
        merged.setdefault("asc_available", False)
        return merged

    merged["asc"] = view
    merged["asc_available"] = True
    if view.get("effective"):
        merged["static_detected"] = True
        merged["confidence"] = view.get("confidence")
        kinds = [
            item.get("kind")
            for item in view.get("findings") or []
            if item.get("kind")
        ]
        for kind in kinds:
            if kind not in merged["types"]:
                merged["types"].append(kind)
        for item in view.get("findings") or []:
            evidence = item.get("evidence")
            if evidence and evidence not in merged["evidence"]:
                merged["evidence"].append(evidence)
        if not merged.get("primary"):
            merged["primary"] = (view.get("findings") or [{}])[0].get("kind") or "asc"
        details = merged.get("details") or ""
        merged["details"] = (
            (details + "; " if details else "")
            + f"ASC: {view.get('confidence') or 'n/a'} ({view.get('total') or 0} achado(s))"
        )
    elif view.get("present"):
        # Só indícios genéricos (ex.: getStackTrace): não afirmam que o
        # app tem proteção, mas ficam no relatório como contexto.
        merged["asc_weak_only"] = True
        merged["asc_evidence"] = [
            item.get("evidence")
            for item in view.get("findings") or []
            if item.get("evidence")
        ]
    return merged


def _infer_pinning_type(view: dict) -> str:
    """Deduz o tipo de pinning a partir dos achados do ASC."""
    blob = " ".join(
        "{} {}".format(item.get("value", ""), item.get("evidence", ""))
        for item in view.get("findings") or []
    ).lower()
    if "okhttp" in blob or "certificatepinner" in blob:
        return "okhttp"
    if "trustkit" in blob:
        return "trustkit"
    if "networksecurityconfig" in blob or "network_security_config" in blob:
        return "network_security_config"
    if "x509trustmanager" in blob or "trustmanager" in blob:
        return "trust_manager"
    if any(token in blob for token in ("ssl_ctx", "boring", "conscrypt", "publickeypinner")):
        return "native"
    return "asc"


def merge_pinning_detection(detection: Optional[dict], view: Optional[dict]) -> dict:
    """Combina a detecção de SSL pinning com a visão ASC."""
    merged = dict(detection or {})
    merged.setdefault("pinning_detected", False)
    merged.setdefault("type", "none")
    merged.setdefault("evidence", [])
    if not view:
        merged.setdefault("asc_available", False)
        return merged

    merged["asc"] = view
    merged["asc_available"] = True
    if view.get("effective"):
        merged["pinning_detected"] = True
        merged.pop("error", None)
        if merged.get("type") in (None, "", "none"):
            merged["type"] = _infer_pinning_type(view)
        for item in view.get("findings") or []:
            evidence = item.get("evidence")
            if evidence and evidence not in merged["evidence"]:
                merged["evidence"].append(evidence)
        details = merged.get("details") or ""
        merged["details"] = (
            (details + "; " if details else "")
            + f"ASC: {view.get('confidence') or 'n/a'} ({view.get('total') or 0} achado(s))"
        )
    elif view.get("present"):
        # Flutter/Conscrypt/NSC sem <pin-set> provam que o app carrega a
        # tecnologia, não que ele fixa certificados.
        merged["asc_weak_only"] = True
        merged["asc_weak_evidence"] = [
            item.get("evidence")
            for item in view.get("findings") or []
            if item.get("evidence")
        ]
    return merged


__all__ = [
    "build_static_profile",
    "merge_pinning_detection",
    "merge_signature_detection",
    "vector_view",
]
