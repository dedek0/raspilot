"""RASPilot — taxonomia central de artefatos e atribuição de origem.

A mesma string pode significar coisas diferentes dependendo do vetor:
``frida`` é anti-Frida, ``xposed`` é anti-hook, ``ptrace`` é anti-debug.
Este módulo evita que listas de palavras-chave cresçam em paralelo nos
scripts e nos checks, e classifica a origem de um achado (app, SDK de
RASP, SDK terceiro, framework ou biblioteca).

A atribuição é heurística: o objetivo é evitar que uma classe empacotada
de biblioteca seja tratada como proteção do app, não provar autoria.
"""

from __future__ import annotations

from typing import Iterable, Optional

from rasp_vendors import all_tokens

FRIDA_MARKERS = (
    "frida",
    "libfrida",
    "gum-js-loop",
    "gum-js",
    "linjector",
    "frida-agent",
    "frida-server",
    "frida-gadget",
    "re.frida.server",
    "/frida/runtime",
)

HOOK_MARKERS = (
    "xposed",
    "xposedbridge",
    "lsposed",
    "lspd",
    "edxposed",
    "substrate",
    "sandhook",
    "yahfa",
    "lsplant",
    "whale",
    "dobby",
    "riru",
    "zygisk",
    "andhook",
    "shadowhook",
    "bytehook",
    "xhook",
)

DEBUG_MARKERS = (
    "ptrace",
    "tracerpid",
    "isdebuggerconnected",
    "waitfordebugger",
)

ROOT_MARKERS = (
    "rootbeer",
    "magisk",
    "superuser",
    "busybox",
    "safetynet",
    "play integrity",
    "test-keys",
    "isdevicerooted",
    "isrooted",
)

EMULATOR_MARKERS = (
    "ro.kernel.qemu",
    "goldfish",
    "ranchu",
    "sdk_gphone",
    "vbox86",
    "genymotion",
    "bluestacks",
    "qemu_pipe",
)

PINNING_MARKERS = (
    "certificatepinner",
    "trustkit",
    "pinningtrustmanager",
    "networksecurityconfig",
    "publickeypinner",
    "ssl_ctx_set_custom_verify",
    "boringssl",
)

FRAMEWORK_PREFIXES = (
    "de.robv.android.xposed",
    "org.lsposed",
    "com.saurik.substrate",
    "com.elderdrivers",
)

THIRD_PARTY_PREFIXES = (
    "com.appsflyer",
    "com.google.android.gms",
    "com.google.firebase",
    "com.google.android.libraries",
    "com.google.android.play",
    "io.sentry",
    "expo",
    "com.learnium",
    "com.zoop",
    "com.facebook.react",
    "com.rnfetchblob",
    "androidx",
    "com.squareup",
    "org.jetbrains",
    "org.jose4j",
    "org.koin",
    "org.brotli",
)

LIBRARY_PREFIXES = (
    "okhttp3",
    "kotlin",
    "kotlinx",
    "androidx",
    "com.google.protobuf",
    "org.brotli",
    "org.jetbrains",
    "org.conscrypt",
    "com.android.org.conscrypt",
)


def normalize_class(name: str) -> str:
    """Converte um descritor Dalvik em nome pontilhado."""
    text = (name or "").strip()
    if text.startswith("L"):
        text = text[1:]
    if text.endswith(";"):
        text = text[:-1]
    return text.replace("/", ".")


def token_match(text: str, term: str) -> bool:
    """Casa ``term`` como token isolado, não como substring."""
    if not text or not term:
        return False
    lowered = text.lower()
    needle = term.lower()
    start = 0
    while True:
        index = lowered.find(needle, start)
        if index < 0:
            return False
        before = lowered[index - 1] if index > 0 else ""
        after_index = index + len(needle)
        after = lowered[after_index] if after_index < len(lowered) else ""
        before_ok = not before or not (before.isalnum())
        after_ok = not after or not (after.isalnum())
        if before_ok and after_ok:
            return True
        start = index + 1


def classify_marker(text: str) -> Optional[str]:
    """Classifica um texto em um vetor de proteção.

    A ordem importa quando o app procura vários artefatos: um caminho
    ``/data/local/tmp/frida-server`` é Frida; ``XposedBridge`` é hook.
    """
    for category, markers in (
        ("hooking", HOOK_MARKERS),
        ("frida", FRIDA_MARKERS),
        ("debug", DEBUG_MARKERS),
        ("root", ROOT_MARKERS),
        ("emulator", EMULATOR_MARKERS),
        ("pinning", PINNING_MARKERS),
    ):
        for marker in markers:
            if token_match(text, marker):
                return category
    return None


def marker_owner(text: str, app_package: Optional[str] = None) -> str:
    """Classifica a origem de uma classe/achado.

    Returns:
        ``app``, ``rasp_sdk``, ``third_party_sdk``, ``framework``,
        ``library`` ou ``unknown``.
    """
    normalized = normalize_class(text)
    lowered = normalized.lower()
    package = (app_package or "").strip().lower()

    if package and (lowered == package or lowered.startswith(package + ".")):
        return "app"
    if any(lowered.startswith(prefix) for prefix in FRAMEWORK_PREFIXES):
        return "framework"
    if any(lowered.startswith(prefix) for prefix in LIBRARY_PREFIXES):
        return "library"
    if any(lowered.startswith(prefix) for prefix in THIRD_PARTY_PREFIXES):
        return "third_party_sdk"
    for token in all_tokens():
        if "." in token and token.lower() in lowered:
            return "rasp_sdk"
    return "unknown"


def is_app_evidence(owner: str) -> bool:
    """Indica se a origem pode representar código do app/RASP.

    ``unknown`` cobre código ofuscado, que não deve ser descartado sem
    evidência em contrário.
    """
    return owner in ("app", "rasp_sdk", "unknown")


def owner_counts(owners: Iterable[str]) -> dict:
    """Conta origens em um dicionário estável."""
    counts: dict = {}
    for owner in owners or []:
        key = owner or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "DEBUG_MARKERS",
    "EMULATOR_MARKERS",
    "FRIDA_MARKERS",
    "HOOK_MARKERS",
    "PINNING_MARKERS",
    "ROOT_MARKERS",
    "classify_marker",
    "is_app_evidence",
    "marker_owner",
    "normalize_class",
    "owner_counts",
    "token_match",
]
