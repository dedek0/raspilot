"""RASPilot — Catálogo de SDKs de RASP conhecidos.

Dados de domínio: como cada SDK se manifesta (tag de log, classe,
pacote, biblioteca nativa) e por quais métodos ele comunica a decisão
de "o app foi violado".

O catálogo é usado em três lugares:

- detecção estática no APK (assinaturas de classe/pacote/lib)
- correlação de logcat (tag do SDK)
- hook de veredito: quando o SDK do app é identificado, os métodos que
  comunicam a violação são neutralizados

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

from typing import Dict, List, NamedTuple, Tuple


class Vendor(NamedTuple):
    """Descrição de um SDK de RASP.

    Attributes:
        name: Nome do produto.
        tokens: Marcadores que identificam o SDK (tag de log, nome de
            classe, pacote ou biblioteca nativa).
        verdict_methods: Nomes de métodos que o SDK usa para comunicar
            que o app foi violado.
    """

    name: str
    tokens: Tuple[str, ...]
    verdict_methods: Tuple[str, ...]


# Métodos que, em qualquer SDK, comunicam uma decisão de violação.
# O nome é o sinal mais estável entre implementações: o SDK varia o
# pacote e as classes, mas continua descrevendo a mesma ação.
GENERIC_VERDICT_METHODS: Tuple[str, ...] = (
    "onThreatDetected",
    "onSecurityThreat",
    "onThreatFound",
    "onDetection",
    "reportThreat",
    "detectThreat",
    "handleThreat",
    "onTamperDetected",
    "onRootDetected",
    "onHookDetected",
    "onDebugDetected",
    "onEmulatorDetected",
    "onIntegrityFailure",
    "onSecurityViolation",
    "onAppCompromised",
    "terminateApp",
    "killApp",
    "blockApp",
    "blockApplication",
    "reportAttack",
    "notifyThreat",
)

# Métodos que devolvem um veredito booleano: false significa "nada
# errado", que é o valor esperado pelo app quando o bypass atua.
BOOLEAN_VERDICT_METHODS: Tuple[str, ...] = (
    "isCompromised",
    "isTampered",
    "isRooted",
    "isHooked",
    "isDebugged",
    "isEmulated",
    "isUnderAttack",
    "hasBeenTampered",
)

VENDORS: Tuple[Vendor, ...] = (
    Vendor(
        name="promon",
        tokens=("com.promon", "promon", "Promon"),
        verdict_methods=("onThreatDetected", "reportThreat", "terminateApp"),
    ),
    Vendor(
        name="appsuit",
        tokens=("com.appsuit", "appsuit", "AppSuit"),
        verdict_methods=("onThreatDetected", "onDetection", "terminateApp"),
    ),
    Vendor(
        name="guardsquare",
        tokens=(
            "com.guardsquare", "approtect", "Approtect", "TrustChecker",
        ),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
    Vendor(
        name="talsec",
        tokens=("com.talsec", "talsec", "Talsec"),
        verdict_methods=("onThreatDetected", "reportThreat", "killApp"),
    ),
    Vendor(
        name="inka",
        tokens=("com.inka", "inka", "Entitas"),
        verdict_methods=("onThreatDetected", "reportThreat", "terminateApp"),
    ),
    Vendor(
        name="nexign",
        tokens=("com.nexign", "nexign", "Nexign"),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
    Vendor(
        name="netskope",
        tokens=("com.netskope", "netskope", "Netskope"),
        verdict_methods=("onThreatDetected", "reportThreat", "blockApp"),
    ),
    Vendor(
        name="dexprotector",
        tokens=("com.dexprotector", "dexprotector", "DexProtector"),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
    Vendor(
        name="bluepoint",
        tokens=("com.bluepoint", "bluepoint", "BluePoint"),
        verdict_methods=("onThreatDetected", "reportThreat", "terminateApp"),
    ),
    Vendor(
        name="avast",
        tokens=("com.avast", "apk.shield", "Avast"),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
    Vendor(
        name="ijiami",
        tokens=("com.ijiami", "ijiami", "Ijiami"),
        verdict_methods=("onThreatDetected", "reportThreat", "terminateApp"),
    ),
    Vendor(
        name="bangcle",
        tokens=("com.bangcle", "bangcle", "SecShell", "secshell"),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
    Vendor(
        name="tesseract",
        tokens=("com.tesseract", "tesseract", "TESSERACT"),
        verdict_methods=("onThreatDetected", "reportThreat", "terminateApp"),
    ),
    Vendor(
        name="appsealing",
        tokens=("com.appsealing", "appsealing", "AppSealing"),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
    Vendor(
        name="quarks",
        tokens=("com.quarks", "quarks", "Quarks"),
        verdict_methods=("onThreatDetected", "reportThreat", "terminateApp"),
    ),
    Vendor(
        name="nagain",
        tokens=("com.nagain", "nagain", "Nagain"),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
    Vendor(
        name="luciq",
        tokens=("luciq", "LUCIQ"),
        verdict_methods=("onThreatDetected", "onSecurityViolation", "terminateApp"),
    ),
)

# Índice reverso: token -> vendors que o reconhecem.
TOKEN_INDEX: Dict[str, List[Vendor]] = {}
for _vendor in VENDORS:
    for _token in _vendor.tokens:
        TOKEN_INDEX.setdefault(_token.lower(), []).append(_vendor)


def vendors_for_token(token: str) -> List[Vendor]:
    """Retorna os vendors associados a um token.

    Args:
        token: Marcador procurado (tag de log, nome de classe etc.).

    Returns:
        Lista de vendors que reconhecem o token.
    """
    return TOKEN_INDEX.get((token or "").lower(), [])


def all_tokens() -> Tuple[str, ...]:
    """Retorna todos os tokens do catálogo.

    Returns:
        Tupla com os tokens, sem repetição.
    """
    seen = set()
    out: List[str] = []
    for vendor in VENDORS:
        for token in vendor.tokens:
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(token)
    return tuple(out)


def verdict_method_names() -> Tuple[str, ...]:
    """Retorna os nomes de método que comunicam violação.

    Inclui os padrões genéricos e os específicos de cada vendor.

    Returns:
        Tupla com os nomes de método.
    """
    seen = set()
    out: List[str] = []
    for name in GENERIC_VERDICT_METHODS:
        if name not in seen:
            seen.add(name)
            out.append(name)
    for vendor in VENDORS:
        for name in vendor.verdict_methods:
            if name not in seen:
                seen.add(name)
                out.append(name)
    return tuple(out)
