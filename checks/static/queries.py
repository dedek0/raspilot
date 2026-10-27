"""RASPilot — consultas e assinaturas da análise estática.

As assinaturas de bytes são a camada sempre disponível (varredura do
ZIP). As consultas ao ASC são poucas e de alto sinal: cada uma custa
uma varredura dos DEX do APK, então o conjunto é deliberadamente
curado em vez de tentar reproduzir toda a superfície de APIs do
Android.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

PROFILE_VERSION = 4

VECTORS: Tuple[str, ...] = (
    "frida",
    "hooking",
    "root",
    "emulator",
    "pinning",
    "tamper",
)

VECTOR_LABELS: Dict[str, str] = {
    "frida": "Anti-Frida",
    "hooking": "Anti-Hooking",
    "root": "Anti-Root (detecção do app)",
    "emulator": "Anti-Emulador",
    "pinning": "SSL Pinning",
    "tamper": "Anti-Tampering",
}

# Assinaturas de bytes adicionais para vetores que ainda não tinham
# varredura estática no APK (anti-Frida e anti-Root).
FRIDA_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"frida", "string 'frida' no APK"),
    (b"re.frida.server", "path do frida-server embutido"),
    (b"gum-js-loop", "thread GumJS"),
    (b"libfrida", "referência a libfrida"),
    (b"linjector", "linjector do Frida"),
    (b"frida-gadget", "Frida Gadget"),
]

ROOT_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"magisk", "string Magisk"),
    (b"Superuser", "string Superuser"),
    (b"busybox", "string busybox"),
    (b"RootBeer", "SDK RootBeer"),
    (b"isDeviceRooted", "método isDeviceRooted"),
    (b"isRooted", "método isRooted"),
    (b"/system/xbin/su", "caminho /system/xbin/su"),
    (b"/system/bin/su", "caminho /system/bin/su"),
    (b"ro.debuggable", "propriedade ro.debuggable"),
    (b"ro.secure", "propriedade ro.secure"),
    (b"SafetyNet", "SafetyNet"),
    (b"Play Integrity", "Play Integrity"),
    (b"test-keys", "build test-keys"),
]

# Assinaturas de integridade/tampering: APIs de assinatura, hash de
# pacote, Play Integrity/SafetyNet e verificações de código.
TAMPER_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"GET_SIGNATURES", "PackageManager.GET_SIGNATURES"),
    (b"GET_SIGNING_CERTIFICATES", "PackageManager.GET_SIGNING_CERTIFICATES"),
    (b"PackageInfo;->signatures", "campo PackageInfo.signatures"),
    (b"checkSignatures", "PackageManager.checkSignatures"),
    (b"SigningInfo", "classe SigningInfo"),
    (b"MessageDigest", "java.security.MessageDigest"),
    (b"getPackageCodePath", "getPackageCodePath"),
    (b"getPackageResourcePath", "getPackageResourcePath"),
    (b"CRC32", "CRC32"),
    (b"Play Integrity", "Play Integrity"),
    (b"SafetyNet", "SafetyNet"),
    (b"IntegrityToken", "IntegrityToken"),
    (b"tamper", "string tamper"),
    (b"checksum", "string checksum"),
]

# Consultas de alto sinal executadas no ASC. Cada item é um comando
# `findrefs`; o campo ``label`` explica o achado no relatório.
ASC_QUERIES: List[dict] = [
    {
        "vector": "frida",
        "kind": "string",
        "value": r"\bfrida\b",
        "display": "frida (palavra isolada)",
        "label": "referência a Frida",
    },
    {
        "vector": "frida",
        "kind": "string",
        "value": "gum-js-loop",
        "label": "referência à thread GumJS",
    },
    {
        "vector": "frida",
        "kind": "string",
        "value": "libfrida",
        "label": "referência à libfrida",
    },
    {
        "vector": "frida",
        "kind": "string",
        "value": "linjector",
        "label": "referência ao linjector do Frida",
    },
    {
        "vector": "hooking",
        "kind": "type",
        "value": "de.robv.android.xposed.XposedBridge",
        "label": "referência ao XposedBridge",
    },
    {
        "vector": "hooking",
        "kind": "string",
        "value": "org.lsposed",
        "label": "referência ao LSPosed",
    },
    {
        "vector": "hooking",
        "kind": "method",
        "value": "getStackTrace",
        "label": "inspeção de stack trace",
        "confidence": "low",
    },
    {
        "vector": "root",
        "kind": "string",
        "value": r"(?i)\bmagisk\b",
        "display": "magisk",
        "label": "referência ao Magisk",
    },
    {
        "vector": "root",
        "kind": "method",
        "value": "exec",
        "class_name": "java.lang.Runtime",
        "label": "execução de comando (Runtime.exec)",
        "confidence": "low",
    },
    {
        "vector": "root",
        "kind": "method",
        "value": "exists",
        "class_name": "java.io.File",
        "label": "checagem de caminho (File.exists)",
        "confidence": "low",
    },
    {
        "vector": "emulator",
        "kind": "string",
        "value": r"ro\.kernel\.qemu",
        "display": "ro.kernel.qemu",
        "label": "propriedade ro.kernel.qemu",
    },
    {
        "vector": "emulator",
        "kind": "string",
        "value": r"(?i)\bgoldfish\b",
        "display": "goldfish",
        "label": "string goldfish",
    },
    {
        "vector": "emulator",
        "kind": "method",
        "value": "get",
        "class_name": "android.os.SystemProperties",
        "label": "leitura de SystemProperties",
        "confidence": "low",
    },
    {
        "vector": "tamper",
        "kind": "method",
        "value": "checkSignatures",
        "class_name": "android.content.pm.PackageManager",
        "label": "checagem de assinatura de pacote",
    },
    {
        "vector": "tamper",
        "kind": "method",
        "value": "getPackageInfo",
        "class_name": "android.content.pm.PackageManager",
        "label": "leitura de PackageInfo/assinaturas",
    },
    {
        "vector": "tamper",
        "kind": "type",
        "value": "android.content.pm.SigningInfo",
        "label": "uso de SigningInfo",
    },
    {
        "vector": "tamper",
        "kind": "type",
        "value": "java.security.MessageDigest",
        "label": "hash de integridade",
    },
    {
        "vector": "tamper",
        "kind": "string",
        "value": r"(?i)play\s+integrity",
        "display": "Play Integrity",
        "label": "Play Integrity",
    },
    {
        "vector": "tamper",
        "kind": "string",
        "value": r"(?i)\bsafetynet\b",
        "display": "SafetyNet",
        "label": "SafetyNet",
    },
    {
        "vector": "tamper",
        "kind": "string",
        "value": r"(?i)\btamper\b",
        "display": "tamper",
        "label": "string tamper",
        "confidence": "low",
    },
    {
        "vector": "pinning",
        "kind": "impl",
        "value": "javax.net.ssl.X509TrustManager",
        "label": "implementação de X509TrustManager",
    },
    {
        "vector": "pinning",
        "kind": "type",
        "value": "okhttp3.CertificatePinner",
        "label": "uso de okhttp CertificatePinner",
    },
    {
        "vector": "pinning",
        "kind": "string",
        "value": "networkSecurityConfig",
        "label": "network security config",
    },
]

# Hooks que os scripts de bypass do RASPilot instalam hoje. A lista é
# usada para mostrar cobertura esperada — não é prova de que o hook
# pegou a chamada (isso continua sendo medido em runtime).
BYPASS_HOOKS: Dict[str, List[str]] = {
    "frida": [
        "strstr/strcasestr (libc)",
        "connect para portas Frida",
        "File.exists/File.list",
        "Runtime.exec/ProcessBuilder.start",
        "Thread.getName/pthread_setname_np",
        "raise/abort/exit (autoencerramento)",
    ],
    "hooking": [
        "Class.forName/ClassLoader.loadClass",
        "File.exists/list/listFiles",
        "Runtime.exec/ProcessBuilder.start",
        "Throwable.getStackTrace/Thread.getStackTrace",
        "strstr/strcasestr (libc)",
    ],
    "root": [
        "RootBeer",
        "File.exists/canRead/canWrite",
        "Runtime.exec",
        "SystemProperties.get",
    ],
    "emulator": [
        "Build (campos estáticos)",
        "SystemProperties.get",
        "File.exists",
        "TelephonyManager",
        "Settings.Secure",
        "propriedades/arquivos/strstr nativos",
    ],
    "tamper": [
        "PackageManager.getPackageInfo/signatures",
        "PackageManager.checkSignatures",
        "MessageDigest/SHA-256",
        "Play Integrity/SafetyNet",
        "Zip/CRC/checksum",
    ],
    "pinning": [
        "X509TrustManager",
        "Conscrypt TrustManagerImpl",
        "HostnameVerifier",
        "HttpsURLConnection",
        "Apache AbstractVerifier",
    ],
}

# Termos que sugerem uma checagem fora do alcance dos hooks Java. Não
# são conclusão: o relatório grava como "possível lacuna".
NATIVE_HINTS: Dict[str, Tuple[str, ...]] = {
    "frida": ("/proc/self/maps", "ptrace", "libfrida", "linjector", "gadget"),
    "root": ("os.access", "libroot", "native", "ptrace"),
    "emulator": ("strstr", "native", "ro.kernel.qemu"),
    "pinning": ("ssl_ctx", "boringssl", "libconscrypt_jni", "publickeypinner"),
    "hooking": ("strstr", "native", "ptrace"),
    "tamper": ("signature", "integrity", "tamper", "checksum"),
}

__all__ = [
    "ASC_QUERIES",
    "BYPASS_HOOKS",
    "FRIDA_SIGNATURES",
    "NATIVE_HINTS",
    "PROFILE_VERSION",
    "ROOT_SIGNATURES",
    "TAMPER_SIGNATURES",
    "VECTOR_LABELS",
    "VECTORS",
]
