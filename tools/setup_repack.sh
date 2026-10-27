#!/usr/bin/env bash
# Prepara o host para o teste de repack e para o payload Frida Gadget.
#
# Uso:
#   ./tools/setup_repack.sh [--abi ABI] [--frida-version V] [--force]
#                           [--no-gadget] [--check]
#
# O script não instala pacotes do sistema. Ele valida as ferramentas,
# cria os diretórios de artefatos/chaves e baixa o Frida Gadget da ABI
# escolhida para ~/.raspilot/gadgets/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android}}"
GADGET_DIR="$HOME/.raspilot/gadgets"
ABI=""
FRIDA_VERSION=""
FORCE=0
NO_GADGET=0
CHECK_ONLY=0

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --abi) ABI="$2"; shift 2 ;;
        --frida-version) FRIDA_VERSION="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --no-gadget) NO_GADGET=1; shift ;;
        --check) CHECK_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "argumento desconhecido: $1" >&2; exit 2 ;;
    esac
done

fail=0
note() { printf '  %s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; }
missing() { printf '  ✗ %s\n' "$*"; fail=1; }

echo "RASPilot — preparação do repack"
echo
echo "Ferramentas do host:"

if command -v adb >/dev/null 2>&1; then
    ok "adb: $(command -v adb)"
else
    missing "adb não encontrado (instale Android Platform Tools e coloque no PATH)"
fi

if command -v apktool >/dev/null 2>&1; then
    ok "apktool: $(command -v apktool)"
else
    missing "apktool 3.x não encontrado (necessário para dex/resource/manifest/gadget)"
    note "Baixe em https://apktool.org/ e coloque o wrapper no PATH."
fi

BUILD_TOOLS="$(ls -d "$SDK_ROOT"/build-tools/* 2>/dev/null | sort -V | tail -1 || true)"
if [[ -n "$BUILD_TOOLS" && -x "$BUILD_TOOLS/zipalign" && -x "$BUILD_TOOLS/apksigner" ]]; then
    ok "build-tools: $BUILD_TOOLS"
else
    missing "zipalign/apksigner não encontrados em $SDK_ROOT/build-tools"
    note "Rode ./instrumentation/setup_toolchain.sh ou defina ANDROID_SDK_ROOT."
fi

KEYTOOL=""
for candidate in "${JAVA_HOME:-}/bin/keytool" "$SDK_ROOT/jdk/bin/keytool"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
        KEYTOOL="$candidate"
        break
    fi
done
if [[ -z "$KEYTOOL" ]] && command -v keytool >/dev/null 2>&1; then
    KEYTOOL="$(command -v keytool)"
fi
if [[ -n "$KEYTOOL" ]]; then
    ok "keytool: $KEYTOOL"
else
    missing "keytool não encontrado (JDK 17+)"
    note "Rode ./instrumentation/setup_toolchain.sh ou defina JAVA_HOME."
fi

if command -v curl >/dev/null 2>&1; then
    ok "curl: $(command -v curl)"
else
    missing "curl não encontrado (necessário para baixar o Frida Gadget)"
fi
if command -v xz >/dev/null 2>&1; then
    ok "xz: $(command -v xz)"
else
    missing "xz não encontrado (necessário para descomprimir o Gadget)"
fi

PYTHON="${PYTHON:-python3}"
if "$PYTHON" -c 'import frida' >/dev/null 2>&1; then
    DETECTED_FRIDA="$("$PYTHON" -c 'import frida; print(frida.__version__)')"
    ok "frida (Python): $DETECTED_FRIDA"
    if [[ -z "$FRIDA_VERSION" ]]; then
        FRIDA_VERSION="$DETECTED_FRIDA"
    fi
else
    missing "pacote frida não encontrado no Python atual"
    note "Ative o venv e rode: pip install -r requirements.txt"
fi

if [[ -z "$ABI" ]] && command -v adb >/dev/null 2>&1; then
    ABI="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r' || true)"
fi
if [[ -z "$ABI" ]]; then
    ABI="arm64-v8a"
    warn "device não conectado; usando ABI padrão $ABI (use --abi para outro)"
fi

case "$ABI" in
    arm64-v8a) ARCH="arm64" ;;
    armeabi-v7a) ARCH="arm" ;;
    x86_64) ARCH="x86_64" ;;
    x86) ARCH="x86" ;;
    *)
        missing "ABI sem Frida Gadget suportado: $ABI"
        ARCH=""
        ;;
esac

echo
echo "Diretórios:"
mkdir -p "$GADGET_DIR" "$HOME/.raspilot/keys" "$HOME/.raspilot/repack"
ok "gadgets: $GADGET_DIR"
ok "chaves: $HOME/.raspilot/keys"
ok "artefatos: $HOME/.raspilot/repack"
ok "artefatos do projeto: $ROOT/reports/repack"

if [[ -n "$ARCH" && "$NO_GADGET" -eq 0 ]]; then
    echo
    echo "Frida Gadget:"
    TARGET="$GADGET_DIR/libgadget-$ARCH.so"
    if [[ -f "$TARGET" && "$FORCE" -eq 0 ]]; then
        ok "já existe: $TARGET"
    elif [[ "$CHECK_ONLY" -eq 1 ]]; then
        warn "ausente: $TARGET (execute sem --check para baixar)"
    elif [[ -z "$FRIDA_VERSION" ]]; then
        missing "versão do Frida desconhecida; use --frida-version"
    else
        URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-android-${ARCH}.so.xz"
        TMP="$TARGET.xz"
        echo "  baixando $URL"
        if curl -L --fail --retry 2 -o "$TMP" "$URL"; then
            xz -dc "$TMP" > "$TARGET"
            rm -f "$TMP"
            ok "Gadget: $TARGET"
        else
            rm -f "$TMP"
            missing "falha ao baixar o Gadget"
        fi
    fi
fi

echo
echo "Variáveis úteis:"
note "ANDROID_SDK_ROOT=${SDK_ROOT}"
note "RASPILOT_APKTOOL_XMX=${RASPILOT_APKTOOL_XMX:-6G}"
note "Frida Gadget padrão: $GADGET_DIR"

echo
if [[ "$fail" -ne 0 ]]; then
    echo "Há requisitos pendentes. Corrija os itens acima antes do repack." >&2
    exit 1
fi
echo "Ambiente pronto para o repack."
