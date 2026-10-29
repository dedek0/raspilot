#!/usr/bin/env bash
# Compila o modulo de instrumentacao (APK) a partir dos fontes do projeto.
#
# O build usa apenas o SDK do Android (aapt2/d8/apksigner) e um JDK: nao
# ha dependencia de gradle nem de rede.
#
# Uso:
#   ./build.sh [--hook off|observe|bypass] [--emu off|observe|probe|mask]
#              [--proxy off|observe|probe|bypass]
#              [--target PACOTE] [--label NOME] [--out CAMINHO_APK]
#              [--hook-targets ARQUIVO_JSON]
#
# ARQUIVO_JSON (--hook-targets): lista de [classe_dalvik, metodo]
# descoberta pela analise estatica do APK alvo (ver checks/static).
# Especifica do app sob auditoria; nao compilada por padrao.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="${SCRIPT_DIR}/xposed"

HOOK_MODE="off"
ROOT_MODE="off"
TAMPER_MODE="off"
EMU_MODE="off"
PROXY_MODE="off"
TARGET=""
LABEL="build"
OUT="${SCRIPT_DIR}/build/raspilot-module.apk"
HOOK_TARGETS_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hook)   HOOK_MODE="$2"; shift 2 ;;
    --root)   ROOT_MODE="$2"; shift 2 ;;
    --tamper) TAMPER_MODE="$2"; shift 2 ;;
    --emu)    EMU_MODE="$2"; shift 2 ;;
    --proxy)  PROXY_MODE="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --label)  LABEL="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    --hook-targets) HOOK_TARGETS_FILE="$2"; shift 2 ;;
    *) echo "argumento desconhecido: $1" >&2; exit 2 ;;
  esac
done

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android}}"
if [[ ! -d "${SDK_ROOT}" ]]; then
  echo "SDK do Android nao encontrado em ${SDK_ROOT}" >&2
  exit 1
fi

BUILD_TOOLS="$(ls -d "${SDK_ROOT}"/build-tools/* 2>/dev/null | sort -V | tail -1)"
if [[ -z "${BUILD_TOOLS}" ]]; then
  echo "build-tools nao encontrado em ${SDK_ROOT}/build-tools" >&2
  exit 1
fi

ANDROID_JAR=""
for platform in android-34 android-33 android-32; do
  if [[ -f "${SDK_ROOT}/platforms/${platform}/android.jar" ]]; then
    ANDROID_JAR="${SDK_ROOT}/platforms/${platform}/android.jar"
    break
  fi
done
if [[ -z "${ANDROID_JAR}" ]]; then
  ANDROID_JAR="$(find "${SDK_ROOT}/platforms" -name android.jar 2>/dev/null | sort | tail -1)"
fi
if [[ -z "${ANDROID_JAR}" ]]; then
  echo "android.jar nao encontrado em ${SDK_ROOT}/platforms" >&2
  exit 1
fi

if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/javac" ]]; then
  JAVAC="${JAVA_HOME}/bin/javac"
  JAR="${JAVA_HOME}/bin/jar"
  KEYTOOL="${JAVA_HOME}/bin/keytool"
elif [[ -x "${SDK_ROOT}/jdk/bin/javac" ]]; then
  JAVAC="${SDK_ROOT}/jdk/bin/javac"
  JAR="${SDK_ROOT}/jdk/bin/jar"
  KEYTOOL="${SDK_ROOT}/jdk/bin/keytool"
else
  JAVAC="$(command -v javac || true)"
  JAR="$(command -v jar || true)"
  KEYTOOL="$(command -v keytool || true)"
fi
if [[ -z "${JAVAC}" || -z "${JAR}" ]]; then
  echo "javac nao encontrado: defina JAVA_HOME ou instale um JDK" >&2
  exit 1
fi

BUILD_DIR="${SCRIPT_DIR}/build"
WORK="${BUILD_DIR}/work"
rm -rf "${WORK}"
mkdir -p "${WORK}/gen/com/raspilot/module" "${WORK}/api" "${WORK}/classes" "${WORK}/dex"

# Configuracao compilada no APK (substituivel em tempo de execucao).
# Os valores sao escapados: um rotulo com aspas quebraria o fonte.
java_string() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\$/\\$/g'
}

# Alvos de hook direcionado (classe/metodo do app, descobertos pela
# analise estatica). Gerados como array Java estatico: a lista e
# especifica do app sob auditoria e nao cabe na propriedade de runtime.
HOOK_TARGETS_JAVA=""
if [[ -n "${HOOK_TARGETS_FILE}" && -f "${HOOK_TARGETS_FILE}" ]]; then
  HOOK_TARGETS_JAVA="$(python3 - "${HOOK_TARGETS_FILE}" <<'PY'
import json
import sys

def escape(value):
    # Escapa apenas o que uma string literal Java exige: barra invertida
    # e aspas duplas. "$" nao e caractere de escape em Java (classes
    # internas usam "$" no nome, ex: "Foo$Bar") e nomes de metodo podem
    # trazer "<init>"/"<clinit>" sem precisar de tratamento especial.
    return value.replace("\\", "\\\\").replace('"', '\\"')

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    pairs = json.load(handle)

rows = []
for cls, method in pairs:
    rows.append(
        '        { "%s", "%s" },' % (escape(str(cls)), escape(str(method)))
    )
print("\n".join(rows))
PY
)"
fi

cat > "${WORK}/gen/com/raspilot/module/RaspilotBaked.java" <<EOF
package com.raspilot.module;

/** Configuracao compilada no APK. Gerado durante o build. */
public final class RaspilotBaked {

    public static final String HOOK_MODE = "$(java_string "${HOOK_MODE}")";
    public static final String ROOT_MODE = "$(java_string "${ROOT_MODE}")";
    public static final String TAMPER_MODE = "$(java_string "${TAMPER_MODE}")";
    public static final String EMULATOR_MODE = "$(java_string "${EMU_MODE}")";
    public static final String PROXY_MODE = "$(java_string "${PROXY_MODE}")";
    public static final String TARGET_PACKAGE = "$(java_string "${TARGET}")";
    public static final String LABEL = "$(java_string "${LABEL}")";

    /**
     * Alvos de hook direcionado: {classe_dalvik, metodo} achados pela
     * analise estatica do APK do app sob auditoria. Generico por
     * definicao — preenchido em tempo de build a partir do app atual,
     * nunca com nomes fixos de um app especifico.
     */
    public static final String[][] HOOK_TARGETS = {
${HOOK_TARGETS_JAVA}
    };

    private RaspilotBaked() {
    }
}
EOF

# 1) Stubs da API de hooking (somente tempo de compilacao).
find "${MODULE_DIR}/api" -name '*.java' > "${WORK}/api-sources.txt"
"${JAVAC}" -nowarn -source 8 -target 8 -encoding UTF-8 \
  -classpath "${ANDROID_JAR}" \
  -d "${WORK}/api" @"${WORK}/api-sources.txt" 2> "${WORK}/api-compile.log" || {
    cat "${WORK}/api-compile.log" >&2
    exit 1
  }

# 2) Fontes do modulo.
find "${MODULE_DIR}/src" "${WORK}/gen" -name '*.java' > "${WORK}/sources.txt"
"${JAVAC}" -nowarn -source 8 -target 8 -encoding UTF-8 \
  -classpath "${ANDROID_JAR}:${WORK}/api" \
  -d "${WORK}/classes" @"${WORK}/sources.txt"

# 3) DEX: as classes da API nao entram no APK (sao fornecidas pelo
#    framework de hooking em tempo de execucao).
find "${WORK}/classes" -name '*.class' | sed '/^$/d' > "${WORK}/class-list.txt"
"${BUILD_TOOLS}/d8" --release --min-api 27 --lib "${ANDROID_JAR}" \
  --lib "${WORK}/api" --output "${WORK}/dex" @"${WORK}/class-list.txt"

# 4) APK: manifesto + assets + classes.dex.
"${BUILD_TOOLS}/aapt2" link \
  -I "${ANDROID_JAR}" \
  --manifest "${MODULE_DIR}/AndroidManifest.xml" \
  -A "${MODULE_DIR}/assets" \
  --min-sdk-version 27 \
  --target-sdk-version 33 \
  -o "${WORK}/unsigned.apk"

python3 - "${WORK}/unsigned.apk" "${WORK}/dex/classes.dex" <<'PY'
import shutil
import sys
import zipfile

apk, dex = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as archive:
    archive.write(dex, "classes.dex")
PY

# 5) Alinhamento e assinatura.
"${BUILD_TOOLS}/zipalign" -f 4 "${WORK}/unsigned.apk" "${WORK}/aligned.apk"

KEYSTORE="${BUILD_DIR}/debug.keystore"
if [[ ! -f "${KEYSTORE}" ]]; then
  "${KEYTOOL}" -genkeypair -keystore "${KEYSTORE}" -storepass android \
    -keypass android -alias raspilot -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=RASPilot Module, OU=Development, O=RASPilot, L=, S=, C=US" >/dev/null 2>&1
fi

mkdir -p "$(dirname "${OUT}")"
"${BUILD_TOOLS}/apksigner" sign \
  --ks "${KEYSTORE}" --ks-pass pass:android --key-pass pass:android \
  --out "${OUT}" "${WORK}/aligned.apk"
"${BUILD_TOOLS}/apksigner" verify "${OUT}" >/dev/null

echo "${OUT}"
