#!/usr/bin/env bash
# Instala o toolchain de build do modulo de instrumentacao.
#
# O modulo e um APK Android: para compila-lo sao necessarios o SDK do
# Android (build-tools + platform) e um JDK. Ambos sao instalados em
# "$HOME/Android", sem privilegios de sistema.
#
# Uso:
#   ./instrumentation/setup_toolchain.sh [--sdk-only|--jdk-only]
set -euo pipefail

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android}}"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
JDK_URL="https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
BUILD_TOOLS_PKG="build-tools;34.0.0"
PLATFORM_PKG="platforms;android-34"

MODE="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sdk-only) MODE="sdk"; shift ;;
    --jdk-only) MODE="jdk"; shift ;;
    *) echo "argumento desconhecido: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "${SDK_ROOT}"

install_sdk() {
  if [[ -x "${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" ]]; then
    echo "cmdline-tools já instalado"
  else
    echo "==> baixando cmdline-tools"
    tmp="$(mktemp -d)"
    curl -sSL -o "${tmp}/cmdline-tools.zip" "${CMDLINE_TOOLS_URL}"
    unzip -q "${tmp}/cmdline-tools.zip" -d "${tmp}"
    mkdir -p "${SDK_ROOT}/cmdline-tools/latest"
    mv "${tmp}/cmdline-tools/bin" "${tmp}/cmdline-tools/lib" \
       "${tmp}/cmdline-tools/NOTICE.txt" \
       "${tmp}/cmdline-tools/source.properties" \
       "${SDK_ROOT}/cmdline-tools/latest/"
    rm -rf "${tmp}"
  fi

  export ANDROID_HOME="${SDK_ROOT}"
  export ANDROID_SDK_ROOT="${SDK_ROOT}"

  echo "==> aceitando as licencas do SDK"
  yes | "${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" \
    --sdk_root="${SDK_ROOT}" --licenses >/dev/null 2>&1 || true

  echo "==> instalando platform-tools, ${BUILD_TOOLS_PKG} e ${PLATFORM_PKG}"
  "${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" --sdk_root="${SDK_ROOT}" \
    "platform-tools" "${BUILD_TOOLS_PKG}" "${PLATFORM_PKG}" >/dev/null
}

install_jdk() {
  if [[ -x "${SDK_ROOT}/jdk/bin/javac" ]]; then
    echo "JDK já instalado"
    return
  fi
  echo "==> baixando o JDK"
  tmp="$(mktemp -d)"
  curl -sSL -o "${tmp}/jdk.tar.gz" "${JDK_URL}"
  mkdir -p "${SDK_ROOT}/jdk"
  tar xzf "${tmp}/jdk.tar.gz" -C "${SDK_ROOT}/jdk" --strip-components=1
  rm -rf "${tmp}"
}

if [[ "${MODE}" == "all" || "${MODE}" == "sdk" ]]; then
  install_sdk
fi
if [[ "${MODE}" == "all" || "${MODE}" == "jdk" ]]; then
  install_jdk
fi

cat <<EOF

Toolchain pronto em ${SDK_ROOT}.

Adicione ao shell (~/.bashrc ou ~/.profile):

export ANDROID_HOME="${SDK_ROOT}"
export ANDROID_SDK_ROOT="${SDK_ROOT}"
export JAVA_HOME="${SDK_ROOT}/jdk"
export PATH="${SDK_ROOT}/platform-tools:${SDK_ROOT}/cmdline-tools/latest/bin:${SDK_ROOT}/jdk/bin:\$PATH"

EOF
