"""RASPilot — Verificação Anti-Emulador (detecção e bypass).

O objetivo deste check é responder duas perguntas sobre o **app alvo**:

1. O app implementa proteção anti-emulador? (detecção)
2. Essa proteção pode ser contornada? (bypass)

A versão anterior do check media outra coisa: ela classificava o
**dispositivo de auditoria** como emulador ou não. Isso não diz nada
sobre a proteção do app — e produzia o veredito invertido (auditar de um
emulador marcava ``FALHOU`` mesmo para apps sem proteção alguma).

O check atual tem três fases:

1. **Contexto do dispositivo**: os vetores de classificação de emulador
   (propriedades, arquivos de kernel, ABI, sensores, MAC de Bluetooth,
   Genymotion/BlueStacks/Nox/Waydroid) passam a ser *contexto* — dizem
   em que tipo de máquina a auditoria rodou, e não se o app é ou não
   protegido.
2. **Detecção estática**: assinaturas anti-emulador no APK (SDKs de
   RASP, métodos de detecção e strings de fingerprint).
3. **Detecção dinâmica + bypass**: um *probe* que faz o app enxergar um
   emulador (modo ``probe``) e um *bypass* que esconde os artefatos
   decisivos de emulador (modo ``mask``).

O bypass usa o mesmo mecanismo do probe com a camada de máscara: no
modo ``mask`` os artefatos **decisivos** (Build, ``ro.kernel.qemu``,
``/dev/qemu_pipe``...) ficam ocultos, enquanto os artefatos
**secundários** que um emulador real deixa expostos (IMEI zerado,
``ANDROID_ID`` de emulador, telco "Android") continuam visíveis. É o
cenário realista de "emulador com camada de stealth": se o app ainda
reage, é porque consulta um canal que não foi ocultado — e o relatório
diz qual.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from checks.apk_utils import pull_apk, scan_apk
from checks.stealth import load_stealth, unload_stealth
from logcat_analyzer import (
    HIGH_CONFIDENCE_CATEGORIES,
    analyze_logcat,
    analyze_since,
    format_evidence,
    get_logcat_mark,
)
from script_loader import load_script_file, safe_detach, safe_unload
from instrumentation import ModuleConfig, XposedManager

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_emulator")

# Intervalo entre as consultas feitas durante a janela de observacao.
# Exposto como constante para que os testes nao dependam de esperar
# tempo real.
OBSERVATION_POLL_INTERVAL = 1.0

# Script de spoof de emulador (probe/mask).
SPOOF_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "emulator_spoof.js",
)

# Script de rastreio de morte do processo.
KILL_TRACE_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "kill_trace.js",
)

# ----------------------------------------------------------------------
# Classificação do dispositivo (contexto da auditoria)
# ----------------------------------------------------------------------
# Arquivos típicos de emuladores (QEMU, Genymotion, etc.).
EMULATOR_FILES = [
    "/dev/qemu_pipe",
    "/dev/socket/qemud",
    "/system/lib/libc_malloc_debug_qemu.so",
    "/system/lib64/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace",
    "/system/bin/qemud",
    "/init.goldfish.rc",
    "/dev/goldfish_pipe",
]

# Valores de propriedades que indicam emulador.
# Obs.: "google" NÃO entra em manufacturers — Pixels físicos também
# reportam esse valor; AVDs são cobertas por model/fingerprint/device.
QEMU_PROPS = {
    "ro.kernel.qemu": "1",
    "ro.boot.qemu": "1",
}
QEMU_HARDWARE = ("goldfish", "ranchu", "vbox86")
EMULATOR_MANUFACTURERS = ("unknown", "genymotion")
EMULATOR_MODELS = (
    "sdk",
    "sdk_gphone",
    "sdk_gphone32",
    "sdk_gphone64",
    "sdk_gphone64_x86_64",
    "emulator",
    "android sdk built for x86",
    "android sdk built for x86_64",
)

# ----------------------------------------------------------------------
# Detecção estática no APK
# ----------------------------------------------------------------------
# Assinaturas anti-emulador no APK: (tipo, [(needle_bytes, descrição)]).
#
# "emulator_sdk" são nomes de métodos/classes de detecção — a presença
# deles é evidência forte de que o app checa emulador. "emulator_strings"
# são marcadores de fingerprint: a presença é um indício (o app pode
# apenas carregá-los), e por isso fica separada.
STATIC_SIGNATURES: List[Tuple[str, List[Tuple[bytes, str]]]] = [
    ("emulator_sdk", [
        (b"DexGuardEmulatorDetected", "DexGuard: detecção de emulador"),
        (b"DexGuardVirtualEnvDetected", "DexGuard: ambiente virtual"),
        (b"SecurityEnvironment_EmulatorBuild", "SecurityEnvironment: build de emulador"),
        (b"EmulatorAbiDetected", "detecção de ABI de emulador"),
        (b"GoogleEmulatorDetected", "detecção de emulador Google"),
        (b"EmulatorFound", "EmulatorFound"),
        (b"isProbablyAnEmulator", "isProbablyAnEmulator"),
        (b"isRunningOnStockEmulator", "isRunningOnStockEmulator"),
        (b"isRunningOnEmulator", "isRunningOnEmulator"),
        (b"deviceIsEmulator", "deviceIsEmulator"),
        (b"isOnEmulator", "isOnEmulator"),
        (b"isEmulatorSync", "isEmulatorSync"),
        (b"EmulatorCapability", "EmulatorCapability"),
        (b"EmulatorUtilities", "EmulatorUtilities"),
    ]),
    ("emulator_strings", [
        (b"ro.kernel.qemu", "propriedade ro.kernel.qemu"),
        (b"/dev/qemu_pipe", "path /dev/qemu_pipe"),
        (b"/dev/socket/qemud", "path /dev/socket/qemud"),
        (b"goldfish", "string goldfish"),
        (b"ranchu", "string ranchu"),
        (b"sdk_gphone", "string sdk_gphone"),
        (b"generic_x86", "string generic_x86"),
        (b"Android SDK built for", "string 'Android SDK built for'"),
        (b"vbox86", "string vbox86"),
    ]),
]

# Prioridade do tipo principal quando há várias assinaturas no APK.
STATIC_PRIORITY = ["emulator_sdk", "emulator_strings"]

# ----------------------------------------------------------------------
# Reação do app ao ambiente emulado
# ----------------------------------------------------------------------
# Linhas de logcat que indicam que o app identificou o emulador.
#
# O critério é objetivo: a linha cita um nome de ameaça de SDK de RASP,
# ou uma afirmação explícita de detecção de emulador. Termos genéricos
# ("emulator") sozinho não bastam: apps imprimem "emulator" em mensagens
# de erro comuns.
EMULATOR_THREAT_PATTERNS = (
    re.compile(
        r"\b(DexGuardEmulatorDetected|GoogleEmulatorDetected|"
        r"EmulatorAbiDetected|EmulatorFound|isProbablyAnEmulator)\b"
    ),
    re.compile(
        r"\b(emulator detected|detected emulator|detecting emulator|"
        r"emulator build|emulatorbuild|is an emulator)\b",
        re.I,
    ),
    re.compile(r"\b(virtual environment|virtualenv)\b", re.I),
    re.compile(r"\b(ro\.kernel\.qemu|goldfish|ranchu|vbox86|sdk_gphone)\b", re.I),
)

# Canais do probe: 'decisive' (nenhum device real tem) e 'secondary'
# (artefatos que um emulador real deixa expostos).
DECISIVE_CHANNEL = "decisive"
SECONDARY_CHANNEL = "secondary"

# Cobertura do spoof por módulo: o módulo atua na camada Java do app e
# não alcança verificações nativas. A limitação é registrada no relatório
# para que o veredito não pareça mais abrangente do que é.
MODULE_COVERAGE = {
    "covered": [
        "Build (campos estáticos)",
        "SystemProperties.get",
        "TelephonyManager (identidade de telefonia)",
        "Settings.Secure (android_id)",
        "File.exists (paths de emulador)",
    ],
    "not_covered": [
        "leitura nativa de /proc/self/maps",
        "busca nativa de strings (strstr/memcmp)",
        "verificações em código nativo do app",
    ],
}


def _now_iso() -> str:
    """Retorna o timestamp atual em ISO8601 (UTC).

    Returns:
        Ex: ``'2026-10-14T18:00:00+00:00'``.
    """
    return datetime.now(timezone.utc).isoformat()


class AntiEmulatorCheck:
    """Detecta proteção anti-emulador do app e testa o bypass."""

    def __init__(
        self,
        dm: "DeviceManager",
        mode: str = "bypass",
        no_java: bool = False,
        java_timeout: float = 30.0,
        method: str = "auto",
        xposed: Optional["XposedManager"] = None,
    ) -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
            mode: ``detect``, ``bypass`` ou ``stealth``.
            no_java: Se True, não tenta carregar hooks Java.
            java_timeout: Tempo máximo de carga dos scripts Java, em
                segundos. A bridge Java domina o tempo de carga e um
                limite curto descarta o script no meio da execução.
            method: Método do probe/bypass: ``frida``, ``module`` ou
                ``auto``.
            xposed: Gerenciador do módulo de instrumentação (opcional).
        """
        self.dm = dm
        self.mode = mode
        self.no_java = no_java
        self.java_timeout = java_timeout
        self.method = method or "auto"
        self.xposed = xposed

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _getprop(self, prop: str) -> str:
        """Lê uma propriedade Android.

        Args:
            prop: Nome da propriedade.

        Returns:
            Valor limpo ou string vazia.
        """
        res = self.dm.run_shell(f"getprop {prop}", timeout=10)
        return res["stdout"].strip() if res["ok"] else ""

    def _shell(self, command: str, timeout: int = 20) -> dict:
        """Executa um comando shell e retorna a resposta estruturada."""
        return self.dm.run_shell(command, timeout=timeout)

    def _baseline(self) -> Optional[dict]:
        """Retorna o baseline somente se ele for um dict válido."""
        value = getattr(self.dm, "baseline", None)
        return value if isinstance(value, dict) else None

    def _script_replacements(self, mode: str, java_only: bool = False) -> Dict[str, str]:
        """Placeholders de configuração injetados nos scripts Frida.

        Args:
            mode: ``probe`` (app enxerga emulador) ou ``mask`` (artefatos
                decisivos ocultos).
            java_only: True para a fase Java.

        Returns:
            Mapa de placeholders.
        """
        return {
            # O modo é uma string: o placeholder é substituído por um
            # literal JS entre aspas, e não por um identificador.
            "__RASPILOT_EMU_MODE__": json.dumps(mode),
            "__RASPILOT_JAVA_ONLY__": "true" if java_only else "false",
            "__RASPILOT_PACKAGE_NAME__": getattr(self.dm, "last_spawn_package", None) or "",
        }

    # ------------------------------------------------------------------
    # Fase 1 — contexto do dispositivo
    # ------------------------------------------------------------------
    def check_emulator_props(self) -> dict:
        """Compara propriedades do build com padrões de emulador.

        Verifica ``ro.kernel.qemu``, ``ro.boot.qemu``, ``ro.hardware``,
        ``ro.product.model``, ``ro.product.manufacturer``,
        ``ro.build.fingerprint`` e ``ro.product.device``.

        Returns:
            Dict com ``detected``, ``evidence`` e ``details``.
        """
        evidence: List[str] = []

        for prop, expected in QEMU_PROPS.items():
            value = self._getprop(prop)
            if value == expected:
                evidence.append(f"{prop}={value}")

        hardware = self._getprop("ro.hardware").lower()
        if hardware in QEMU_HARDWARE:
            evidence.append(f"ro.hardware={hardware}")

        model = self._getprop("ro.product.model")
        if model.lower() in EMULATOR_MODELS:
            evidence.append(f"ro.product.model={model}")

        manufacturer = self._getprop("ro.product.manufacturer")
        if manufacturer.lower() in EMULATOR_MANUFACTURERS:
            evidence.append(f"ro.product.manufacturer={manufacturer}")

        fingerprint = self._getprop("ro.build.fingerprint").lower()
        for marker in ("generic", "emulator", "sdk_gphone", "sdk"):
            if marker in fingerprint:
                evidence.append(f"ro.build.fingerprint contém '{marker}'")
                break

        device = self._getprop("ro.product.device").lower()
        if device in ("generic", "generic_x86", "generic_x86_64", "emulator", "goldfish"):
            evidence.append(f"ro.product.device={device}")

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Propriedades de emulador: {'; '.join(evidence)}" if detected
                else "Propriedades do build não indicam emulador"
            ),
        }
        logger.debug("check_emulator_props: detected=%s", detected)
        return result

    def check_emulator_files(self) -> dict:
        """Verifica a existência de arquivos/dirs típicos de emuladores.

        Returns:
            Dict com ``detected``, ``evidence`` (paths) e ``details``.
        """
        found: List[str] = []
        for path in EMULATOR_FILES:
            res = self.dm.run_shell(f"ls {path} 2>/dev/null")
            if res["ok"] and path in res["stdout"]:
                found.append(path)

        detected = bool(found)
        result = {
            "detected": detected,
            "evidence": found,
            "details": (
                f"Arquivos de emulador encontrados: {', '.join(found)}" if detected
                else "Nenhum arquivo típico de emulador encontrado"
            ),
        }
        logger.debug("check_emulator_files: detected=%s evidence=%s", detected, found)
        return result

    def check_cpu_architecture(self) -> dict:
        """Avalia a arquitetura da CPU como indício de emulador.

        ``x86``/``x86_64`` em Android é forte indício de emulador (AVD,
        BlueStacks, Nox, LDPlayer) — exceto Chromebooks (verificados via
        ``ro.boot.hardware`` ou fingerprint 'hatch'/'octopus').

        Returns:
            Dict com ``detected``, ``evidence``, ``details`` e
            ``is_x86`` (flag para uso na consolidação).
        """
        abi = self.dm._detect_abi()
        chromebook = self._getprop("ro.boot.hardware").lower() == "chromebook"
        fingerprint = self._getprop("ro.build.fingerprint").lower()
        if any(m in fingerprint for m in ("hatch", "octopus", "trogdor", "coral")):
            chromebook = True

        is_x86 = abi in ("x86", "x86_64") and not chromebook
        evidence = [f"abi={abi}"] if is_x86 else []
        if chromebook:
            evidence.append("chromebook detectado — x86 descartado como emulador")

        result = {
            "detected": is_x86,
            "is_x86": is_x86,
            "evidence": evidence,
            "details": (
                f"ABI {abi} sem Chromebook — forte indício de emulador" if is_x86
                else f"ABI {abi} compatível com dispositivo físico"
            ),
        }
        logger.debug("check_cpu_architecture: abi=%s detected=%s", abi, is_x86)
        return result

    def check_sensors(self) -> dict:
        """Conta sensores via ``dumpsys sensorservice``.

        O formato da saída mudou no Android 10: a lista passou a usar
        ``0x00000001) nome | fabricante | ...`` em vez de ``- Nome``. O
        parser antigo (que só entendia o formato antigo) deixava o
        vetor permanentemente "indisponível" — e um vetor indisponível
        não é evidência de nada.

        Emuladores com menos de 3 sensores (ou com sensores de nome
        virtual) são indício de ambiente emulado.

        Returns:
            Dict com ``detected`` (True se < 3 sensores), ``evidence``,
            ``sensor_count`` e ``details``.
        """
        res = self.dm.run_shell("dumpsys sensorservice 2>/dev/null")
        if not res["ok"] and not res["stdout"]:
            return {
                "detected": False,
                "sensor_count": None,
                "evidence": [],
                "details": "dumpsys sensorservice indisponível",
                "error": res["stderr"] or f"rc={res['rc']}",
            }

        stdout = res["stdout"] or ""
        sensors = self._parse_sensors(stdout)
        count = len(sensors)

        # Nomes de sensor de emulador/virtual (goldfish, AOSP Emulator).
        virtual = [s for s in sensors if self._is_virtual_sensor(s)]
        detected = bool(virtual) or (0 < count < 3)

        evidence: List[str] = []
        if count:
            evidence.append(f"{count} sensores: {', '.join(sensors[:5])}")
        if virtual:
            evidence.append(f"sensores virtuais: {', '.join(virtual[:5])}")

        result = {
            "detected": detected,
            "sensor_count": count,
            "evidence": evidence,
            "details": (
                f"{count} sensores — típico de emulador" if detected
                else f"{count} sensores — plausível para dispositivo físico"
            ),
        }
        logger.debug("check_sensors: count=%s detected=%s", count, detected)
        return result

    @staticmethod
    def _parse_sensors(output: str) -> List[str]:
        """Extrai os nomes dos sensores da saída do ``dumpsys sensorservice``.

        Entende os dois formatos: o antigo (``- Nome``) e o atual
        (``0x00000001) Nome | fabricante | ...``). No formato atual, só a
        seção ``Sensor List:`` é contada — a seção ``Sensor Device:``
        lista clientes, não sensores.

        Args:
            output: Saída completa do comando.

        Returns:
            Lista com os nomes dos sensores.
        """
        names: List[str] = []
        in_list = False
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.lower().startswith("sensor list"):
                in_list = True
                continue
            if line.lower().startswith("sensor device"):
                in_list = False
                continue
            # Formato atual: "0x00000001) accelerometer_stk8321 | ..."
            match = re.match(r"^0x[0-9a-fA-F]{8}\)\s*([^|]+)", line)
            if match:
                if in_list:
                    names.append(match.group(1).strip())
                continue
            # Formato antigo: "- LSM6DSO Accelerometer"
            if line.startswith("- "):
                names.append(line[2:].strip())
        return names

    @staticmethod
    def _is_virtual_sensor(name: str) -> bool:
        """Indica se o nome do sensor denuncia um ambiente virtual.

        Args:
            name: Nome do sensor.

        Returns:
            True para nomes típicos de emulador.
        """
        low = name.lower()
        return any(
            marker in low
            for marker in ("goldfish", "aosp emulator", "android emulator", "virtual")
        )

    def check_bluetooth_mac(self) -> dict:
        """Verifica o MAC de Bluetooth via ``settings``.

        Emuladores costumam reportar o MAC placeholder ``02:00:00:00:00:00``.

        Returns:
            Dict com ``detected`` (True se placeholder), ``evidence`` e
            ``details``.
        """
        res = self.dm.run_shell("settings get secure bluetooth_address 2>/dev/null")
        mac = res["stdout"].strip().lower() if res["ok"] else ""
        if not mac or mac in ("null", "none"):
            return {
                "detected": False,
                "evidence": [],
                "details": "Endereço Bluetooth indisponível",
            }
        detected = mac == "02:00:00:00:00:00"
        result = {
            "detected": detected,
            "evidence": [f"bluetooth_address={mac}"],
            "details": (
                "MAC de Bluetooth placeholder (02:00:00:00:00:00) — emulador" if detected
                else f"MAC de Bluetooth real: {mac}"
            ),
        }
        logger.debug("check_bluetooth_mac: detected=%s", detected)
        return result

    def check_genymotion(self) -> dict:
        """Detecta especificamente o Genymotion (packages e binários).

        Returns:
            Dict com ``detected``, ``evidence`` e ``details``.
        """
        evidence: List[str] = []
        res = self.dm.run_shell("pm list packages 2>/dev/null | grep -i genymotion")
        if res["ok"] and "genymotion" in res["stdout"].lower():
            for line in res["stdout"].splitlines():
                pkg = line.replace("package:", "").strip()
                if pkg:
                    evidence.append(f"package: {pkg}")

        for path in ("/system/bin/genymotion", "/system/bin/genybaseband"):
            res = self.dm.run_shell(f"ls {path} 2>/dev/null")
            if res["ok"] and path in res["stdout"]:
                evidence.append(path)

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Genymotion detectado: {'; '.join(evidence)}" if detected
                else "Genymotion não detectado"
            ),
        }
        logger.debug("check_genymotion: detected=%s", detected)
        return result

    def check_third_party_emulators(self) -> dict:
        """Detecta emuladores de terceiros (LDPlayer, BlueStacks, Nox, Waydroid).

        Procura packages e processos característicos de cada um usando
        regex com boundaries — markers curtos como "nox" não devem casar
        com substrings legítimas de outros softwares (ex: "knox").

        Returns:
            Dict com ``detected``, ``types`` (lista), ``evidence`` e
            ``details``.
        """
        signatures: Dict[str, List[Tuple[str, str]]] = {
            "ldplayer": [
                (r"ldplayer|dnplayer|flysilkworm", "LDPlayer"),
            ],
            "bluestacks": [
                (r"bluestacks|bstlauncher", "BlueStacks"),
            ],
            "nox": [
                (r"(?<![a-zA-Z])nox(d|roid)?(?![a-zA-Z])|com\.bignox", "Nox"),
            ],
            "waydroid": [
                (r"waydroid|org\.lineageos\.waydroid", "Waydroid"),
            ],
        }

        pm = self.dm.run_shell("pm list packages 2>/dev/null")
        ps = self.dm.run_shell("ps -A 2>/dev/null")
        corpus = (pm["stdout"] + "\n" + ps["stdout"]).lower()

        found_types: List[str] = []
        evidence: List[str] = []
        for emu_type, patterns in signatures.items():
            for pattern, label in patterns:
                if re.search(pattern, corpus):
                    found_types.append(emu_type)
                    evidence.append(f"marker '{label}' ({pattern})")
                    break

        detected = bool(found_types)
        result = {
            "detected": detected,
            "types": found_types,
            "evidence": evidence,
            "details": (
                f"Emuladores de terceiros: {', '.join(found_types)}" if detected
                else "Nenhum emulador de terceiros reconhecido"
            ),
        }
        logger.debug("check_third_party_emulators: types=%s", found_types)
        return result

    def classify_device(self) -> dict:
        """Classifica o dispositivo de auditoria (contexto, não veredito).

        Returns:
            Dict com ``is_emulator``, ``emulator_type``, ``confidence``,
            ``checks`` (por vetor) e ``details``.
        """
        checks = {
            "emulator_props": self.check_emulator_props(),
            "emulator_files": self.check_emulator_files(),
            "cpu_architecture": self.check_cpu_architecture(),
            "sensors": self.check_sensors(),
            "bluetooth_mac": self.check_bluetooth_mac(),
            "genymotion": self.check_genymotion(),
            "third_party_emulators": self.check_third_party_emulators(),
        }

        props = checks["emulator_props"]
        files = checks["emulator_files"]
        cpu = checks["cpu_architecture"]
        geny = checks["genymotion"]
        third = checks["third_party_emulators"]

        if geny.get("detected"):
            emulator_type = "genymotion"
        elif third.get("types"):
            emulator_type = third["types"][0]
        elif props.get("detected") or files.get("detected"):
            emulator_type = "qemu_avd"
        elif cpu.get("detected"):
            emulator_type = None  # x86 sem demais sinais: pode ser outro ambiente
        else:
            emulator_type = None

        strong = bool(
            props.get("detected") or files.get("detected")
            or geny.get("detected") or third.get("detected")
        )
        is_emulator = bool(
            strong or (cpu.get("detected") and checks["sensors"].get("detected"))
        )
        if not is_emulator:
            confidence = "high"
        elif strong:
            confidence = "high"
        else:
            confidence = "medium"

        result = {
            "is_emulator": is_emulator,
            "emulator_type": emulator_type if is_emulator else None,
            "confidence": confidence,
            "checks": checks,
            "details": (
                f"Dispositivo de auditoria emulado ({emulator_type})" if is_emulator
                else "Dispositivo de auditoria físico"
            ),
        }
        logger.info(
            "Contexto do dispositivo: is_emulator=%s type=%s",
            is_emulator, result["emulator_type"],
        )
        return result

    # ------------------------------------------------------------------
    # Fase 2 — detecção estática
    # ------------------------------------------------------------------
    def detect_static(self, package_name: str, apk_path: Optional[str] = None) -> dict:
        """Detecta assinaturas anti-emulador no APK do app.

        Procura classes/métodos de detecção de emulador e strings de
        fingerprint de emulador.

        Args:
            package_name: Package name do app alvo.
            apk_path: Caminho opcional de um APK local (pula o ``adb pull``).

        Returns:
            Dict com ``static_detected``, ``types``, ``primary``,
            ``evidence``, ``confidence`` e, em falha de pull, ``error``.
        """
        with tempfile.TemporaryDirectory(prefix="raspilot_emu_") as tmp:
            if apk_path:
                apks = [apk_path]
            else:
                apks = pull_apk(self.dm, package_name, tmp)
                if not apks:
                    return {
                        "static_detected": False,
                        "types": [],
                        "primary": None,
                        "evidence": [],
                        "error": f"Não foi possível obter o APK de {package_name}",
                    }

            all_found: Dict[str, List[str]] = {}
            for apk in apks:
                try:
                    found = scan_apk(apk, STATIC_SIGNATURES)
                except zipfile.BadZipFile as exc:
                    logger.warning("APK inválido: %s", exc)
                    continue
                for sig_type, evidences in found.items():
                    all_found.setdefault(sig_type, []).extend(evidences)

        if not all_found:
            return {
                "static_detected": False,
                "types": [],
                "primary": None,
                "evidence": [],
                "confidence": "none",
                "details": "Nenhuma assinatura anti-emulador no APK",
            }

        chosen = sorted(
            all_found.keys(),
            key=lambda t: STATIC_PRIORITY.index(t) if t in STATIC_PRIORITY else 99,
        )[0]
        evidence = [f"[{t}] {e}" for t, items in all_found.items() for e in items]
        confidence = "high" if "emulator_sdk" in all_found else "medium"

        result = {
            "static_detected": True,
            "types": sorted(all_found.keys()),
            "primary": chosen,
            "evidence": evidence,
            "confidence": confidence,
            "details": f"Assinaturas anti-emulador no APK (principal: {chosen})",
        }
        logger.info("Assinaturas anti-emulador detectadas: type=%s", chosen)
        return result

    # ------------------------------------------------------------------
    # Fase 3 — observação dinâmica (probe)
    # ------------------------------------------------------------------
    def check_emulator_detection_in_app(
        self,
        session: object,
        on_script_loaded: Optional[object] = None,
        window: int = 12,
        pid: Optional[int] = None,
        package_name: Optional[str] = None,
        logcat_mark: Optional[int] = None,
    ) -> dict:
        """Observa se o app detecta o ambiente emulado (probe).

        Injeta um script que faz o app **enxergar um emulador** e
        registra as consultas que ele faz às primitivas sensíveis. O
        veredito se apoia na reação do app (veredito de detecção, morte
        do processo, log de ameaça) — não no simples fato de o hook ter
        sido instalado.

        Args:
            session: Sessão Frida ativa sobre o app alvo.
            on_script_loaded: Callback chamado logo após ``script.load()``
                — usado para ``resume`` de spawn suspenso.
            window: Janela de observação em segundos.
            pid: PID do processo alvo (para monitorar se o app morre).
            package_name: Package name do app alvo.
            logcat_mark: Marcador de logcat tirado antes do spawn.

        Returns:
            Dict com ``detected``, ``detection_methods_found``,
            ``strong_signals``, ``weak_signals``, ``channels``,
            ``app_alive_at_end`` e ``observation_status``.
        """
        found: List[str] = []
        strong: List[str] = []
        weak: List[str] = []
        channels: Dict[str, List[str]] = {DECISIVE_CHANNEL: [], SECONDARY_CHANNEL: []}
        spoofed: List[str] = []
        script = None
        java_script = None
        kill_script = None
        java_load_error: Optional[str] = None
        stealth_loaded: List[tuple] = []
        resumed = False
        died_after: Optional[int] = None
        notes: List[str] = []

        def add_signal(method: str, detail: str, strong_signal: bool) -> None:
            entry = f"{method}: {detail}"
            if entry not in found:
                found.append(entry)
                (strong if strong_signal else weak).append(entry)
                logger.info("App consultou primitiva de emulador -> %s", entry)

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload", {})
                ptype = payload.get("type")
                if ptype == "emulator-detection":
                    channel = payload.get("channel", SECONDARY_CHANNEL)
                    method = payload.get("method", "?")
                    detail = payload.get("detail", "")
                    kind = payload.get("kind", "query")
                    entry = f"{method}: {detail}"
                    if kind == "spoof":
                        # A instrumentação trocou o valor: isso é
                        # diagnóstico do spoof, não consulta do app.
                        if entry not in spoofed:
                            spoofed.append(entry)
                        return
                    if kind == "mask":
                        if entry not in spoofed:
                            spoofed.append(entry)
                        return
                    if channel not in channels:
                        channels[channel] = []
                    if entry not in channels[channel]:
                        channels[channel].append(entry)
                    # O veredito do próprio app (isEmulated, onEmulatorDetected)
                    # é a evidência mais forte: a checagem foi exercitada.
                    is_verdict = method.startswith("verdict:")
                    is_strong = is_verdict or channel == DECISIVE_CHANNEL
                    add_signal(method, detail, is_strong)
                    return
                if ptype == "emulator-note":
                    msg = payload.get("message", "")
                    if msg and msg not in notes:
                        notes.append(msg)
                    return
                if ptype == "emulator-error":
                    msg = payload.get("message", "")
                    if msg and msg not in notes:
                        notes.append(msg)
                    return
                if ptype == "app-kill":
                    msg = payload.get("message", "")
                    # "kill-trace carregado" é o carregamento do
                    # observador de kill, não um kill.
                    if not msg or "carregado" in msg:
                        return
                    add_signal("app_kill", msg, True)
                    return
                if ptype == "raspilot-script-error":
                    msg = str(payload.get("message", ""))
                    if msg and msg not in notes:
                        notes.append(msg)
                    logger.warning("Erro em script de observação: %s", msg)
                    return
            elif message.get("type") == "error":
                logger.debug("Erro no script anti-emulador: %s", message.get("description"))

        try:
            # A evasão anti-Frida é carregada para que a reação observada
            # seja do ambiente emulado, e não da instrumentação: um app
            # com anti-Frida morreria no probe por um motivo alheio ao
            # que estamos medindo.
            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=self._script_replacements("probe"),
                include_proc_filter=True,
            )
            # Fase 1 (antes do resume): hooks nativos do spoof.
            script = load_script_file(
                session, SPOOF_SCRIPT, on_message=on_message,
                replacements=self._script_replacements("probe", java_only=False),
                with_java_bridge=False, load_timeout=5.0,
            )
            if on_script_loaded is not None:
                on_script_loaded()
                resumed = True
            # Fase 2 (após o resume): hooks Java do spoof.
            if not self.no_java:
                try:
                    java_script = load_script_file(
                        session, SPOOF_SCRIPT, on_message=on_message,
                        replacements=self._script_replacements("probe", java_only=True),
                        with_java_bridge=True, load_timeout=self.java_timeout,
                    )
                except Exception as exc:
                    java_load_error = str(exc)
                    logger.warning("Hooks Java anti-emulador não carregaram: %s", exc)
                    safe_detach(session)
            if java_load_error is None and not self.no_java:
                try:
                    kill_script = load_script_file(
                        session, KILL_TRACE_SCRIPT, on_message=on_message,
                        load_timeout=3.0,
                    )
                except Exception:
                    logger.debug("kill_trace.js indisponível na observação", exc_info=True)
            for elapsed in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante o probe anti-emulador (~%ss)",
                        pid, died_after,
                    )
                    break
        except Exception as exc:
            logger.warning("Falha ao observar checagens anti-emulador", exc_info=True)
            return {
                "detected": False,
                "detection_methods_found": [],
                "strong_signals": [],
                "weak_signals": [],
                "channels": channels,
                "app_alive_at_end": None,
                "observed": False,
                "observation_status": "error",
                "error": str(exc),
            }
        finally:
            safe_unload(script)
            safe_unload(java_script)
            safe_unload(kill_script)
            unload_stealth(stealth_loaded)
            if not resumed and on_script_loaded is not None:
                try:
                    on_script_loaded()
                except Exception:
                    logger.debug("Falha no resume de emergência", exc_info=True)

        if died_after is None and pid is not None:
            try:
                if not self.dm.is_app_alive(pid):
                    died_after = max(1, int(window))
                    logger.info("Processo %s morreu após a janela do probe", pid)
            except Exception:
                logger.debug("Falha na rechecagem de vida", exc_info=True)

        logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
        baseline = self._baseline()

        # Reação do app no logcat: o app dizendo que detectou emulador.
        for line in self._emulator_threat_lines(logcat):
            add_signal("logcat_emulator", line, True)

        death_cause = None
        death_classification = None
        app_alive = died_after is None
        if not app_alive:
            try:
                death_cause = self.dm.capture_death_cause(
                    pid=pid, package=package_name
                )
            except Exception:
                logger.debug("Falha ao capturar causa da morte", exc_info=True)
            death_classification = self._classify_death(logcat, baseline, app_alive)
            if death_classification in ("rasp_kill", "rasp_reaction"):
                add_signal(
                    "app_terminated",
                    f"processo encerrou ~{died_after}s após resume "
                    f"({death_classification})",
                    True,
                )

        observation_status = "ok"
        error: Optional[str] = None
        if not app_alive and death_classification == "instrumentation_crash" and not strong:
            # O app matou o agente de instrumentação. A morte não diz
            # nada sobre emulador: sem a observação, a conclusão sobre
            # a proteção anti-emulador seria inventada.
            observation_status = "instrumentation_crash"
            error = (
                "o app encerrou o agente de instrumentação antes que as "
                "checagens anti-emulador pudessem ser observadas; a morte "
                "não é atribuível à detecção de emulador"
            )
        elif not app_alive and death_classification == "baseline_death" and not strong:
            observation_status = "baseline_death"
            error = (
                "app encerrou no baseline sem instrumentação; a observação "
                "anti-emulador é inconclusiva"
            )
        elif app_alive and self.no_java and not strong:
            observation_status = "native_only"
            error = (
                "hooks Java desativados (--no-java); a observação nativa não "
                "encontrou checagem anti-emulador"
            )
        elif app_alive and java_load_error and not strong:
            observation_status = "error"
            error = (
                "hooks Java de observação não carregaram e nenhuma checagem "
                f"anti-emulador foi observada: {java_load_error}"
            )

        detected = bool(strong)
        result = {
            "detected": detected,
            "detection_methods_found": found,
            "strong_signals": strong,
            "weak_signals": weak,
            "channels": channels,
            "spoofed_values": spoofed,
            "app_alive_at_end": app_alive,
            "observed": True,
            "observation_status": observation_status,
            "death_cause": death_cause,
            "death_classification": death_classification,
            "baseline": baseline,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "java_load_error": java_load_error,
            "notes": notes,
            "details": (
                f"App reagiu ao ambiente emulado: {'; '.join(strong[:5])}"
                if strong
                else (
                    "App consultou primitivas de emulador, sem reação"
                    if weak
                    else "Nenhuma checagem anti-emulador observada"
                )
            ),
        }
        if error:
            result["error"] = error
        logger.info(
            "check_emulator_detection_in_app: detected=%s strong=%s weak=%s",
            detected, len(strong), len(weak),
        )
        return result

    # ------------------------------------------------------------------
    # Fase 3 — bypass (mask)
    # ------------------------------------------------------------------
    def attempt_bypass(self, package_name: str, window: int = 12) -> dict:
        """Tenta ocultar do app os artefatos de emulador.

        Spawna o app com o script de spoof no modo ``mask``: os canais
        decisivos (Build, ``ro.kernel.qemu``, ``/dev/qemu_pipe``) ficam
        ocultos, enquanto os artefatos secundários que um emulador real
        deixa expostos (IMEI zerado, ``ANDROID_ID`` de emulador, telco
        "Android") continuam visíveis.

        O bypass só é considerado vencedor quando o app **não reage** ao
        ambiente emulado com os artefatos decisivos ocultos — é o
        diferencial em relação ao probe.

        Args:
            package_name: Package name do app alvo.
            window: Janela de observação em segundos.

        Returns:
            Dict com ``success``, ``bypass_logs``, ``masked_channels``,
            ``exposed_channels``, ``app_alive_at_end`` e ``error``.
        """
        logs: List[str] = []
        masked_channels: List[str] = []
        exposed_channels: List[str] = []
        spoofed_channels: List[str] = []
        session = None
        script = None
        java_script = None
        kill_script = None
        java_load_error: Optional[str] = None
        stealth_loaded: List[tuple] = []
        died_after: Optional[int] = None
        pid: Optional[int] = None
        signals: List[str] = []
        logcat_mark = get_logcat_mark(self.dm)

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload", {})
                ptype = payload.get("type")
                if ptype == "emulator-detection":
                    method = payload.get("method", "?")
                    detail = payload.get("detail", "")
                    entry = f"{method}: {detail}"
                    kind = payload.get("kind", "query")
                    if kind in ("spoof", "mask"):
                        if entry not in spoofed_channels:
                            spoofed_channels.append(entry)
                        return
                    if payload.get("masked"):
                        if entry not in masked_channels:
                            masked_channels.append(entry)
                    else:
                        if entry not in exposed_channels:
                            exposed_channels.append(entry)
                        if method.startswith("verdict:"):
                            if entry not in signals:
                                signals.append(entry)
                    return
                if ptype == "app-kill":
                    msg = payload.get("message", "")
                    # "kill-trace carregado" é o carregamento do
                    # observador de kill, não um kill.
                    if not msg or "carregado" in msg:
                        return
                    entry = "app-kill: " + msg
                    if entry not in logs:
                        logs.append(entry)
                    if entry not in signals:
                        signals.append(entry)
                    return
                if ptype == "emulator-note":
                    msg = "[nota] " + payload.get("message", "")
                    if msg not in logs:
                        logs.append(msg)
                    return
                if ptype == "raspilot-script-error":
                    msg = "[script-error] " + payload.get("message", "")
                    if msg not in logs:
                        logs.append(msg)
                    return
            elif message.get("type") == "error":
                desc = message.get("description", "")
                if desc:
                    entry = f"[script-error] {desc}"
                    if entry not in logs:
                        logs.append(entry)

        try:
            session = self.dm.spawn_app(package_name, resume=False)
            stealth_loaded = load_stealth(
                session,
                on_message=on_message,
                replacements=self._script_replacements("mask"),
                include_proc_filter=True,
            )
            script = load_script_file(
                session, SPOOF_SCRIPT, on_message=on_message,
                replacements=self._script_replacements("mask", java_only=False),
                with_java_bridge=False, load_timeout=5.0,
            )
            self.dm.resume_app()
            pid = self.dm.last_spawn_pid or self.dm.get_app_pid(package_name)
            if not self.no_java:
                try:
                    java_script = load_script_file(
                        session, SPOOF_SCRIPT, on_message=on_message,
                        replacements=self._script_replacements("mask", java_only=True),
                        with_java_bridge=True, load_timeout=self.java_timeout,
                    )
                except Exception as exc:
                    java_load_error = str(exc)
                    logger.warning("Hooks Java do bypass anti-emulador não carregaram: %s", exc)
                    safe_detach(session)
            if java_load_error is None and not self.no_java:
                try:
                    kill_script = load_script_file(
                        session, KILL_TRACE_SCRIPT, on_message=on_message,
                        load_timeout=3.0,
                    )
                except Exception:
                    logger.debug("kill_trace.js indisponível no bypass", exc_info=True)
            for elapsed in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    logger.info(
                        "Processo %s encerrou durante o bypass anti-emulador (~%ss)",
                        pid, died_after,
                    )
                    break
        except Exception as exc:
            logger.warning("Bypass anti-emulador falhou", exc_info=True)
            logs.append(f"[script-error] {exc}")
        finally:
            safe_unload(script)
            safe_unload(java_script)
            safe_unload(kill_script)
            unload_stealth(stealth_loaded)
            if session is not None:
                safe_detach(session)

        logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
        baseline = self._baseline()
        alive = died_after is None

        # Reação do app com os artefatos decisivos ocultos.
        for line in self._emulator_threat_lines(logcat):
            entry = f"logcat_emulator: {line}"
            if entry not in signals:
                signals.append(entry)

        death_cause = None
        death_classification = None
        if not alive:
            try:
                death_cause = self.dm.capture_death_cause(
                    pid=pid, package=package_name
                )
            except Exception:
                logger.debug("Falha ao capturar causa da morte", exc_info=True)
            death_classification = self._classify_death(logcat, baseline, alive)
            if death_classification in ("rasp_kill", "rasp_reaction"):
                # A morte só é reação do app quando é atribuível ao RASP.
                entry = f"app_terminated: processo encerrou ~{died_after}s após resume"
                if entry not in signals:
                    signals.append(entry)

        # O bypass venceu quando o app NÃO reagiu ao ambiente emulado
        # com os artefatos decisivos ocultos — mas só há conclusão se o
        # bypass foi exercitado: o app precisou consultar ao menos uma
        # primitiva de emulador na janela. O self-report do spoof
        # ("valor trocado") não conta: ele prova que a instrumentação
        # está ativa, não que o app foi enganado.
        exercised = bool(masked_channels) or bool(exposed_channels)
        success: Optional[bool] = bool(alive) and not signals
        inconclusive = False
        error: Optional[str] = None
        skipped_reason: Optional[str] = None
        if not alive and death_classification == "instrumentation_crash":
            # O app matou o agente de instrumentação: a morte não prova
            # que a proteção anti-emulador resistiu ao bypass.
            inconclusive = True
            error = (
                "o app encerrou o agente de instrumentação antes que o "
                "bypass anti-emulador pudesse ser avaliado"
            )
        elif not alive and death_classification == "baseline_death":
            inconclusive = True
            error = (
                "app encerrou no baseline sem instrumentação; o bypass "
                "anti-emulador é inconclusivo"
            )
        elif not alive:
            success = False
            if death_classification in ("rasp_kill", "rasp_reaction"):
                error = (
                    "o app bloqueou o bypass: encerrou durante a execução "
                    "do bypass anti-emulador (reação do RASP)"
                )
            else:
                error = (
                    "app encerrou durante o bypass anti-emulador sem reação "
                    f"RASP atribuível ({death_classification or 'causa desconhecida'}); "
                    "resultado inconclusivo"
                )
        elif java_load_error:
            success = False
            error = (
                "hooks Java do bypass anti-emulador não carregaram: "
                f"{java_load_error}"
            )
        elif not signals and not exercised:
            success = None
            skipped_reason = (
                "bypass não exercitado: nenhuma consulta do app a "
                "primitivas de emulador observada na janela"
            )

        result = {
            "success": success,
            "inconclusive": inconclusive,
            "exercised": exercised,
            "skipped_reason": skipped_reason,
            "blocked": bool(not alive and not inconclusive and death_classification
                            in ("rasp_kill", "rasp_reaction")),
            "bypass_logs": logs,
            "masked_channels": masked_channels,
            "exposed_channels": exposed_channels,
            "spoofed_values": spoofed_channels,
            "detection_signals": signals,
            "app_alive_at_end": alive,
            "death_cause": death_cause,
            "death_classification": death_classification,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "java_load_error": java_load_error,
            "error": error,
        }
        logger.info(
            "Bypass anti-emulador: success=%s ocultados=%s expostos=%s",
            success, len(masked_channels), len(exposed_channels),
        )
        return result

    # ------------------------------------------------------------------
    # Helpers de evidência
    # ------------------------------------------------------------------
    @staticmethod
    def _emulator_threat_lines(logcat: dict) -> List[str]:
        """Extrai do logcat as linhas que indicam detecção de emulador.

        Args:
            logcat: Resultado de ``analyze_since``.

        Returns:
            Lista de linhas (sem repetição) que denunciam a detecção.
        """
        lines: List[str] = []
        candidates: List[str] = []
        for item in logcat.get("target_lines", []) or []:
            candidates.append(str(item))
        for item in logcat.get("vendor_signals", []) or []:
            candidates.append(str(item))
        for line in candidates:
            if any(p.search(line) for p in EMULATOR_THREAT_PATTERNS):
                if line not in lines:
                    lines.append(line)
        return lines[:10]

    def _classify_death(
        self, logcat: dict, baseline: Optional[dict], app_alive: bool
    ) -> Optional[str]:
        """Classifica a morte do processo durante o probe.

        Só uma morte atribuível ao RASP conta como reação do app: um
        crash da instrumentação não é proteção anti-emulador.

        O caso mais delicado é o app que mata o **agente de
        instrumentação** (anti-Frida): o processo morre com o agente no
        backtrace, mas nada diz respeito ao emulador. Nessas condições a
        observação é inconclusiva — afirmar proteção anti-emulador a
        partir de uma morte causada pela própria ferramenta seria falso.

        Args:
            logcat: Resultado da análise do logcat.
            baseline: Baseline sem instrumentação.
            app_alive: True se o processo estava vivo.

        Returns:
            ``rasp_kill``, ``rasp_reaction``, ``baseline_death``,
            ``instrumentation_crash``, ``unclassified_death`` ou None.
        """
        if app_alive:
            return None
        baseline_died = bool(
            baseline and baseline.get("available") and baseline.get("alive_at_end") is False
        )
        baseline_healthy = bool(
            baseline and baseline.get("available") and baseline.get("alive_at_end") is True
        )
        if baseline_died:
            return "baseline_death"
        # O agente morreu dentro do processo: a morte é da ferramenta.
        if logcat.get("agent_terminated"):
            return "instrumentation_crash"
        logcat_rasp = any(
            category in (logcat.get("categories") or {})
            for category in HIGH_CONFIDENCE_CATEGORIES
        )
        if logcat_rasp:
            return "rasp_reaction"
        death = logcat.get("death") or {}
        if logcat.get("available") and death.get("kind") in ("crash", "anr"):
            if baseline_healthy and logcat.get("crash_origin") != "instrumentation":
                return "rasp_reaction"
            return "instrumentation_crash"
        return "unclassified_death"

    # ------------------------------------------------------------------
    # Probe e bypass via módulo do dispositivo
    # ------------------------------------------------------------------
    def module_available(self) -> bool:
        """Informa se o probe/bypass via módulo pode ser usado.

        Returns:
            True quando há framework de hooking no dispositivo e o
            método escolhido permite o uso do módulo.
        """
        if self.method == "frida":
            return False
        if self.xposed is None:
            return False
        framework = self.xposed.detect()
        return bool(framework.get("available"))

    def _module_events(self, run: dict) -> Tuple[List[dict], List[dict]]:
        """Separa consultas do app e spoofings do módulo.

        Args:
            run: Resultado da fase do módulo.

        Returns:
            Tupla ``(consultas, spoofings)``.
        """
        queries: List[dict] = []
        spoofs: List[dict] = []
        for item in run.get("evidence", []):
            if not item.get("channel", "").startswith("emulator"):
                continue
            if item.get("kind") == "spoof":
                spoofs.append(item)
            elif item.get("kind") in ("neutralize", "observe"):
                queries.append(item)
        return queries, spoofs

    def attempt_module_probe(self, package_name: str, window: int = 12) -> dict:
        """Faz o app enxergar um emulador usando o módulo do dispositivo.

        O módulo é limitado ao pacote alvo e executado **sem**
        instrumentação externa: o app reage ao ambiente emulado, e não a
        um agente injetado.

        Returns:
            Dict com ``detected``, ``detection_methods_found``,
            ``strong_signals``, ``weak_signals``, ``channels``,
            ``app_alive_at_end`` e ``observation_status``.
        """
        manager = self.xposed
        empty = {
            "detected": False,
            "detection_methods_found": [],
            "strong_signals": [],
            "weak_signals": [],
            "channels": {DECISIVE_CHANNEL: [], SECONDARY_CHANNEL: []},
            "app_alive_at_end": None,
            "observed": False,
            "observation_status": "error",
            "method": "module",
        }
        if manager is None:
            return {**empty, "error": "gerenciador do módulo indisponível"}

        config = ModuleConfig(
            hook="bypass",
            emulator="probe",
            target=package_name,
            label="emu-probe",
        )
        phase = manager.run_phase(config, window=window)
        run = phase.get("run") or {}
        if not run:
            return {**empty, "error": phase.get("error") or "probe do módulo falhou"}

        queries, spoofs = self._module_events(run)
        found: List[str] = []
        strong: List[str] = []
        weak: List[str] = []
        channels: Dict[str, List[str]] = {DECISIVE_CHANNEL: [], SECONDARY_CHANNEL: []}

        def add_signal(method: str, detail: str, strong_signal: bool) -> None:
            entry = f"{method}: {detail}"
            if entry in found:
                return
            found.append(entry)
            (strong if strong_signal else weak).append(entry)
            logger.info("App consultou primitiva de emulador -> %s", entry)

        for item in queries:
            channel = item.get("channel", "")
            bucket = DECISIVE_CHANNEL if channel.endswith("decisive") else SECONDARY_CHANNEL
            entry = f"{item.get('method')}: {item.get('detail')}"
            if entry not in channels[bucket]:
                channels[bucket].append(entry)
            add_signal(item.get("method", "?"), item.get("detail", ""),
                       bucket == DECISIVE_CHANNEL)

        pid = run.get("pid")
        alive = bool(run.get("app_alive_at_end"))
        logcat = analyze_logcat(run.get("lines", []), package=package_name, pid=pid)
        baseline = self._baseline()

        for line in self._emulator_threat_lines(logcat):
            add_signal("logcat_emulator", line, True)

        death_cause = None
        death_classification = None
        if not alive:
            try:
                death_cause = self.dm.capture_death_cause(pid=pid, package=package_name)
            except Exception:
                logger.debug("Falha ao capturar causa da morte", exc_info=True)
            death_classification = self._classify_death(logcat, baseline, alive)
            if death_classification in ("rasp_kill", "rasp_reaction"):
                add_signal(
                    "app_terminated",
                    f"processo encerrou durante o probe com o módulo "
                    f"({death_classification})",
                    True,
                )

        observation_status = "ok"
        error: Optional[str] = None
        if not run.get("module_ready"):
            observation_status = "error"
            error = (
                "o módulo não foi carregado no processo alvo — o escopo do "
                "framework não foi aplicado"
            )
        elif not alive and death_classification == "baseline_death" and not strong:
            observation_status = "baseline_death"
            error = (
                "app encerrou no baseline sem instrumentação; a observação "
                "anti-emulador é inconclusiva"
            )

        detected = bool(strong)
        result = {
            "detected": detected,
            "detection_methods_found": found,
            "strong_signals": strong,
            "weak_signals": weak,
            "channels": channels,
            "spoofed_values": [
                f"{item.get('method')}: {item.get('detail')}" for item in spoofs
            ],
            "app_alive_at_end": alive,
            "observed": True,
            "observation_status": observation_status,
            "death_cause": death_cause,
            "death_classification": death_classification,
            "baseline": baseline,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "coverage": MODULE_COVERAGE,
            "method": "module",
            "steps": phase.get("steps", []),
            "details": (
                f"App reagiu ao ambiente emulado: {'; '.join(strong[:5])}"
                if strong
                else (
                    "App consultou primitivas de emulador, sem reação"
                    if weak
                    else "Nenhuma checagem anti-emulador observada"
                )
            ),
        }
        if error:
            result["error"] = error
        logger.info(
            "check_emulator_detection_in_app (módulo): detected=%s strong=%s weak=%s",
            detected, len(strong), len(weak),
        )
        return result

    def attempt_module_bypass(self, package_name: str, window: int = 12) -> dict:
        """Oculta do app os artefatos de emulador usando o módulo.

        O módulo é limitado ao pacote alvo e aplica a camada de máscara:
        os artefatos decisivos ficam ocultos enquanto os secundários
        permanecem visíveis.

        Returns:
            Dict com ``success``, ``bypass_logs``, ``masked_channels``,
            ``exposed_channels``, ``app_alive_at_end`` e ``error``.
        """
        manager = self.xposed
        if manager is None:
            return {
                "success": False,
                "bypass_logs": [],
                "masked_channels": [],
                "exposed_channels": [],
                "app_alive_at_end": None,
                "error": "gerenciador do módulo indisponível",
                "method": "module",
            }

        config = ModuleConfig(
            hook="bypass",
            emulator="mask",
            target=package_name,
            label="emu-mask",
        )
        phase = manager.run_phase(config, window=window)
        run = phase.get("run") or {}
        if not run:
            return {
                "success": False,
                "bypass_logs": [],
                "masked_channels": [],
                "exposed_channels": [],
                "app_alive_at_end": None,
                "error": phase.get("error") or "bypass do módulo falhou",
                "method": "module",
            }

        queries, spoofs = self._module_events(run)
        masked: List[str] = []
        exposed: List[str] = []
        for item in queries:
            entry = f"{item.get('method')}: {item.get('detail')}"
            channel = item.get("channel", "")
            if channel.endswith("decisive"):
                if entry not in masked:
                    masked.append(entry)
            elif entry not in exposed:
                exposed.append(entry)

        pid = run.get("pid")
        alive = bool(run.get("app_alive_at_end"))

        # Re-checagem de vida: o run_phase só amostra até o fim da
        # janela; reação de RASP costuma ser assíncrona. Morte logo após
        # a janela invalida a conclusão de "app vivo".
        post_window_death = False
        if alive and pid is not None:
            try:
                if not self.dm.is_app_alive(pid):
                    alive = False
                    post_window_death = True
            except Exception:
                logger.debug("Re-checagem de vida do app falhou", exc_info=True)

        logcat = analyze_logcat(run.get("lines", []), package=package_name, pid=pid)
        baseline = self._baseline()
        conflicts = manager.scoped_modules_for(package_name)

        signals: List[str] = []
        for line in self._emulator_threat_lines(logcat):
            entry = f"logcat_emulator: {line}"
            if entry not in signals:
                signals.append(entry)

        death_cause = None
        death_classification = None
        if not alive:
            try:
                death_cause = self.dm.capture_death_cause(pid=pid, package=package_name)
            except Exception:
                logger.debug("Falha ao capturar causa da morte", exc_info=True)
            death_classification = self._classify_death(logcat, baseline, alive)
            if death_classification in ("rasp_kill", "rasp_reaction"):
                entry = "app_terminated: processo encerrou durante o bypass com o módulo"
                if entry not in signals:
                    signals.append(entry)

        # Evidência obrigatória (mesmo rigor do caminho Frida): o bypass
        # só "venceu" quando o app exercitou suas checagens anti-emulador
        # (consultas observadas) e não reagiu. O spoof do módulo é
        # self-report da instrumentação e não conta como consulta do app.
        exercised = bool(queries)
        success: Optional[bool] = bool(alive) and not signals
        inconclusive = False
        error: Optional[str] = None
        skipped_reason: Optional[str] = None
        if not alive and death_classification == "instrumentation_crash":
            inconclusive = True
            error = (
                "o app encerrou antes que o bypass anti-emulador pudesse ser "
                "avaliado"
            )
        elif not alive and death_classification == "baseline_death":
            inconclusive = True
            error = (
                "app encerrou no baseline sem instrumentação; o bypass "
                "anti-emulador é inconclusivo"
            )
        elif not alive:
            if death_classification in ("rasp_kill", "rasp_reaction"):
                error = (
                    "o app bloqueou o bypass: encerrou durante a execução "
                    "do bypass anti-emulador (reação do RASP)"
                )
            else:
                error = (
                    "app encerrou durante o bypass anti-emulador sem reação "
                    f"RASP atribuível ({death_classification or 'causa desconhecida'}); "
                    "resultado inconclusivo"
                )
        elif run.get("error"):
            error = str(run["error"])
        elif not signals and not exercised:
            success = None
            skipped_reason = (
                "bypass não exercitado: nenhuma consulta do app a "
                "primitivas de emulador observada na janela"
            )

        result = {
            "success": success,
            "inconclusive": inconclusive,
            "exercised": exercised,
            "skipped_reason": skipped_reason,
            "blocked": bool(
                not alive and not inconclusive
                and death_classification in ("rasp_kill", "rasp_reaction")
            ),
            "bypass_logs": [f"{item.get('method')}: {item.get('detail')}"
                            for item in queries],
            "masked_channels": masked,
            "exposed_channels": exposed,
            "spoofed_values": [
                f"{item.get('method')}: {item.get('detail')}" for item in spoofs
            ],
            "detection_signals": signals,
            "app_alive_at_end": alive,
            "post_window_death": post_window_death,
            "death_cause": death_cause,
            "death_classification": death_classification,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "coverage": MODULE_COVERAGE,
            "method": "module",
            "steps": phase.get("steps", []),
            "other_modules_in_scope": conflicts,
            "details": (
                "nenhuma consulta anti-emulador observada: o bypass não foi "
                "exercitado na janela"
                if not exercised
                else (
                    "nenhum artefato de emulador a ocultar: o app enxergou "
                    "o device real"
                    if not masked and not exposed
                    else (
                        f"artefatos ocultos: {len(masked)}; "
                        f"artefatos secundários expostos: {len(exposed)}"
                    )
                )
            ),
            "error": error,
        }
        logger.info(
            "Bypass anti-emulador (módulo): success=%s ocultados=%s expostos=%s",
            success, len(masked), len(exposed),
        )
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self,
        package_name: str,
        window: int = 12,
        apk_path: Optional[str] = None,
        precomputed_detection: Optional[dict] = None,
        precomputed_bypass: Optional[dict] = None,
    ) -> dict:
        """Combina contexto do dispositivo, detecção (estática + dinâmica)
        e bypass.

        Semântica do veredito:

        - ``protection_detected=True`` e ``bypass_successful=True`` ⇒ o
          app tem proteção anti-emulador, mas o bypass venceu (falha de
          RASP).
        - ``protection_detected=True`` e ``bypass_successful=False`` ⇒ a
          proteção resistiu ao bypass (OK).
        - ``protection_detected=False`` ⇒ o app não possui checagens
          anti-emulador observáveis (falha de RASP).

        Args:
            package_name: Package name do app alvo.
            window: Janela de observação (segundos) do probe e do bypass.
            apk_path: Caminho opcional de APK local para a análise estática.
            precomputed_detection: Detecção pré-calculada (opcional).
            precomputed_bypass: Bypass pré-calculado (opcional).

        Returns:
            Dict com ``protection_detected``, ``bypass_successful``,
            ``device_environment``, ``checks``, ``static_detection``,
            ``app_detection``, ``bypass_details`` e ``timestamp``.
        """
        device = self.classify_device()
        static = self.detect_static(package_name, apk_path=apk_path)

        # Fase dinâmica: usa a detecção pré-calculada quando fornecida;
        # caso contrário, cria um spawn próprio (uso standalone).
        session = None
        pid: Optional[int] = None
        app_detection: dict = {}
        probe_method = "frida"
        if precomputed_detection is not None:
            app_detection = precomputed_detection
        elif self.module_available():
            probe_method = "module"
            app_detection = self.attempt_module_probe(package_name, window=window)
        else:
            logcat_mark = get_logcat_mark(self.dm)
            try:
                session = self.dm.spawn_app(package_name, resume=False)
                pid = self.dm.last_spawn_pid or self.dm.get_app_pid(package_name)
            except Exception as exc:
                logger.warning("Spawn para o probe anti-emulador falhou", exc_info=True)
                app_detection = {
                    "detected": False,
                    "detection_methods_found": [],
                    "strong_signals": [],
                    "weak_signals": [],
                    "app_alive_at_end": None,
                    "error": str(exc),
                }
            else:
                try:
                    app_detection = self.check_emulator_detection_in_app(
                        session,
                        on_script_loaded=self.dm.resume_app,
                        window=window,
                        pid=pid,
                        package_name=package_name,
                        logcat_mark=logcat_mark,
                    )
                finally:
                    safe_detach(session)

        protection_detected = bool(static.get("static_detected")) or bool(
            app_detection.get("detected")
        )

        phase_errors: List[str] = []
        static_error = static.get("error")
        dynamic_error = app_detection.get("error")
        if not protection_detected and dynamic_error:
            # A análise estática é evidência positiva; a prova de que não
            # há proteção é o app não ter reagido ao ambiente emulado.
            # Sem essa observação, não dá para afirmar ausência de
            # proteção — o check não pôde concluir.
            phase_errors.append(f"dinâmico: {dynamic_error}")
            if static_error:
                phase_errors.append(f"estático: {static_error}")

        bypass_details: Optional[dict] = None
        bypass_successful: Optional[bool] = None
        bypass_skipped_reason: Optional[str] = None
        bypass_method = "frida"
        if self.mode == "detect":
            bypass_skipped_reason = "modo detect: bypass não executado"
        elif self.no_java and probe_method == "frida":
            bypass_skipped_reason = "--no-java: hooks Java necessários ao bypass"
        elif protection_detected:
            if precomputed_bypass is not None:
                bypass_details = precomputed_bypass
                bypass_method = str(precomputed_bypass.get("method") or "frida")
            elif self.module_available():
                bypass_method = "module"
                bypass_details = self.attempt_module_bypass(package_name, window=window)
            else:
                bypass_details = self.attempt_bypass(package_name, window=window)
            if bypass_details.get("blocked"):
                # O app bloqueou o bypass: a proteção resistiu.
                bypass_successful = False
            elif bypass_details.get("inconclusive"):
                # A etapa não pôde ser avaliada (o app derrubou a
                # instrumentação): não é conclusão sobre a proteção.
                bypass_skipped_reason = f"bypass inconclusivo: {bypass_details.get('error')}"
            elif bypass_details.get("error"):
                bypass_skipped_reason = f"bypass: {bypass_details['error']}"
            elif bypass_details.get("success") is None:
                # Bypass não exercitado: nenhuma consulta anti-emulador
                # observada/neutralizada na janela — inconclusivo, não
                # derrota da proteção.
                bypass_skipped_reason = str(
                    bypass_details.get("skipped_reason")
                    or "bypass não exercitado: sem evidência durante a janela"
                )
            else:
                success = bool(bypass_details.get("success"))
                # Só existe conclusão de "bypass venceu" quando a
                # proteção foi observada em runtime no probe ou quando a
                # janela de bypass exercitou um canal decisivo. Consultas
                # apenas a canais secundários (telefonia, android_id) têm
                # uso legítimo e não provam que a checagem anti-emulador
                # do app foi exercitada.
                dynamic_protection = bool(app_detection.get("detected"))
                decisive_exercised = bool(
                    bypass_details.get("masked_channels")
                )
                if success and not dynamic_protection and not decisive_exercised:
                    bypass_successful = None
                    bypass_skipped_reason = (
                        "bypass não exercitado: a proteção foi vista apenas "
                        "no APK e nenhuma consulta a canal decisivo de "
                        "emulador ocorreu na janela"
                    )
                else:
                    bypass_successful = success

        result: dict = {
            "protection_detected": protection_detected,
            "bypass_successful": bypass_successful,
            "probe_method": probe_method,
            "bypass_method": bypass_method,
            "device_is_emulator": bool(device.get("is_emulator")),
            "emulator_type": device.get("emulator_type"),
            "checks": device.get("checks", {}),
            "device_environment": device,
            "static_detection": static,
            "app_detection": app_detection,
            "bypass_details": bypass_details,
            "bypass_skipped_reason": bypass_skipped_reason,
            "timestamp": _now_iso(),
        }
        if static_error and not protection_detected:
            # A análise estática falhou mas a observação dinâmica rodou:
            # o veredito se apoia nela, e a falha fica registrada.
            result["static_error"] = static_error
        if phase_errors:
            result["error"] = "; ".join(phase_errors)

        logger.info(
            "Anti-Emulador: protection_detected=%s bypass_successful=%s device_is_emulator=%s",
            protection_detected, bypass_successful, result["device_is_emulator"],
        )
        return result
