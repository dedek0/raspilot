"""RASPilot — Verificação Anti-Emulador.

Detecta se o ambiente de execução é um emulador (AVD/QEMU, Genymotion,
LDPlayer, BlueStacks, Nox, Waydroid) combinando múltiplos vetores
(propriedades do build, arquivos do kernel, arquitetura de CPU,
sensores, MAC de Bluetooth e packages específicos) e classifica o tipo
de emulador com nível de confiança.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_emulator")

# Arquivos típicos de emuladores (QEMU, Genymotion, etc.).
EMULATOR_FILES = [
    "/dev/qemu_pipe",
    "/dev/socket/qemud",
    "/dev/socket/genyd",
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
EMULATOR_MODELS = ("sdk", "emulator", "android sdk built for x86", "android sdk built for x86_64")


def _now_iso() -> str:
    """Retorna o timestamp atual em ISO8601 (UTC).

    Returns:
        Ex: ``'2026-10-14T18:00:00+00:00'``.
    """
    return datetime.now(timezone.utc).isoformat()


class AntiEmulatorCheck:
    """Detecta emuladores Android por combinação de evidências."""

    def __init__(self, dm: "DeviceManager") -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
        """
        self.dm = dm

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

    # ------------------------------------------------------------------
    # Vetores
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
        ``ro.boot.hardware.chromebook`` ou fingerprint 'hatch'/'octopus').

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

        Emuladores normalmente expõem menos de 3 sensores (faltam
        acelerômetro/giroscópio reais).

        Returns:
            Dict com ``detected`` (True se < 3 sensores), ``evidence``,
            ``sensor_count`` e ``details``.
        """
        res = self.dm.run_shell("dumpsys sensorservice 2>/dev/null | grep -E '^\\s+- '")
        if not res["ok"] and not res["stdout"]:
            return {
                "detected": False,
                "sensor_count": None,
                "evidence": [],
                "details": "dumpsys sensorservice indisponível",
                "error": res["stderr"] or f"rc={res['rc']}",
            }

        sensors = [line.strip() for line in res["stdout"].splitlines() if line.strip().startswith("-")]
        count = len(sensors)
        detected = 0 < count < 3
        result = {
            "detected": detected,
            "sensor_count": count,
            "evidence": [f"{count} sensores: {', '.join(sensors[:5])}"],
            "details": (
                f"Apenas {count} sensores — típico de emulador" if detected
                else f"{count} sensores — plausível para dispositivo físico"
            ),
        }
        logger.debug("check_sensors: count=%s detected=%s", count, detected)
        return result

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
        # tipo: [(regex de marker, descrição), ...]
        signatures: Dict[str, List[Tuple[str, str]]] = {
            "ldplayer": [
                (r"ldplayer|dnplayer|flysilkworm", "LDPlayer"),
            ],
            "bluestacks": [
                (r"bluestacks|bstlauncher", "BlueStacks"),
            ],
            "nox": [
                # negative lookbehind/lookahead evitam substrings como
                # "knox"; "noxd"/"noxroid" continuam casando.
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

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def _classify(
        self,
        props: dict,
        files: dict,
        genymotion: dict,
        third_party: dict,
        cpu: dict,
    ) -> Tuple[Optional[str], int]:
        """Classifica o tipo de emulador e pontua a confiança.

        Args:
            props: Resultado de ``check_emulator_props``.
            files: Resultado de ``check_emulator_files``.
            genymotion: Resultado de ``check_genymotion``.
            third_party: Resultado de ``check_third_party_emulators``.
            cpu: Resultado de ``check_cpu_architecture``.

        Returns:
            Tupla ``(emulator_type, pontuação)`` — o tipo é ``None``
            quando não classificado; a pontuação alimenta a confiança.
        """
        evidence_blob = " ".join(
            list(props.get("evidence", []))
            + list(files.get("evidence", []))
            + list(genymotion.get("evidence", []))
            + list(third_party.get("evidence", []))
        ).lower()

        # Ordem importa: genymotion/terceiros antes do fallback QEMU.
        if genymotion.get("detected"):
            return "genymotion", 3
        for emu_type in third_party.get("types", []):
            return emu_type, 3
        if props.get("detected") or files.get("detected"):
            # Combinação de props + files ⇒ QEMU/AVD (alta confiança).
            if props.get("detected") and files.get("detected"):
                return "qemu_avd", 3
            if cpu.get("detected"):
                return "qemu_avd", 2
            return "qemu_avd", 2
        if cpu.get("detected"):
            # x86 sem demais sinais: indício médio (pode ser Chromebook/Win11 ARM).
            return None, 1
        if evidence_blob:
            return None, 1
        return None, 0

    def run_all(self) -> dict:
        """Executa todos os vetores anti-emulador e consolida o veredito.

        Returns:
            Dict com ``is_emulator`` (bool), ``emulator_type``
            ('qemu_avd'|'genymotion'|'ldplayer'|'bluestacks'|'nox'|
            'waydroid'|None), ``confidence`` ('high'|'medium'|'low'),
            ``checks`` (por vetor) e ``timestamp`` (ISO8601).
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

        emulator_type, score = self._classify(
            checks["emulator_props"],
            checks["emulator_files"],
            checks["genymotion"],
            checks["third_party_emulators"],
            checks["cpu_architecture"],
        )

        # Sinais fortes diretos (props QEMU, genymotion, terceiros) ⇒ high.
        strong = (
            checks["emulator_props"].get("detected")
            or checks["emulator_files"].get("detected")
            or checks["genymotion"].get("detected")
            or checks["third_party_emulators"].get("detected")
        )
        # Sinais fracos (sensores, MAC placeholder) somam à decisão.
        weak = checks["sensors"].get("detected") or checks["bluetooth_mac"].get("detected")

        is_emulator = bool(strong or (checks["cpu_architecture"].get("detected") and weak))

        # Sem vetor efetivamente avaliado não há conclusão: um device
        # inacessível não pode ser declarado "físico".
        evaluated = [
            name for name, res in checks.items() if not res.get("error")
        ]
        failed = [name for name, res in checks.items() if res.get("error")]

        if is_emulator and strong:
            confidence = "high"
        elif is_emulator:
            confidence = "medium"
        elif not evaluated:
            confidence = "none"
        elif weak or checks["cpu_architecture"].get("detected"):
            confidence = "low"
        else:
            confidence = "high"  # todos os vetores negativos = confiante: físico

        result = {
            "is_emulator": is_emulator,
            "emulator_type": emulator_type if is_emulator else None,
            "confidence": confidence,
            "evaluated_vectors": evaluated,
            "failed_vectors": failed,
            "checks": checks,
            "timestamp": _now_iso(),
        }
        if not evaluated:
            result["error"] = (
                "nenhum vetor anti-emulador pôde ser avaliado: "
                f"falhas em {', '.join(failed) or 'todos os vetores'}"
            )
        logger.info(
            "Anti-Emulador: is_emulator=%s type=%s confidence=%s",
            is_emulator, result["emulator_type"], confidence,
        )
        return result
