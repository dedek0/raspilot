"""RASPilot — Verificação Anti-Root.

Investiga o dispositivo alvo por múltiplos vetores independentes de
detecção de root (binários ``su``, Magisk, propriedades de build,
apps gerenciadores de root, sistema montado ``rw``, busybox) e
consolida um veredito único com nível de confiança e evidências.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_root")

# Caminhos clássicos onde o binário `su` costuma existir.
SU_PATHS = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/vendor/bin/su",
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
]

# Packages de apps gerenciadores de root conhecidos.
ROOT_APP_PACKAGES = [
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
]

# Paths de busybox comuns em ROMs rooteadas.
BUSYBOX_PATHS = [
    "/system/bin/busybox",
    "/system/xbin/busybox",
    "/sbin/busybox",
    "/vendor/bin/busybox",
]


def _now_iso() -> str:
    """Retorna o timestamp atual em ISO8601 (UTC).

    Returns:
        Ex: ``'2026-10-14T18:00:00+00:00'``.
    """
    return datetime.now(timezone.utc).isoformat()


class AntiRootCheck:
    """Executa verificações de detecção de root no dispositivo alvo.

    Cada sub-check é independente e **nunca** lança exceção: falhas de
    comando/timeout viram ``{'detected': False, 'error': str}``, para que
    um vetor com problema não derrube os demais.
    """

    def __init__(self, dm: "DeviceManager") -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
        """
        self.dm = dm

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _shell(self, command: str, timeout: int = 20) -> dict:
        """Executa um comando shell e retorna a resposta estruturada.

        Args:
            command: Comando shell do dispositivo.
            timeout: Timeout em segundos.

        Returns:
            Dict ``{'ok', 'rc', 'stdout', 'stderr'}``.
        """
        return self.dm.run_shell(command, timeout=timeout)

    def _getprop(self, prop: str) -> str:
        """Lê uma propriedade Android.

        Args:
            prop: Nome da propriedade.

        Returns:
            Valor limpo ou string vazia.
        """
        res = self._shell(f"getprop {prop}", timeout=10)
        return res["stdout"].strip() if res["ok"] else ""

    # ------------------------------------------------------------------
    # Vetores de detecção
    # ------------------------------------------------------------------
    def check_su_binaries(self) -> dict:
        """Verifica a existência dos binários ``su`` em paths conhecidos.

        Returns:
            Dict com ``detected`` (bool), ``evidence`` (lista de paths
            encontrados) e ``details`` (str legível). Em falha de shell:
            ``detected=False`` e ``error`` preenchido.
        """
        found: List[str] = []
        errors: List[str] = []
        for path in SU_PATHS:
            res = self._shell(f"ls -l {path} 2>/dev/null", timeout=10)
            if res["ok"] and path in res["stdout"]:
                found.append(path)
            elif not res["ok"] and res["stderr"]:
                errors.append(f"{path}: {res['stderr']}")

        detected = bool(found)
        details = (
            f"Binário(s) su encontrado(s): {', '.join(found)}"
            if detected
            else "Nenhum binário su encontrado nos paths verificados"
        )
        result = {"detected": detected, "evidence": found, "details": details}
        if errors and not detected:
            result["error"] = "; ".join(errors)
        logger.debug("check_su_binaries: detected=%s evidence=%s", detected, found)
        return result

    def check_magisk(self) -> dict:
        """Detecta a presença do Magisk (package, dirs e binário).

        Tenta quatro vetores: package listado via ``pm``, diretório
        ``/data/adb/magisk``, ``/sbin/.magisk`` e ``which magisk``.

        Returns:
            Dict com ``detected``, ``evidence`` (lista) e ``details``.
        """
        evidence: List[str] = []

        # 1) Package Magisk instalado como app.
        res = self._shell("pm list packages 2>/dev/null | grep -i magisk")
        if res["ok"] and "magisk" in res["stdout"].lower():
            for line in res["stdout"].splitlines():
                pkg = line.replace("package:", "").strip()
                if pkg:
                    evidence.append(f"package: {pkg}")

        # 2) Diretório de dados do Magisk (requer root para listar).
        res = self._shell("ls /data/adb/magisk 2>/dev/null")
        if res["ok"] and res["stdout"]:
            evidence.append("/data/adb/magisk (dir)")

        # 3) Overlay em /sbin/.magisk.
        res = self._shell("ls /sbin/.magisk 2>/dev/null")
        if res["ok"] and res["stdout"]:
            evidence.append("/sbin/.magisk")

        # 4) Binário magisk no PATH.
        res = self._shell("which magisk 2>/dev/null")
        if res["ok"] and "magisk" in res["stdout"]:
            evidence.append(f"which magisk -> {res['stdout'].strip()}")

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Evidências Magisk: {'; '.join(evidence)}"
                if detected
                else "Nenhuma evidência do Magisk"
            ),
        }
        logger.debug("check_magisk: detected=%s", detected)
        return result

    def check_root_props(self) -> dict:
        """Analisa propriedades de build indicativas de root/debug.

        Lê ``ro.debuggable``, ``ro.secure``, ``service.adb.root``,
        ``ro.boot.verifiedbootstate`` e ``ro.boot.flash.locked``.
        Considera ``detected=True`` se ``ro.debuggable=1`` ou ``ro.secure=0``.

        Returns:
            Dict com ``detected``, ``evidence`` e ``details``.
        """
        props = {
            "ro.debuggable": self._getprop("ro.debuggable"),
            "ro.secure": self._getprop("ro.secure"),
            "service.adb.root": self._getprop("service.adb.root"),
            "ro.boot.verifiedbootstate": self._getprop("ro.boot.verifiedbootstate"),
            "ro.boot.flash.locked": self._getprop("ro.boot.flash.locked"),
        }
        evidence: List[str] = []
        detected = False

        if props["ro.debuggable"] == "1":
            evidence.append("ro.debuggable=1 (build de desenvolvimento)")
            detected = True
        if props["ro.secure"] == "0":
            evidence.append("ro.secure=0 (shell com root)")
            detected = True
        if props["service.adb.root"] == "1":
            evidence.append("service.adb.root=1 (adb em modo root)")
        if props["ro.boot.verifiedbootstate"] in ("orange", "red"):
            evidence.append(
                f"ro.boot.verifiedbootstate={props['ro.boot.verifiedbootstate']} "
                "(bootloader destravado/verificação desativada)"
            )
        if props["ro.boot.flash.locked"] == "0":
            evidence.append("ro.boot.flash.locked=0 (bootloader destravado)")

        result = {
            "detected": detected,
            "evidence": evidence,
            "props": props,
            "details": (
                f"Propriedades suspeitas: {'; '.join(evidence)}"
                if evidence
                else "Propriedades de build indicam ambiente seguro"
            ),
        }
        logger.debug("check_root_props: detected=%s", detected)
        return result

    def check_dangerous_apps(self) -> dict:
        """Detecta apps gerenciadores de root instalados.

        Compara a lista de packages do dispositivo com
        ``ROOT_APP_PACKAGES``.

        Returns:
            Dict com ``detected``, ``evidence`` (packages encontrados)
            e ``details``.
        """
        res = self._shell("pm list packages 2>/dev/null")
        if not res["ok"]:
            return {
                "detected": False,
                "evidence": [],
                "details": "Não foi possível listar packages",
                "error": res["stderr"] or f"rc={res['rc']}",
            }

        installed = {
            line.replace("package:", "").strip()
            for line in res["stdout"].splitlines()
            if line.strip()
        }
        found = [pkg for pkg in ROOT_APP_PACKAGES if pkg in installed]
        detected = bool(found)
        result = {
            "detected": detected,
            "evidence": found,
            "details": (
                f"Apps de root instalados: {', '.join(found)}"
                if detected
                else "Nenhum app gerenciador de root conhecido instalado"
            ),
        }
        logger.debug("check_dangerous_apps: detected=%s evidence=%s", detected, found)
        return result

    def check_rw_system(self) -> dict:
        """Verifica se ``/system`` está montado como gravável (rw).

        Returns:
            Dict com ``detected`` (True se ``rw``), ``evidence`` e ``details``.
        """
        res = self._shell("mount 2>/dev/null | grep ' /system '")
        if not res["ok"] or not res["stdout"]:
            # Sem entrada de /system no mount (systemless/sem grep) — não é detecção.
            return {
                "detected": False,
                "evidence": [],
                "details": "/system não listado como rw no output de mount",
            }
        line = res["stdout"].splitlines()[0]
        is_rw = " rw," in line or line.rstrip().endswith(" rw")
        evidence = [line] if is_rw else []
        result = {
            "detected": is_rw,
            "evidence": evidence,
            "details": (
                f"/system montado rw: {line}" if is_rw else "/system montado ro (leitura)"
            ),
        }
        logger.debug("check_rw_system: detected=%s", is_rw)
        return result

    def check_busybox(self) -> dict:
        """Detecta busybox instalado (indicativo de ROM customizada).

        Procura via ``which busybox`` e nos paths comuns.

        Returns:
            Dict com ``detected``, ``evidence`` e ``details``.
        """
        evidence: List[str] = []
        res = self._shell("which busybox 2>/dev/null")
        if res["ok"] and "busybox" in res["stdout"]:
            evidence.append(f"which busybox -> {res['stdout'].strip()}")

        for path in BUSYBOX_PATHS:
            res = self._shell(f"ls {path} 2>/dev/null")
            if res["ok"] and path in res["stdout"]:
                evidence.append(path)

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"Busybox encontrado: {'; '.join(evidence)}"
                if detected
                else "Busybox não encontrado"
            ),
        }
        logger.debug("check_busybox: detected=%s", detected)
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(self) -> dict:
        """Executa todos os vetores anti-root e consolida o veredito.

        Consolidação: ``is_rooted=True`` se **qualquer** vetor positivo
        (exceto evidências "informativas" como bootloader). Confiança:
        ``high`` (>= 2 vetores), ``medium`` (1), ``low`` (0).

        Returns:
            Dict com ``is_rooted`` (bool), ``confidence``
            ('high'|'medium'|'low'), ``checks`` (dict por vetor) e
            ``timestamp`` (ISO8601).
        """
        checks = {
            "su_binaries": self.check_su_binaries(),
            "magisk": self.check_magisk(),
            "root_props": self.check_root_props(),
            "dangerous_apps": self.check_dangerous_apps(),
            "rw_system": self.check_rw_system(),
            "busybox": self.check_busybox(),
        }

        # Qualquer vetor positivo indica root; confiança vem da quantidade.
        positive = [name for name, res in checks.items() if res.get("detected")]

        is_rooted = bool(positive)
        if len(positive) >= 2:
            confidence = "high"
        elif len(positive) == 1:
            confidence = "medium"
        else:
            confidence = "low"

        result = {
            "is_rooted": is_rooted,
            "confidence": confidence,
            "positive_vectors": positive,
            "checks": checks,
            "timestamp": _now_iso(),
        }
        logger.info(
            "Anti-Root: is_rooted=%s confidence=%s vetores=%s",
            is_rooted, confidence, positive,
        )
        return result
