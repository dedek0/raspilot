"""RASPilot — Verificação Anti-Root.

Investiga o dispositivo alvo por múltiplos vetores independentes de
detecção de root (binários ``su``, Magisk, propriedades de build,
apps gerenciadores de root, sistema montado ``rw``, busybox) e
consolida um veredito único com nível de confiança e evidências.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional

from checks.static import vector_view
from checks.stealth import load_stealth, unload_stealth
from instrumentation import ModuleConfig
from logcat_analyzer import analyze_since
from script_loader import load_script_file, safe_detach, safe_unload

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_root")

# Intervalo de polling da observação dinâmica (exposto para testes).
ROOT_OBSERVATION_POLL_INTERVAL = 1.0

# A bridge Java do app pode demorar a subir depois do resume; o script de
# root precisa de mais folga que os hooks nativos.
ROOT_SCRIPT_TIMEOUT = 20.0

SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)
ROOT_DETECTION_SCRIPT = os.path.join(SCRIPTS_DIR, "root_detection.js")
ROOT_BYPASS_SCRIPT = os.path.join(SCRIPTS_DIR, "anti_root_bypass.js")

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
    "me.bmax.apatch",
    "me.weishu.kernelsu",
    "com.rifsxd.ksunext",
]

ALT_ROOT_SOLUTION_MARKERS = [
    ("ls /data/adb/ap 2>/dev/null", "/data/adb/ap (APatch)"),
    ("which apd 2>/dev/null", "which apd"),
    ("ls /data/adb/ksu 2>/dev/null", "/data/adb/ksu (KernelSU)"),
    ("which ksud 2>/dev/null", "which ksud"),
    ("ls /data/adb/ksud 2>/dev/null", "/data/adb/ksud"),
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

    def __init__(
        self,
        dm: "DeviceManager",
        mode: str = "bypass",
        no_java: bool = False,
        xposed: Optional[object] = None,
    ) -> None:
        """Inicializa o check com o gerenciador de dispositivo.

        Args:
            dm: Instância conectada de ``DeviceManager``.
            mode: ``detect``, ``bypass`` ou ``stealth``. ``detect`` mede
                a detecção de root do app sem tentar o bypass.
            no_java: Se True, a observação Java via Frida é pulada.
            xposed: Gerenciador do módulo de instrumentação (opcional).
                Quando disponível, a observação/bypass de root usa o
                módulo antes de partir para o Frida.
        """
        self.dm = dm
        self.mode = mode
        self.no_java = bool(no_java)
        self.xposed = xposed

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

    def _shell_root(self, command: str, timeout: int = 20) -> dict:
        """Executa um comando shell elevando para root quando ``su`` existe.

        Diretórios como ``/data/adb/ap`` (APatch), ``/data/adb/magisk`` e
        ``/sbin/.magisk`` são ``drwx------ root`` e negam leitura ao
        usuário ``shell`` — sem elevação esses vetores dão falso-negativo
        mesmo em dispositivos rooteados.

        Args:
            command: Comando shell do dispositivo.
            timeout: Timeout em segundos.

        Returns:
            Dict ``{'ok', 'rc', 'stdout', 'stderr'}``.
        """
        runner = getattr(self.dm, "run_shell_root", None)
        if callable(runner):
            return runner(command, timeout=timeout)
        # Fake/legado sem suporte: cai no shell comum.
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
        res = self._shell_root("ls /data/adb/magisk 2>/dev/null")
        if res["ok"] and res["stdout"]:
            evidence.append("/data/adb/magisk (dir)")

        # 3) Overlay em /sbin/.magisk.
        res = self._shell_root("ls /sbin/.magisk 2>/dev/null")
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

    def check_alt_root_solutions(self) -> dict:
        """Detecta soluções de root modernas (APatch e KernelSU).

        Procura diretórios e binários característicos de cada solução.
        As probes são elevadas via ``su`` quando disponível, pois
        ``/data/adb/ap`` e ``/data/adb/ksu`` são acessíveis apenas por
        root.

        Returns:
            Dict com ``detected``, ``evidence`` e ``details``.
        """
        evidence: List[str] = []
        for command, label in ALT_ROOT_SOLUTION_MARKERS:
            res = self._shell_root(command, timeout=10)
            if res["ok"] and res["stdout"]:
                evidence.append(label)

        detected = bool(evidence)
        result = {
            "detected": detected,
            "evidence": evidence,
            "details": (
                f"APatch/KernelSU detectado: {'; '.join(evidence)}"
                if detected
                else "Nenhuma evidência de APatch ou KernelSU"
            ),
        }
        logger.debug("check_alt_root_solutions: detected=%s", detected)
        return result

    # ------------------------------------------------------------------
    # Detecção e bypass no app
    # ------------------------------------------------------------------
    def _script_replacements(self, java_only: bool = False) -> Dict[str, str]:
        """Placeholders comuns aos scripts de root."""
        return {
            "__RASPILOT_JAVA_ONLY__": "true" if java_only else "false",
            "__RASPILOT_PACKAGE_NAME__": (
                getattr(self.dm, "last_spawn_package", None) or ""
            ),
        }

    # ------------------------------------------------------------------
    # Observação via módulo (Xposed/LSPosed)
    # ------------------------------------------------------------------
    def _module_available(self) -> bool:
        """Informa se o módulo pode ser usado neste dispositivo."""
        if self.xposed is None:
            return False
        try:
            return bool(self.xposed.detect().get("available"))
        except Exception:
            return False

    def _module_observation(self, package_name: str, window: int = 12) -> dict:
        """Observa checagens de root com o módulo, sem Frida."""
        manager = self.xposed
        if manager is None:
            return {
                "detected": False,
                "detection_methods_found": [],
                "error": "módulo indisponível",
                "source": "module",
            }
        config = ModuleConfig(
            hook="off",
            root="observe",
            emulator="off",
            target=package_name,
            label="root-observe",
        )
        phase = manager.run_phase(config, window=window, interact=True)
        run = phase.get("run") or {}
        observed = list(dict.fromkeys(
            f"{item.get('method')}: {item.get('detail')}".strip(": ")
            for item in run.get("observed", [])
        ))
        result = {
            "detected": bool(observed),
            "detection_methods_found": observed,
            "app_alive_at_end": run.get("app_alive_at_end"),
            "module_ready": bool(run.get("module_ready")),
            "effective_config": run.get("effective_config", {}),
            "details": (
                f"módulo observou checagens de root: {'; '.join(observed[:4])}"
                if observed
                else "módulo não observou checagens de root"
            ),
            "source": "module",
            "error": phase.get("error") or run.get("error"),
        }
        return result

    def _attempt_module_bypass(self, package_name: str, window: int = 12) -> dict:
        """Tenta neutralizar a detecção de root com o módulo."""
        manager = self.xposed
        if manager is None:
            return {
                "success": None,
                "method": "module",
                "skipped_reason": "módulo indisponível",
                "app_alive_at_end": None,
                "neutralized": [],
                "bypass_logs": [],
                "timestamp": _now_iso(),
            }
        observation = self._module_observation(package_name, window=window)
        logs = [f"[observe] {item}" for item in observation.get("detection_methods_found") or []]
        config = ModuleConfig(
            hook="off",
            root="bypass",
            emulator="off",
            target=package_name,
            label="root-bypass",
        )
        phase = manager.run_phase(config, window=window, interact=True)
        run = phase.get("run") or {}
        neutralized = list(dict.fromkeys(
            f"{item.get('method')}: {item.get('detail')}".strip(": ")
            for item in run.get("neutralized", [])
        ))
        observed = list(dict.fromkeys(
            f"{item.get('method')}: {item.get('detail')}".strip(": ")
            for item in run.get("observed", [])
        ))
        logs.extend(f"[bypass] {item}" for item in neutralized)
        app_alive = run.get("app_alive_at_end")
        if app_alive is False:
            success = False
            reason = "app encerrou durante o bypass: a proteção resistiu"
        elif neutralized:
            success = True
            reason = f"checagens de root neutralizadas pelo módulo: {len(neutralized)}"
        elif observed:
            success = None
            reason = "módulo observou checagens, mas não as neutralizou"
        else:
            success = None
            reason = "módulo não exercitou checagens de root"
        result = {
            "success": success,
            "method": "module",
            "app_alive_at_end": app_alive,
            "neutralized": neutralized,
            "observed_checks": observed,
            "bypass_logs": logs,
            "phases": [{"phase": "observe", "ok": not observation.get("error")}],
            "details": reason,
            "timestamp": _now_iso(),
        }
        if success is None:
            result["skipped_reason"] = reason
        error = phase.get("error") or run.get("error")
        if error:
            result["error"] = str(error)
        return result

    @staticmethod
    def _exercise_message(message: str) -> bool:
        """Distingue instalação de hook de checagem realmente exercitada."""
        text = str(message or "")
        lower = text.lower()
        if "->" in text or "ioexception" in lower:
            return True
        if "rootbeer." in lower and ("false" in lower or "true" in lower):
            return True
        return False

    def _detect_app_root(self, package_name: str, window: int = 12) -> dict:
        """Observa chamadas de detecção de root feitas pelo app."""
        found: List[str] = []
        errors: List[str] = []
        loaded: List[object] = []
        stealth_loaded: List[tuple] = []
        session = None
        pid: Optional[int] = None
        resumed = False
        logcat_mark = None
        try:
            marker = getattr(self.dm, "logcat_mark", None)
            if callable(marker):
                logcat_mark = marker()

            def on_message(message, data):  # noqa: ANN001 - assinatura frida
                if message.get("type") != "send":
                    return
                payload = message.get("payload", {})
                ptype = payload.get("type")
                method = str(payload.get("method") or "")
                detail = str(payload.get("detail") or "")
                if ptype == "root-detection":
                    entry = f"{method}: {detail}"
                    if entry not in found:
                        found.append(entry)
                elif ptype in ("root-detection-error", "raspilot-script-error"):
                    text = str(payload.get("message") or "")
                    if text:
                        errors.append(text)

            session = self.dm.spawn_app(package_name, resume=False)
            pid = getattr(self.dm, "last_spawn_pid", None)
            if pid is None:
                pid = self.dm.get_app_pid(package_name)

            # A observação de root usa Frida; sem a evasão nativa o app
            # pode reagir à instrumentação antes de executar a checagem.
            try:
                stealth_loaded = load_stealth(
                    session,
                    on_message=on_message,
                    replacements=self._script_replacements(),
                    include_proc_filter=True,
                    load_native_frida=True,
                )
            except Exception:
                logger.debug("Stealth indisponível no anti-root", exc_info=True)

            native_script = load_script_file(
                session,
                ROOT_DETECTION_SCRIPT,
                on_message=on_message,
                replacements=self._script_replacements(java_only=False),
                with_java_bridge=False,
                name="raspilot-root-detect-native",
                load_timeout=ROOT_SCRIPT_TIMEOUT,
            )
            loaded.append(native_script)
            self.dm.resume_app()
            resumed = True

            if not self.no_java:
                wait = getattr(self.dm, "wait_for_app_ready", None)
                if callable(wait):
                    try:
                        wait(package_name, pid=pid)
                    except Exception:
                        logger.debug("wait_for_app_ready falhou no anti-root", exc_info=True)
                try:
                    java_script = load_script_file(
                        session,
                        ROOT_DETECTION_SCRIPT,
                        on_message=on_message,
                        replacements=self._script_replacements(java_only=True),
                        with_java_bridge=True,
                        name="raspilot-root-detect-java",
                        load_timeout=ROOT_SCRIPT_TIMEOUT,
                    )
                    loaded.append(java_script)
                except Exception as exc:
                    errors.append(f"camada Java: {exc}")
                    logger.warning("Observação Java de root não carregou", exc_info=True)

            for _ in range(max(1, int(window))):
                time.sleep(ROOT_OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    break
            app_alive = None
            if pid is not None:
                try:
                    app_alive = bool(self.dm.is_app_alive(pid))
                except Exception:
                    app_alive = None
        except Exception as exc:
            errors.append(str(exc))
            app_alive = None
            logger.warning("Observação de root do app falhou", exc_info=True)
        finally:
            if not resumed:
                try:
                    self.dm.resume_app()
                except Exception:
                    logger.debug("Falha ao retomar após observação de root", exc_info=True)
            for script in loaded:
                safe_unload(script)
            unload_stealth(stealth_loaded)
            safe_detach(session)

        logcat = {}
        if logcat_mark is not None:
            try:
                logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
            except Exception:
                logger.debug("Falha ao correlacionar logcat no anti-root", exc_info=True)

        detected = bool(found)
        details = (
            f"App executou checagens de root: {'; '.join(found[:4])}"
            if detected
            else "Nenhuma checagem de root observada no app"
        )
        result = {
            "detected": detected,
            "detection_methods_found": found,
            "app_alive_at_end": app_alive,
            "logcat": logcat,
            "details": details,
            "timestamp": _now_iso(),
        }
        if errors:
            result["error"] = "; ".join(errors)
        return result

    def _attempt_bypass(self, package_name: str, window: int = 12) -> dict:
        """Executa ``anti_root_bypass.js`` e mede a reação do app."""
        if self.mode == "detect":
            return {
                "success": None,
                "method": "frida",
                "skipped_reason": "modo detect: bypass de root não executado",
                "app_alive_at_end": None,
                "neutralized": [],
                "bypass_logs": [],
                "timestamp": _now_iso(),
            }

        bypass_logs: List[str] = []
        errors: List[str] = []
        stealth_loaded: List[tuple] = []
        loaded_scripts: List[object] = []
        session = None
        pid: Optional[int] = None
        resumed = False
        logcat_mark = None
        try:
            marker = getattr(self.dm, "logcat_mark", None)
            if callable(marker):
                logcat_mark = marker()

            def on_message(message, data):  # noqa: ANN001 - assinatura frida
                if message.get("type") != "send":
                    return
                payload = message.get("payload", {})
                text = str(payload.get("message") or "")
                if payload.get("type") == "raspilot-bypass" and text:
                    if text not in bypass_logs:
                        bypass_logs.append(text)
                elif payload.get("type") in (
                    "raspilot-script-error", "raspilot-java-unavailable",
                ):
                    if text:
                        errors.append(text)

            session = self.dm.spawn_app(package_name, resume=False)
            pid = getattr(self.dm, "last_spawn_pid", None)
            if pid is None:
                pid = self.dm.get_app_pid(package_name)
            try:
                stealth_loaded = load_stealth(
                    session,
                    on_message=on_message,
                    replacements=self._script_replacements(),
                    include_proc_filter=True,
                    load_native_frida=True,
                )
            except Exception:
                logger.debug("Stealth indisponível no bypass de root", exc_info=True)

            # Camada nativa antes do resume: cobre checagens que rodam
            # cedo e não dependem da bridge Java.
            try:
                native_script = load_script_file(
                    session,
                    ROOT_BYPASS_SCRIPT,
                    on_message=on_message,
                    replacements=self._script_replacements(java_only=False),
                    with_java_bridge=False,
                    name="raspilot-root-bypass-native",
                    load_timeout=5.0,
                )
                loaded_scripts.append(native_script)
            except Exception as exc:
                errors.append(f"camada nativa: {exc}")
                logger.debug("Bypass nativo de root indisponível", exc_info=True)

            self.dm.resume_app()
            resumed = True

            # Camada Java depois do resume: cobre RootBeer e APIs Java.
            try:
                java_script = load_script_file(
                    session,
                    ROOT_BYPASS_SCRIPT,
                    on_message=on_message,
                    replacements=self._script_replacements(java_only=True),
                    name="raspilot-root-bypass-java",
                    load_timeout=ROOT_SCRIPT_TIMEOUT,
                )
                loaded_scripts.append(java_script)
            except Exception as exc:
                errors.append(f"camada Java: {exc}")
                logger.warning("Bypass Java de root indisponível", exc_info=True)

            for _ in range(max(1, int(window))):
                time.sleep(ROOT_OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    break
            app_alive = None
            if pid is not None:
                try:
                    app_alive = bool(self.dm.is_app_alive(pid))
                except Exception:
                    app_alive = None
        except Exception as exc:
            errors.append(str(exc))
            app_alive = None
            logger.warning("Bypass de root falhou", exc_info=True)
        finally:
            if not resumed:
                try:
                    self.dm.resume_app()
                except Exception:
                    logger.debug("Falha ao retomar após bypass de root", exc_info=True)
            for script in loaded_scripts:
                safe_unload(script)
            unload_stealth(stealth_loaded)
            safe_detach(session)

        logcat = {}
        if logcat_mark is not None:
            try:
                logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
            except Exception:
                logger.debug("Falha ao correlacionar logcat no bypass de root", exc_info=True)

        exercised = [item for item in bypass_logs if self._exercise_message(item)]
        if app_alive is False:
            success = False
            reason = "app encerrou durante o bypass: a proteção resistiu à evasão"
        elif exercised:
            success = True
            reason = f"checagens de root exercitadas/neutralizadas: {len(exercised)}"
        elif errors:
            success = None
            reason = f"bypass de root: {'; '.join(errors)}"
        else:
            success = None
            reason = "bypass não exercitado: nenhuma checagem de root observada"

        result = {
            "success": success,
            "method": "frida",
            "app_alive_at_end": app_alive,
            "neutralized": exercised,
            "bypass_logs": bypass_logs,
            "exercised": bool(exercised),
            "logcat": logcat,
            "details": reason,
            "timestamp": _now_iso(),
        }
        if success is None:
            result["skipped_reason"] = reason
        if errors:
            result["error"] = "; ".join(errors)
        return result

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self,
        static_profile: Optional[dict] = None,
        package_name: Optional[str] = None,
        window: int = 12,
    ) -> dict:
        """Executa vetores de dispositivo, detecção no app e bypass.

        Consolidação: ``is_rooted=True`` se **qualquer** vetor positivo
        (exceto evidências "informativas" como bootloader). Confiança:
        ``high`` (>= 2 vetores), ``medium`` (1), ``low`` (0).

        O perfil estático e a detecção dinâmica respondem se o app tem
        código de detecção de root. O bypass mede se essa proteção resiste.
        ``is_rooted`` continua medindo o dispositivo — são dimensões
        diferentes e aparecem separadas no relatório.

        Args:
            static_profile: Perfil estático do APK (opcional).
            package_name: Package name do alvo (habilita a fase no app).
            window: Janela de observação da detecção/bypass no app.

        Returns:
            Dict com ``is_rooted``, ``confidence``, ``checks``,
            ``app_root_detection``, ``app_detection``,
            ``protection_detected``, ``bypass_successful`` e
            ``timestamp``.
        """
        checks = {
            "su_binaries": self.check_su_binaries(),
            "magisk": self.check_magisk(),
            "root_props": self.check_root_props(),
            "dangerous_apps": self.check_dangerous_apps(),
            "rw_system": self.check_rw_system(),
            "busybox": self.check_busybox(),
            "alt_root_solutions": self.check_alt_root_solutions(),
        }

        # Qualquer vetor positivo indica root; confiança vem da quantidade.
        positive = [name for name, res in checks.items() if res.get("detected")]

        # Um vetor só é conclusivo se a coleta nele realmente funcionou.
        # Sem essa contagem, um device inacessível produziria zero vetores
        # positivos e o veredito seria "ambiente limpo" — a conclusao
        # oposta do que a ausencia de dados permite afirmar.
        evaluated = [
            name for name, res in checks.items() if not res.get("error")
        ]
        failed = [name for name, res in checks.items() if res.get("error")]

        is_rooted = bool(positive)
        if len(positive) >= 2:
            confidence = "high"
        elif len(positive) == 1:
            confidence = "medium"
        elif evaluated:
            confidence = "low"
        else:
            confidence = "none"

        static_view = vector_view(static_profile, "root")
        static_present = bool(static_view and static_view.get("present"))
        app_root_detection = None
        app_detection = None
        module_detection = None
        protection_detected = None
        bypass_details = None
        bypass_successful = None
        bypass_method = None
        bypass_skipped_reason = None
        status_hint = None
        verdict_reason = None

        if static_view is not None:
            app_root_detection = dict(static_view)
            app_root_detection["static_detected"] = static_present
            app_root_detection["details"] = (
                "o APK referencia APIs/paths de detecção de root"
            )

        # A fase no app só roda quando há um perfil do APK: sem ele, o
        # pipeline não tem como distinguir "sem proteção" de "APK não
        # analisado", e um spawn extra só adicionaria ruído.
        if static_view is not None and package_name:
            # O módulo cobre checagens Java cedo (antes da bridge Frida).
            # Se ele não observar nada, a fase Frida tenta o lado nativo.
            if self._module_available():
                module_detection = self._module_observation(
                    package_name, window=window
                )
            if module_detection and module_detection.get("detected"):
                app_detection = module_detection
            else:
                app_detection = self._detect_app_root(package_name, window=window)
            dynamic_detected = bool(app_detection.get("detected")) or bool(
                (module_detection or {}).get("detected")
            )
            protection_detected = static_present or dynamic_detected
            if app_root_detection is None:
                app_root_detection = {
                    "present": False,
                    "confidence": None,
                    "static_detected": False,
                }
            app_root_detection["dynamic"] = app_detection
            app_root_detection["module"] = module_detection
            app_root_detection["dynamic_detected"] = dynamic_detected
            app_root_detection["detected"] = protection_detected
            app_root_detection["details"] = app_detection.get("details") or (
                "detecção de root no APK e no runtime"
            )

            if self.mode == "detect":
                bypass_skipped_reason = "modo detect: bypass de root não executado"
            elif protection_detected:
                if self._module_available():
                    bypass_details = self._attempt_module_bypass(
                        package_name, window=window
                    )
                else:
                    bypass_details = self._attempt_bypass(
                        package_name, window=window
                    )
                bypass_method = str(bypass_details.get("method") or "frida")
                if bypass_details.get("success") is None:
                    bypass_skipped_reason = str(
                        bypass_details.get("skipped_reason")
                        or bypass_details.get("error")
                        or "bypass de root inconclusivo"
                    )
                else:
                    bypass_successful = bool(bypass_details.get("success"))
            else:
                bypass_skipped_reason = "nenhuma detecção de root identificada no app"

            if bypass_successful is True:
                status_hint = "FALHOU"
                verdict_reason = "bypass de root venceu: proteção contornada"
            elif bypass_successful is False:
                status_hint = "OK"
                verdict_reason = "proteção de root resistiu à evasão"
            elif protection_detected:
                status_hint = "SKIP"
                verdict_reason = (
                    bypass_skipped_reason or "bypass de root não avaliado"
                )
        elif static_view is not None:
            protection_detected = static_present

        result = {
            "is_rooted": is_rooted,
            "confidence": confidence,
            "positive_vectors": positive,
            "evaluated_vectors": evaluated,
            "failed_vectors": failed,
            "checks": checks,
            "app_root_detection": app_root_detection,
            "app_detection": app_detection,
            "module_detection": module_detection,
            "protection_detected": protection_detected,
            "bypass_successful": bypass_successful,
            "bypass_method": bypass_method,
            "bypass_details": bypass_details,
            "bypass_skipped_reason": bypass_skipped_reason,
            "status_hint": status_hint,
            "verdict_reason": verdict_reason,
            "timestamp": _now_iso(),
        }
        if static_view is not None:
            result["static_analysis"] = {
                "engine": static_view.get("engine"),
                "version": static_view.get("version"),
                "vector": "root",
                "present": static_present,
                "confidence": static_view.get("confidence"),
                "owners": static_view.get("owners") or {},
                "app_evidence": bool(static_view.get("app_evidence")),
                "coverage": static_view.get("coverage"),
            }
        else:
            result["static_analysis"] = None
        if not evaluated:
            result["error"] = (
                "nenhum vetor anti-root pôde ser avaliado: "
                f"falhas em {', '.join(failed) or 'todos os vetores'}"
            )
        logger.info(
            "Anti-Root: is_rooted=%s confidence=%s vetores=%s app_root=%s bypass=%s",
            is_rooted, confidence, positive, protection_detected, bypass_successful,
        )
        return result
