"""RASPilot — Verificação de Anti-Tampering.

Três camadas:

1. **Estática** — procura APIs/strings de integridade no APK (assinatura
   de pacote, `MessageDigest`, Play Integrity/SafetyNet, CRC etc.).
2. **Dinâmica em memória** — altera em memória a assinatura devolvida
   por `PackageManager` e compara com um controle sem alteração. Usa o
   módulo do dispositivo (`TamperShield`) quando disponível; senão,
   Frida com stealth. Se o app morre só na fase com tamper, ele detectou
   a alteração.
3. **Repack destrutivo** — opcional e opt-in (`method="repack"`):
   reconstrói o APK, re-assina e reinstala para medir a reação do app.
   Exige `allow_reinstall`; o fluxo de controles e restore fica em
   :mod:`checks.tamper_repack`.
"""

from __future__ import annotations

import glob
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence

from checks.apk_utils import pull_apk, scan_apk
from checks.static import vector_view
from checks.static.queries import TAMPER_SIGNATURES
from checks.stealth import load_stealth, unload_stealth
from logcat_analyzer import analyze_since
from script_loader import load_script_file, safe_detach, safe_unload

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.checks.anti_tampering")

OBSERVATION_POLL_INTERVAL = 1.0
# A bridge Java pode demorar a subir em apps grandes; o script só precisa
# ficar carregado antes de a janela de observação terminar.
TAMPER_SCRIPT_TIMEOUT = 60.0
TAMPER_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "tamper_probe.js",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _confidence(descriptions: List[str]) -> str:
    text = " ".join(item.lower() for item in descriptions)
    if any(token in text for token in (
        "get_signatures", "get_signing_certificates", "checksignatures",
        "signinginfo", "play integrity", "safetynet", "integritytoken",
    )):
        return "high"
    if any(token in text for token in (
        "messagedigest", "getpackagecodepath", "getpackageresourcepath",
        "crc32", "checksum",
    )):
        return "medium"
    return "low"


class AntiTamperingCheck:
    """Detecta anti-tampering e testa sonda em memória ou repack."""

    def __init__(
        self,
        dm: "DeviceManager",
        mode: str = "bypass",
        no_java: bool = False,
        method: str = "auto",
        xposed=None,
        repack_variants: Optional[Sequence[str]] = None,
        allow_reinstall: bool = False,
        installer: Optional[str] = None,
        restore: bool = True,
        keep_artifacts: bool = False,
        output_dir: Optional[str] = None,
        repack_timeout: int = 600,
    ) -> None:
        self.dm = dm
        self.mode = mode
        self.no_java = bool(no_java)
        self.method = method or "auto"
        self.repack_variants = list(repack_variants or ("asset", "dex"))
        self.allow_reinstall = bool(allow_reinstall)
        self.installer = installer
        self.restore = bool(restore)
        self.keep_artifacts = bool(keep_artifacts)
        self.output_dir = output_dir
        self.repack_timeout = int(repack_timeout)
        # Gerenciador do módulo de instrumentação (opcional). Quando
        # disponível, a sonda roda no próprio dispositivo, sem a bridge
        # Java do Frida — que alguns alvos tratam como crash de runtime.
        self.xposed = xposed

    # ------------------------------------------------------------------
    # Estático
    # ------------------------------------------------------------------
    def detect_static(
        self,
        package_name: str,
        apk_path: Optional[str] = None,
        static_profile: Optional[dict] = None,
    ) -> dict:
        """Detecta APIs/strings de integridade no APK."""
        view = vector_view(static_profile, "tamper")
        if view is not None:
            evidence = [
                item.get("evidence")
                for item in view.get("findings") or []
                if item.get("evidence")
            ]
            return {
                "tamper_detected": bool(view.get("present")),
                "static_detected": bool(view.get("present")),
                "types": sorted(
                    {
                        item.get("kind")
                        for item in view.get("findings") or []
                        if item.get("kind")
                    }
                ),
                "evidence": evidence,
                "confidence": view.get("confidence"),
                "owners": view.get("owners") or {},
                "app_evidence": bool(view.get("app_evidence")),
                "asc": view,
                "details": (
                    "referências de integridade/tampering no APK"
                    if view.get("present")
                    else "nenhuma referência de integridade no APK"
                ),
            }

        with tempfile.TemporaryDirectory(prefix="raspilot_tamper_") as tmp:
            if apk_path and os.path.isdir(apk_path):
                apks = sorted(glob.glob(os.path.join(apk_path, "*.apk")))
            elif apk_path:
                apks = [apk_path]
            else:
                apks = pull_apk(self.dm, package_name, tmp)
            if not apks:
                return {
                    "tamper_detected": False,
                    "static_detected": False,
                    "types": [],
                    "evidence": [],
                    "confidence": "none",
                    "error": f"Não foi possível obter o APK de {package_name}",
                    "details": "APK indisponível",
                }
            found: Dict[str, List[str]] = {}
            for apk in apks:
                try:
                    partial = scan_apk(apk, [("tamper", TAMPER_SIGNATURES)])
                except Exception:
                    logger.debug("Falha ao escanear APK para tampering", exc_info=True)
                    continue
                for key, values in partial.items():
                    found.setdefault(key, []).extend(values)
        evidence = found.get("tamper") or []
        return {
            "tamper_detected": bool(evidence),
            "static_detected": bool(evidence),
            "types": ["signature"] if evidence else [],
            "evidence": evidence,
            "confidence": _confidence(evidence),
            "details": (
                "referências de integridade/tampering no APK"
                if evidence
                else "nenhuma referência de integridade no APK"
            ),
        }

    # ------------------------------------------------------------------
    # Dinâmico
    # ------------------------------------------------------------------
    def _module_available(self) -> bool:
        """Informa se o módulo pode executar a sonda neste dispositivo."""
        if self.xposed is None:
            return False
        try:
            return bool(self.xposed.detect().get("available"))
        except Exception:
            return False

    def _module_phase(self, package_name: str, window: int, tamper: bool) -> dict:
        """Executa a fase de controle/alteração pelo módulo do dispositivo."""
        from instrumentation import ModuleConfig

        mode = "bypass" if tamper else "observe"
        config = ModuleConfig(
            hook="off",
            root="off",
            tamper=mode,
            emulator="off",
            target=package_name,
            label=f"tamper-{mode}",
        )
        phase = self.xposed.run_phase(config, window=window, interact=True)
        run = phase.get("run") or {}
        observed = list(dict.fromkeys(
            f"{item.get('method')}: {item.get('detail')}".strip(": ")
            for item in run.get("observed", [])
        ))
        neutralized = list(dict.fromkeys(
            f"{item.get('method')}: {item.get('detail')}".strip(": ")
            for item in run.get("neutralized", [])
        ))
        error = phase.get("error") or run.get("error")
        # O módulo pode emitir evidência mesmo quando a linha "ready"
        # não aparece no recorte do logcat. Evidência de hook vale mais
        # que o aviso genérico de "módulo não carregado".
        if neutralized or observed:
            error = None
        return {
            "app_alive": run.get("app_alive_at_end"),
            "tamper_installed": bool(neutralized or observed),
            "sham": not tamper,
            "messages": observed + [f"neutralized: {item}" for item in neutralized],
            "neutralized": neutralized,
            "observed": observed,
            "module_ready": bool(run.get("module_ready")),
            "error": str(error) if error else None,
        }

    def _script_replacements(self, tamper_mode: str = "sham") -> Dict[str, str]:
        port = getattr(self.dm, "frida_port", None)
        return {
            "__RASPILOT_FRIDA_PORT__": str(port if isinstance(port, int) else 27999),
            "__RASPILOT_PACKAGE_NAME__": (
                getattr(self.dm, "last_spawn_package", None) or ""
            ),
            "__RASPILOT_TAMPER_MODE__": tamper_mode,
        }

    def _phase(self, package_name: str, window: int, tamper: bool) -> dict:
        """Executa uma fase (controle ou tamper) com stealth."""
        if tamper and self.no_java:
            return {
                "app_alive": None,
                "tamper_installed": False,
                "messages": [],
                "error": "--no-java: sonda de tamper exige Java",
            }
        messages: List[str] = []
        errors: List[str] = []
        stealth_loaded: List[tuple] = []
        probe_script = None
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
                text = str(payload.get("message") or "")
                if ptype == "tamper-probe" and text:
                    if text not in messages:
                        messages.append(text)
                elif ptype == "app-kill" and text:
                    if text not in messages:
                        messages.append("app-kill: " + text)
                elif ptype in ("raspilot-script-error", "raspilot-java-unavailable"):
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
                logger.debug("Stealth indisponível no anti-tampering", exc_info=True)
            # A sonda é carregada com o processo suspenso. Depois do
            # resume, a inicialização do runtime Java do app disputa o
            # agente e o load pode estourar o timeout do RPC do Frida. O
            # script adia os hooks, então o load não inicializa a bridge.
            probe_mode = "tamper" if tamper else "sham"
            probe_script = load_script_file(
                session,
                TAMPER_SCRIPT,
                on_message=on_message,
                replacements=self._script_replacements(probe_mode),
                name=f"raspilot-tamper-{probe_mode}",
                load_timeout=TAMPER_SCRIPT_TIMEOUT,
            )
            self.dm.resume_app()
            resumed = True
            wait = getattr(self.dm, "wait_for_app_ready", None)
            if callable(wait):
                try:
                    wait(package_name, pid=pid)
                except Exception:
                    logger.debug("wait_for_app_ready falhou no tamper", exc_info=True)
            for _ in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
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
            logger.warning("Fase anti-tampering falhou", exc_info=True)
        finally:
            if not resumed:
                try:
                    self.dm.resume_app()
                except Exception:
                    logger.debug("Falha ao retomar após tamper", exc_info=True)
            if probe_script is not None:
                safe_unload(probe_script)
            unload_stealth(stealth_loaded)
            safe_detach(session)

        logcat = {}
        if logcat_mark is not None:
            try:
                logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
            except Exception:
                logger.debug("Falha ao correlacionar logcat no tamper", exc_info=True)

        installed = any(
            token in str(item).lower()
            for item in messages
            for token in (
                "instalando hooks", "hooks instalados",
                "sonda de assinatura", "hookado", "alterado",
            )
        )
        return {
            "app_alive": app_alive,
            "tamper_installed": installed,
            "sham": not tamper,
            "messages": messages,
            "error": "; ".join(errors) if errors else None,
            "logcat": logcat,
        }

    def probe_in_memory(self, package_name: str, window: int = 12) -> dict:
        """Compara controle sem tamper com a sonda de assinatura alterada."""
        baseline = getattr(self.dm, "baseline", None)
        if isinstance(baseline, dict) and baseline.get("available") and baseline.get(
            "alive_at_end"
        ) is False:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": "frida",
                "skipped_reason": "app já morria no baseline sem instrumentação",
                "control_alive": None,
                "tamper_alive": None,
                "details": "linha de base instável",
                "timestamp": _now_iso(),
            }

        use_module = self.method != "frida" and self._module_available()
        phase = self._module_phase if use_module else self._phase
        method = "module" if use_module else "frida"
        control = phase(package_name, window, tamper=False)
        if control.get("error") or control.get("app_alive") is not True:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": method,
                "skipped_reason": (
                    "controle sem tamper não ficou vivo: "
                    + str(control.get("error") or "app encerrou")
                ),
                "control_alive": control.get("app_alive"),
                "tamper_alive": None,
                "control": control,
                "details": "controle inconclusivo",
                "timestamp": _now_iso(),
            }

        tamper = phase(package_name, window, tamper=True)
        if tamper.get("error"):
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": method,
                "skipped_reason": f"sonda de tamper: {tamper.get('error')}",
                "control_alive": control.get("app_alive"),
                "tamper_alive": tamper.get("app_alive"),
                "control": control,
                "probe": tamper,
                "details": "sonda inconclusiva",
                "timestamp": _now_iso(),
            }
        if not tamper.get("tamper_installed"):
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": method,
                "skipped_reason": "sonda de tamper não exercitou a checagem de assinatura",
                "control_alive": control.get("app_alive"),
                "tamper_alive": tamper.get("app_alive"),
                "control": control,
                "probe": tamper,
                "details": "sonda não exercitada",
                "timestamp": _now_iso(),
            }

        detected = tamper.get("app_alive") is False
        bypass = tamper.get("app_alive") is True
        return {
            "tamper_detected": detected,
            "bypass_successful": bypass,
            "probe_method": method,
            "control_alive": control.get("app_alive"),
            "tamper_alive": tamper.get("app_alive"),
            "control": control,
            "probe": tamper,
            "details": (
                "app encerrou na fase com assinatura alterada: tampering detectado"
                if detected
                else "app sobreviveu à assinatura alterada: tampering não bloqueado"
            ),
            "timestamp": _now_iso(),
        }

    # ------------------------------------------------------------------
    # Consolidação
    # ------------------------------------------------------------------
    def run_all(
        self,
        static_profile: Optional[dict] = None,
        package_name: Optional[str] = None,
        window: int = 12,
        apk_path: Optional[str] = None,
    ) -> dict:
        static = self.detect_static(
            package_name or "",
            apk_path=apk_path,
            static_profile=static_profile,
        )
        probe: Optional[dict] = None
        bypass_skipped_reason = None
        if self.method == "static":
            bypass_skipped_reason = "método static: sonda dinâmica não executada"
        elif self.mode == "detect":
            bypass_skipped_reason = "modo detect: sonda dinâmica não executada"
        elif not package_name:
            bypass_skipped_reason = "package name ausente"
        elif self.method == "repack":
            from checks.tamper_repack import RepackTester

            probe = RepackTester(
                self.dm,
                package_name,
                apk_path=apk_path,
                output_dir=self.output_dir,
                window=window,
                variants=self.repack_variants,
                installer=self.installer,
                allow_reinstall=self.allow_reinstall,
                restore=self.restore,
                keep_artifacts=self.keep_artifacts,
                timeout=self.repack_timeout,
            ).run()
            if probe.get("bypass_successful") is None:
                bypass_skipped_reason = str(
                    probe.get("skipped_reason") or "repack inconclusivo"
                )
        elif self.no_java:
            bypass_skipped_reason = "--no-java: sonda de tamper exige Java"
        else:
            probe = self.probe_in_memory(package_name, window=window)
            if probe.get("bypass_successful") is None:
                bypass_skipped_reason = str(
                    probe.get("skipped_reason") or "sonda inconclusiva"
                )

        tamper_detected = None if probe is None else probe.get("tamper_detected")
        bypass_successful = None if probe is None else probe.get("bypass_successful")
        static_present = bool(static.get("static_detected"))
        protection_detected = static_present or bool(tamper_detected)

        status_hint = None
        verdict_reason = None
        if probe is not None and probe.get("probe_method") == "repack":
            status_hint = probe.get("status_hint") or "SKIP"
            verdict_reason = (
                probe.get("verdict_reason")
                or probe.get("skipped_reason")
                or "repack inconclusivo"
            )
        elif bypass_successful is True:
            status_hint = "FALHOU"
            verdict_reason = "app sobreviveu à alteração de assinatura em memória"
        elif bypass_successful is False:
            status_hint = "OK"
            verdict_reason = "app detectou/bloqueou a alteração de assinatura"
        elif static_present:
            status_hint = "SKIP"
            verdict_reason = bypass_skipped_reason or "sonda dinâmica não executada"
        else:
            status_hint = "SKIP"
            verdict_reason = bypass_skipped_reason or "sem evidência de anti-tampering"

        app_detection = None
        if probe is not None:
            observations = probe.get("observations") or {}
            detected_variants = [
                item for item in observations.values()
                if isinstance(item, dict)
                and item.get("usable") is False
                and item.get("label") in (
                    "asset", "dex", "resource", "manifest"
                )
            ]
            app_detection = {
                "detected": tamper_detected,
                "app_alive_at_end": probe.get("tamper_alive"),
                "control_alive": probe.get("control_alive"),
                "observation_status": (
                    "ok" if tamper_detected is not None else "inconclusive"
                ),
                "details": probe.get("verdict_reason") or probe.get("details"),
                "error": probe.get("skipped_reason") if tamper_detected is None else None,
            }
            if probe.get("probe_method") == "repack":
                app_detection["observation_status"] = (
                    "ok" if probe.get("status_hint") in ("OK", "FALHOU")
                    else "inconclusive"
                )
                app_detection["variants_detected"] = sorted(
                    str(item.get("label"))
                    for item in detected_variants
                    if item.get("label")
                )

        result = {
            "tamper_detected": tamper_detected,
            "static_detected": static_present,
            "protection_detected": protection_detected,
            "bypass_successful": bypass_successful,
            "bypass_method": (
                probe.get("probe_method") if probe is not None else None
            ),
            "bypass_details": probe,
            "bypass_skipped_reason": bypass_skipped_reason,
            "static_detection": static,
            "static_analysis": (
                {
                    "engine": (static.get("asc") or {}).get("engine"),
                    "version": (static.get("asc") or {}).get("version"),
                    "vector": "tamper",
                    "present": static_present,
                    "confidence": static.get("confidence"),
                    "owners": static.get("owners") or {},
                    "app_evidence": bool(static.get("app_evidence")),
                    "coverage": (static.get("asc") or {}).get("coverage"),
                }
                if static.get("asc")
                else None
            ),
            "app_detection": app_detection,
            "status_hint": status_hint,
            "verdict_reason": verdict_reason,
            "evidence": static.get("evidence") or [],
            "timestamp": _now_iso(),
        }
        if static.get("error"):
            result["static_error"] = static["error"]
        return result
