"""RASPilot — Verificação de detecção de Proxy/VPN (estático + dinâmico).

O check responde a duas perguntas sobre o **app alvo**:

1. O app consulta a configuração de proxy/VPN para decidir se bloqueia
   ou restringe o uso?
2. Essa decisão pode ser contornada escondendo proxy/VPN do app?

O modo ``probe`` faz o app enxergar um proxy/VPN e observa quais APIs
ele consulta e se ele reage. O modo ``bypass`` esconde proxy/VPN para
que o app continue utilizável quando o operador usa um proxy. A
tentativa usa o módulo de instrumentação (quando há framework) ou o
script Frida ``proxy_bypass.js``.

Importante: detectar proxy/VPN não é certificate pinning. Um app pode
bloquear proxy sem fixar certificados; este check existe justamente
para separar as duas coisas.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from checks.apk_utils import pull_apk, scan_apk
from checks.static import merge_signature_detection, vector_view
from checks.stealth import load_stealth, unload_stealth
from instrumentation import ModuleConfig, XposedManager
from logcat_analyzer import (
    HIGH_CONFIDENCE_CATEGORIES,
    analyze_since,
    format_evidence,
    get_logcat_mark,
)
from script_loader import load_script_file, safe_detach, safe_unload

logger = logging.getLogger("raspilot.checks.anti_proxy")

OBSERVATION_POLL_INTERVAL = 1.0

PROXY_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "proxy_bypass.js",
)

KILL_TRACE_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "kill_trace.js",
)

# Assinaturas de bytes. Grupos com APIs específicas têm confiança maior;
# a simples presença de NetworkInterface/ConnectivityManager é comum e
# fica como contexto.
STATIC_SIGNATURES: List[Tuple[str, List[Tuple[bytes, str]]]] = [
    ("proxy_strings", [
        (b"http.proxyHost", "propriedade http.proxyHost"),
        (b"https.proxyHost", "propriedade https.proxyHost"),
        (b"socksProxyHost", "propriedade socksProxyHost"),
        (b"http_proxy", "chave http_proxy"),
        (b"https_proxy", "chave https_proxy"),
        (b"java.net.useSystemProxies", "propriedade useSystemProxies"),
        (b"getDefaultProxy", "Proxy.getDefaultProxy"),
        (b"ProxySelector.select", "ProxySelector.select"),
        (b"ProxySelector.getDefault", "ProxySelector.getDefault"),
        (b"getHttpProxy", "LinkProperties.getHttpProxy"),
        (b"TRANSPORT_VPN", "NetworkCapabilities.TRANSPORT_VPN"),
        (b"VpnService.prepare", "VpnService.prepare"),
    ]),
    ("proxy_api", [
        (b"java.net.ProxySelector", "ProxySelector"),
        (b"java.net.Proxy", "java.net.Proxy"),
        (b"android.net.ProxyInfo", "ProxyInfo"),
        (b"android.net.Proxy", "android.net.Proxy"),
        (b"getPacFileUrl", "ProxyInfo.getPacFileUrl"),
    ]),
    ("vpn_api", [
        (b"android.net.VpnService", "VpnService"),
        (b"VpnService", "VpnService"),
        (b"NetworkCapabilities", "NetworkCapabilities"),
        (b"hasTransport", "NetworkCapabilities.hasTransport"),
    ]),
    ("network_api", [
        (b"java.net.NetworkInterface", "NetworkInterface"),
        (b"getNetworkInterfaces", "NetworkInterface.getNetworkInterfaces"),
        (b"tun0", "interface tun0"),
        (b"ppp0", "interface ppp0"),
        (b"tap0", "interface tap0"),
    ]),
]

STATIC_PRIORITY = ["proxy_strings", "proxy_api", "vpn_api", "network_api"]

# Termos de logcat que indicam reação à presença de proxy/VPN. Termos
# genéricos ("proxy") não bastam: muitos apps os usam em mensagens de
# erro de rede.
PROXY_THREAT_PATTERNS = (
    re.compile(
        r"\b(proxy detected|detected proxy|proxy detection|untrusted proxy|"
        r"proxy is not allowed|proxy not allowed|transparent proxy|"
        r"mitm proxy|network proxy detected)\b",
        re.I,
    ),
    re.compile(
        r"\b(vpn detected|detected vpn|vpn detection|"
        r"vpn is not allowed|vpn not allowed|vpn connection detected)\b",
        re.I,
    ),
)

MODULE_COVERAGE = {
    "covered": [
        "System.getProperty (proxy.* / useSystemProxies)",
        "ProxySelector.select/getDefault",
        "android.net.Proxy.getDefaultHost/Port",
        "LinkProperties.getHttpProxy/getHttpProxyPort",
        "NetworkCapabilities.hasTransport(TRANSPORT_VPN)",
        "Settings.Global/Secure (http_proxy)",
        "NetworkInterface.getNetworkInterfaces (tun/ppp/tap)",
        "VpnService.prepare",
    ],
    "not_covered": [
        "leitura nativa de /proc/net/route",
        "getifaddrs/if_nameindex nativos",
        "verificações em código nativo do app",
    ],
}

PROXY_CHANNELS = ("proxy", "vpn", "network")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _channel_of(value: str) -> str:
    """Normaliza canais como ``proxy:proxy`` / ``proxy:vpn``."""
    text = str(value or "").lower()
    if text.endswith(":vpn") or text == "vpn":
        return "vpn"
    if text.endswith(":network") or text == "network":
        return "network"
    return "proxy"


def _is_strong_channel(channel: str) -> bool:
    return _channel_of(channel) in ("proxy", "vpn")


class AntiProxyCheck:
    """Detecção e bypass de proxy/VPN no app alvo."""

    def __init__(
        self,
        dm: object,
        mode: str = "bypass",
        no_java: bool = False,
        java_timeout: float = 30.0,
        method: str = "auto",
        xposed: Optional[XposedManager] = None,
    ) -> None:
        self.dm = dm
        self.mode = mode
        self.no_java = no_java
        self.java_timeout = java_timeout
        self.method = method
        self.xposed = xposed

    # ------------------------------------------------------------------
    # Estático
    # ------------------------------------------------------------------
    def _pull_apk(self, package_name: str, dest_dir: str) -> List[str]:
        return pull_apk(self.dm, package_name, dest_dir)

    def _scan_apk(self, apk_path: str) -> Dict[str, List[str]]:
        return scan_apk(apk_path, STATIC_SIGNATURES)

    def detect_static(
        self, package_name: str, apk_path: Optional[str] = None
    ) -> dict:
        """Detecta referências a APIs/strings de proxy/VPN no APK."""
        with tempfile.TemporaryDirectory(prefix="raspilot_apk_") as tmp:
            if apk_path:
                apks = [apk_path]
            else:
                apks = self._pull_apk(package_name, tmp)
                if not apks:
                    return {
                        "static_detected": False,
                        "types": [],
                        "primary": None,
                        "evidence": [],
                        "confidence": "none",
                        "error": f"Não foi possível obter o APK de {package_name}",
                    }
            all_found: Dict[str, List[str]] = {}
            for apk in apks:
                try:
                    found = self._scan_apk(apk)
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
                "details": "Nenhuma assinatura de proxy/VPN no APK",
            }

        chosen = sorted(
            all_found.keys(),
            key=lambda item: (
                STATIC_PRIORITY.index(item)
                if item in STATIC_PRIORITY else 99
            ),
        )[0]
        evidence = [
            f"[{item}] {detail}"
            for item, details in all_found.items()
            for detail in details
        ]
        confidence = (
            "high" if "proxy_strings" in all_found
            else "medium" if "proxy_api" in all_found or "vpn_api" in all_found
            else "low"
        )
        return {
            "static_detected": True,
            "types": sorted(all_found.keys()),
            "primary": chosen,
            "evidence": evidence,
            "confidence": confidence,
            "details": (
                f"assinaturas de proxy/VPN no APK "
                f"({', '.join(sorted(all_found.keys()))})"
            ),
        }

    # ------------------------------------------------------------------
    # Configuração dos scripts
    # ------------------------------------------------------------------
    def _script_replacements(self, mode: str) -> Dict[str, str]:
        return {
            "__RASPILOT_PROXY_MODE__": json.dumps(mode),
            "__RASPILOT_PACKAGE_NAME__": (
                getattr(self.dm, "last_spawn_package", None) or ""
            ),
        }

    def _baseline(self) -> Optional[dict]:
        value = getattr(self.dm, "baseline", None)
        return value if isinstance(value, dict) else None

    # ------------------------------------------------------------------
    # Módulo
    # ------------------------------------------------------------------
    def module_available(self) -> bool:
        if self.method == "frida" or self.xposed is None:
            return False
        try:
            return bool(self.xposed.detect().get("available"))
        except Exception:
            return False

    @staticmethod
    def _module_kind(item: dict) -> str:
        return _channel_of(item.get("channel", ""))

    def attempt_module_probe(
        self, package_name: str, window: int = 12
    ) -> dict:
        """Faz o app enxergar proxy/VPN usando o módulo do dispositivo."""
        empty = self._empty_detection("module")
        manager = self.xposed
        if manager is None:
            return {**empty, "error": "gerenciador do módulo indisponível"}
        phase = manager.run_phase(
            ModuleConfig(
                hook="bypass", proxy="probe",
                target=package_name, label="proxy-probe",
            ),
            window=window, interact=True,
        )
        run = phase.get("run") or {}
        if not run:
            return {
                **empty,
                "error": phase.get("error") or "probe do módulo falhou",
            }
        return self._detection_from_module(run, package_name)

    def attempt_module_bypass(
        self, package_name: str, window: int = 12
    ) -> dict:
        """Esconde proxy/VPN do app usando o módulo do dispositivo."""
        manager = self.xposed
        if manager is None:
            return {
                "success": None, "blocked": False,
                "app_alive_at_end": None,
                "masked_channels": [], "exposed_channels": [],
                "evidence_strength": "none",
                "error": "gerenciador do módulo indisponível",
            }
        phase = manager.run_phase(
            ModuleConfig(
                hook="bypass", proxy="bypass",
                target=package_name, label="proxy-bypass",
            ),
            window=window, interact=True,
        )
        run = phase.get("run") or {}
        if not run:
            return {
                "success": None, "blocked": False,
                "app_alive_at_end": None,
                "masked_channels": [], "exposed_channels": [],
                "evidence_strength": "none",
                "error": phase.get("error") or "bypass do módulo falhou",
            }
        return self._bypass_from_module(run, package_name)

    def _module_events(self, run: dict) -> Tuple[List[dict], List[dict], List[dict]]:
        queries: List[dict] = []
        spoofs: List[dict] = []
        masks: List[dict] = []
        for item in run.get("evidence", []):
            channel = str(item.get("channel") or "")
            if not channel.startswith("proxy"):
                continue
            kind = item.get("kind")
            if kind == "spoof":
                spoofs.append(item)
            elif kind == "mask":
                masks.append(item)
            elif kind in ("observe", "neutralize"):
                queries.append(item)
        return queries, spoofs, masks

    def _detection_from_module(self, run: dict, package_name: str) -> dict:
        empty = self._empty_detection("module")
        queries, spoofs, _ = self._module_events(run)
        found: List[str] = []
        strong: List[str] = []
        weak: List[str] = []
        channels: Dict[str, List[str]] = {name: [] for name in PROXY_CHANNELS}
        for item in queries:
            channel = self._module_kind(item)
            entry = f"{item.get('method')}: {item.get('detail')}"
            if entry not in channels[channel]:
                channels[channel].append(entry)
            if entry not in found:
                found.append(entry)
                if _is_strong_channel(channel):
                    strong.append(entry)
                else:
                    weak.append(entry)
        pid = run.get("pid")
        alive = bool(run.get("app_alive_at_end"))
        logcat = {"target_lines": list(run.get("lines") or [])}
        threat_lines = self._threat_lines(logcat)
        for line in threat_lines:
            entry = f"logcat_proxy: {line}"
            if entry not in found:
                found.append(entry)
                strong.append(entry)
        death = None if alive else "unclassified_death"
        if not alive and death in ("rasp_kill", "rasp_reaction"):
            entry = f"app_terminated: processo encerrou durante o probe ({death})"
            if entry not in found:
                found.append(entry)
                strong.append(entry)
        detected = bool(strong)
        observation_status = "ok"
        error = None
        if not alive and not strong:
            observation_status = "unclassified_death"
            error = "app encerrou durante o probe de proxy/VPN"
        return {
            **empty,
            "detected": detected,
            "detection_methods_found": found,
            "strong_signals": strong,
            "weak_signals": weak,
            "channels": channels,
            "spoofed_values": [
                f"{item.get('method')}: {item.get('detail')}"
                for item in spoofs
            ],
            "app_alive_at_end": alive,
            "observed": True,
            "observation_status": observation_status,
            "death_cause": logcat.get("death"),
            "death_classification": death,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "details": (
                f"app reagiu à presença de proxy/VPN: {'; '.join(strong[:5])}"
                if strong else (
                    "app consultou APIs de rede, sem reação"
                    if weak else "nenhuma checagem de proxy/VPN observada"
                )
            ),
            **({"error": error} if error else {}),
        }

    def _bypass_from_module(self, run: dict, package_name: str) -> dict:
        queries, _, masks = self._module_events(run)
        masked: List[str] = []
        exposed: List[str] = []
        masked_methods = {str(item.get("method") or "") for item in masks}
        for item in masks:
            entry = f"{item.get('method')}: {item.get('detail')}"
            if entry not in masked:
                masked.append(entry)
        for item in queries:
            entry = f"{item.get('method')}: {item.get('detail')}"
            method = str(item.get("method") or "")
            if method in masked_methods:
                if entry not in masked:
                    masked.append(entry)
            elif _is_strong_channel(self._module_kind(item)):
                if entry not in exposed:
                    exposed.append(entry)
            elif entry not in masked:
                masked.append(entry)
        pid = run.get("pid")
        alive = bool(run.get("app_alive_at_end"))
        logcat = {"target_lines": list(run.get("lines") or [])}
        threat_lines = self._threat_lines(logcat)
        death = None if alive else "unclassified_death"
        blocked = not alive
        signals = list(threat_lines)
        success: Optional[bool]
        if blocked:
            success = False
        elif signals or exposed:
            success = False
        elif masked:
            success = True
        else:
            success = None
        return {
            "success": success,
            "blocked": blocked,
            "app_alive_at_end": alive,
            "masked_channels": masked,
            "exposed_channels": exposed,
            "detection_signals": signals,
            "death_cause": logcat.get("death"),
            "death_classification": death,
            "logcat": logcat,
            "evidence_strength": "masked" if masked else (
                "observed" if exposed else "none"
            ),
            "details": (
                "proxy/VPN oculto do app e app sobreviveu"
                if success else (
                    "o app ainda observou proxy/VPN"
                    if exposed else (
                        "o app bloqueou o bypass" if blocked
                        else "hook de proxy/VPN instalado, sem checagem exercitada"
                    )
                )
            ),
        }

    # ------------------------------------------------------------------
    # Frida
    # ------------------------------------------------------------------
    def _empty_detection(self, method: str) -> dict:
        return {
            "detected": False,
            "detection_methods_found": [],
            "strong_signals": [],
            "weak_signals": [],
            "channels": {name: [] for name in PROXY_CHANNELS},
            "spoofed_values": [],
            "app_alive_at_end": None,
            "observed": False,
            "observation_status": "error",
            "method": method,
        }

    def _run_frida_phase(
        self, mode: str, package_name: str, window: int, interact: bool = True
    ) -> dict:
        """Executa o script Frida em ``probe``/``bypass`` e coleta eventos."""
        found: List[str] = []
        strong: List[str] = []
        weak: List[str] = []
        channels: Dict[str, List[str]] = {name: [] for name in PROXY_CHANNELS}
        spoofed: List[str] = []
        masked: List[str] = []
        notes: List[str] = []
        session = None
        script = None
        kill_script = None
        stealth_loaded: List[tuple] = []
        java_load_error: Optional[str] = None
        resumed = False
        died_after: Optional[int] = None
        pid: Optional[int] = None
        logcat_mark = get_logcat_mark(self.dm)

        def add_signal(method: str, detail: str, channel: str) -> None:
            entry = f"{method}: {detail}"
            target = channels.setdefault(_channel_of(channel), [])
            if entry not in target:
                target.append(entry)
            if entry not in found:
                found.append(entry)
                (strong if _is_strong_channel(channel) else weak).append(entry)

        def on_message(message, data):  # noqa: ANN001 - assinatura frida
            if message.get("type") == "send":
                payload = message.get("payload") or {}
                ptype = payload.get("type")
                if ptype == "proxy-detection":
                    kind = payload.get("kind", "query")
                    channel = payload.get("channel", "proxy")
                    method = payload.get("method", "?")
                    detail = payload.get("detail", "")
                    entry = f"{method}: {detail}"
                    if kind in ("note", "error", "ready"):
                        return
                    if kind in ("spoof", "mask"):
                        bucket = spoofed if kind == "spoof" else masked
                        if entry not in bucket:
                            bucket.append(entry)
                        return
                    add_signal(method, detail, channel)
                    return
                if ptype in ("proxy-note", "proxy-error"):
                    msg = payload.get("message", "")
                    if msg and msg not in notes:
                        notes.append(msg)
                    return
                if ptype == "app-kill":
                    msg = payload.get("message", "")
                    if not msg or "carregado" in msg:
                        return
                    entry = f"app-kill: {msg}"
                    if entry not in found:
                        found.append(entry)
                        strong.append(entry)
                    return
                if ptype == "raspilot-script-error":
                    msg = str(payload.get("message", ""))
                    if msg and msg not in notes:
                        notes.append(msg)
                    logger.warning("Erro no script anti-proxy: %s", msg)
                    return
            elif message.get("type") == "error":
                logger.debug(
                    "Erro no script anti-proxy: %s",
                    message.get("description"),
                )

        try:
            try:
                session = self.dm.spawn_app(package_name, resume=False)
                pid = getattr(self.dm, "last_spawn_pid", None)
                if pid is None:
                    pid = self.dm.get_app_pid(package_name)
            except Exception as exc:
                return {
                    **self._empty_detection("frida"),
                    "error": f"falha ao spawnar o app: {exc}",
                }
            try:
                stealth_loaded = load_stealth(
                    session,
                    on_message=on_message,
                    replacements=self._script_replacements(mode),
                    include_proc_filter=True,
                )
            except Exception:
                logger.debug("Stealth indisponível no anti-proxy", exc_info=True)
            if on_resume := getattr(self.dm, "resume_app", None):
                on_resume()
                resumed = True
            if self.no_java:
                java_load_error = "--no-java: hooks Java necessários ao proxy/VPN"
            else:
                try:
                    script = load_script_file(
                        session,
                        PROXY_SCRIPT,
                        on_message=on_message,
                        replacements=self._script_replacements(mode),
                        with_java_bridge=True,
                        load_timeout=self.java_timeout,
                    )
                except Exception as exc:
                    java_load_error = str(exc)
                    logger.warning("Hooks Java anti-proxy não carregaram: %s", exc)
            if java_load_error is None:
                try:
                    kill_script = load_script_file(
                        session, KILL_TRACE_SCRIPT, on_message=on_message,
                        load_timeout=3.0,
                    )
                except Exception:
                    logger.debug("kill_trace.js indisponível no anti-proxy", exc_info=True)
            if interact:
                self._start_interaction(package_name, window)
            for elapsed in range(max(1, int(window))):
                time.sleep(OBSERVATION_POLL_INTERVAL)
                if pid is not None and not self.dm.is_app_alive(pid):
                    died_after = elapsed + 1
                    break
        except Exception as exc:
            logger.warning("Falha na fase anti-proxy", exc_info=True)
            return {
                **self._empty_detection("frida"),
                "error": str(exc),
            }
        finally:
            safe_unload(script)
            safe_unload(kill_script)
            unload_stealth(stealth_loaded)
            if not resumed:
                try:
                    self.dm.resume_app()
                except Exception:
                    logger.debug("Falha no resume de emergência", exc_info=True)
            safe_detach(session)

        if died_after is None and pid is not None:
            try:
                if not self.dm.is_app_alive(pid):
                    died_after = max(1, int(window))
            except Exception:
                logger.debug("Falha na rechecagem de vida", exc_info=True)
        alive = died_after is None
        logcat = analyze_since(self.dm, logcat_mark, package_name, pid)
        baseline = self._baseline()
        threat_lines = self._threat_lines(logcat)
        for line in threat_lines:
            add_signal("logcat_proxy", line, "proxy")
        death = self._classify_death(logcat, baseline, alive)
        if not alive and death in ("rasp_kill", "rasp_reaction"):
            add_signal(
                "app_terminated",
                f"processo encerrou ~{died_after}s após resume ({death})",
                "proxy",
            )
        observation_status = "ok"
        error: Optional[str] = None
        if not alive and death == "instrumentation_crash" and not strong:
            observation_status = "instrumentation_crash"
            error = "o app derrubou o agente antes da checagem de proxy/VPN"
        elif not alive and death == "baseline_death" and not strong:
            observation_status = "baseline_death"
            error = "app encerrou no baseline sem instrumentação"
        elif java_load_error and not strong:
            observation_status = "error"
            error = f"hooks Java de proxy/VPN não carregaram: {java_load_error}"
        return {
            "detected": bool(strong),
            "detection_methods_found": found,
            "strong_signals": strong,
            "weak_signals": weak,
            "channels": channels,
            "spoofed_values": spoofed,
            "masked_channels": masked,
            "app_alive_at_end": alive,
            "died_after": died_after,
            "observed": True,
            "observation_status": observation_status,
            "death_cause": logcat.get("death"),
            "death_classification": death,
            "baseline": baseline,
            "logcat": logcat,
            "logcat_evidence": format_evidence(logcat),
            "java_load_error": java_load_error,
            "notes": notes,
            "mode": mode,
            "details": (
                f"app reagiu à presença de proxy/VPN: {'; '.join(strong[:5])}"
                if strong else (
                    "app consultou APIs de rede, sem reação"
                    if weak else "nenhuma checagem de proxy/VPN observada"
                )
            ),
            **({"error": error} if error else {}),
        }

    def check_detection_in_app(
        self,
        package_name: str,
        window: int = 12,
        interact: bool = True,
    ) -> dict:
        """Observa o app com proxy/VPN simulado via Frida."""
        return self._run_frida_phase("probe", package_name, window, interact)

    def attempt_bypass(
        self, package_name: str, window: int = 12, interact: bool = True
    ) -> dict:
        """Esconde proxy/VPN do app via Frida."""
        phase = self._run_frida_phase("bypass", package_name, window, interact)
        alive = bool(phase.get("app_alive_at_end"))
        masked = list(phase.get("masked_channels") or [])
        exposed = [
            item for item in phase.get("strong_signals") or []
        ]
        death = phase.get("death_classification")
        # Uma morte causada pelo agente (anti-Frida) não é resistência da
        # proteção de proxy: o bypass não chegou a ser avaliado.
        blocked = (
            phase.get("app_alive_at_end") is False
            and death not in ("instrumentation_crash", "baseline_death")
        )
        if phase.get("error") and not phase.get("observed"):
            success: Optional[bool] = None
        elif death in ("instrumentation_crash", "baseline_death"):
            success = None
        elif blocked:
            success = False
        elif exposed:
            success = False
        elif masked:
            success = True
        else:
            success = None
        return {
            "success": success,
            "blocked": blocked,
            "app_alive_at_end": alive,
            "masked_channels": masked,
            "exposed_channels": exposed,
            "detection_signals": list(phase.get("strong_signals") or []),
            "death_cause": phase.get("death_cause"),
            "death_classification": phase.get("death_classification"),
            "logcat": phase.get("logcat"),
            "evidence_strength": "masked" if masked else (
                "observed" if exposed else "none"
            ),
            "details": (
                "proxy/VPN oculto do app e app sobreviveu"
                if success else (
                    "o app ainda observou proxy/VPN"
                    if exposed else (
                        "o app bloqueou o bypass" if blocked
                        else "hook de proxy/VPN instalado, sem checagem exercitada"
                    )
                )
            ),
            **({"error": phase["error"]} if phase.get("error") else {}),
        }

    def _start_interaction(self, package_name: str, window: int) -> None:
        driver = getattr(self.dm, "drive_ui", None)
        use_drive = callable(driver)
        if not use_drive:
            driver = getattr(self.dm, "simulate_interaction", None)
        if not callable(driver):
            return

        def _drive() -> None:
            try:
                if use_drive:
                    driver(package_name, taps=4, timeout=max(30, window * 2))
                else:
                    driver(package_name, events=25, timeout=max(30, window * 2))
            except Exception:
                logger.debug("Interação anti-proxy falhou", exc_info=True)

        threading.Thread(
            target=_drive, name="raspilot-proxy-interact", daemon=True
        ).start()

    # ------------------------------------------------------------------
    # Logcat / morte
    # ------------------------------------------------------------------
    @staticmethod
    def _threat_lines(logcat: dict) -> List[str]:
        candidates: List[str] = []
        for key in ("target_lines", "vendor_signals"):
            for item in logcat.get(key, []) or []:
                candidates.append(str(item))
        lines: List[str] = []
        for line in candidates:
            if any(pattern.search(line) for pattern in PROXY_THREAT_PATTERNS):
                if line not in lines:
                    lines.append(line)
        return lines[:10]

    def _classify_death(
        self, logcat: dict, baseline: Optional[dict], app_alive: bool
    ) -> Optional[str]:
        if app_alive:
            return None
        baseline_died = bool(
            baseline and baseline.get("available")
            and baseline.get("alive_at_end") is False
        )
        baseline_healthy = bool(
            baseline and baseline.get("available")
            and baseline.get("alive_at_end") is True
        )
        if baseline_died:
            return "baseline_death"
        if logcat.get("agent_terminated"):
            return "instrumentation_crash"
        if any(
            category in (logcat.get("categories") or {})
            for category in HIGH_CONFIDENCE_CATEGORIES
        ):
            return "rasp_reaction"
        death = logcat.get("death") or {}
        if logcat.get("available") and death.get("kind") in ("crash", "anr"):
            if baseline_healthy and logcat.get("crash_origin") != "instrumentation":
                return "rasp_reaction"
            return "instrumentation_crash"
        return "unclassified_death"

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
        static_profile: Optional[dict] = None,
    ) -> dict:
        """Combina detecção estática, probe e bypass de proxy/VPN."""
        static_view = vector_view(static_profile, "proxy")
        if static_view is not None:
            static = merge_signature_detection({}, static_view)
            static["details"] = (
                static.get("details") or "análise estática do perfil do APK"
            )
        else:
            static = self.detect_static(package_name, apk_path=apk_path)
        static_analysis = (
            {
                "engine": static_view.get("engine"),
                "version": static_view.get("version"),
                "vector": "proxy",
                "present": bool(
                    static_view.get(
                        "effective", static_view.get("present")
                    )
                ),
                "confidence": static_view.get("confidence"),
                "owners": static_view.get("owners") or {},
                "app_evidence": bool(static_view.get("app_evidence")),
                "coverage": static_view.get("coverage"),
            }
            if static_view is not None
            else None
        )

        app_detection: dict
        probe_method = "frida"
        if precomputed_detection is not None:
            app_detection = dict(precomputed_detection)
        elif self.module_available():
            probe_method = "module"
            app_detection = self.attempt_module_probe(
                package_name, window=window
            )
        else:
            app_detection = self.check_detection_in_app(
                package_name, window=window
            )

        static_present = bool(static.get("static_detected"))
        dynamic_detected = bool(app_detection.get("detected"))
        protection_detected = static_present or dynamic_detected

        phase_errors: List[str] = []
        if not protection_detected and app_detection.get("error"):
            phase_errors.append(f"dinâmico: {app_detection['error']}")
            if static.get("error"):
                phase_errors.append(f"estático: {static['error']}")

        bypass_details: Optional[dict] = None
        bypass_successful: Optional[bool] = None
        bypass_skipped_reason: Optional[str] = None
        bypass_method = "frida"
        if self.mode == "detect":
            bypass_skipped_reason = "modo detect: bypass não executado"
        elif self.no_java and probe_method == "frida":
            bypass_skipped_reason = (
                "--no-java: hooks Java necessários ao bypass de proxy/VPN"
            )
        elif protection_detected:
            if precomputed_bypass is not None:
                bypass_details = dict(precomputed_bypass)
                bypass_method = str(
                    precomputed_bypass.get("method") or "frida"
                )
            elif self.module_available():
                bypass_method = "module"
                bypass_details = self.attempt_module_bypass(
                    package_name, window=window
                )
            else:
                bypass_details = self.attempt_bypass(
                    package_name, window=window
                )
            if bypass_details.get("blocked"):
                bypass_successful = False
            elif bypass_details.get("success") is True:
                bypass_successful = True
            elif bypass_details.get("exposed_channels"):
                bypass_successful = False
            elif bypass_details.get("success") is False:
                bypass_successful = False
            else:
                bypass_successful = None
                bypass_skipped_reason = (
                    "bypass não exercitado: o app não consultou proxy/VPN "
                    "na janela"
                )
            if bypass_details.get("error") and bypass_successful is None:
                bypass_skipped_reason = (
                    f"bypass: {bypass_details['error']}"
                )

        status_hint: Optional[str] = None
        verdict_reason: Optional[str] = None
        if not protection_detected:
            if phase_errors:
                status_hint = "ERROR"
                verdict_reason = "; ".join(phase_errors)
            else:
                status_hint = "FALHOU"
                verdict_reason = (
                    "nenhuma referência ou checagem de proxy/VPN observada"
                )
        elif bypass_successful is True:
            status_hint = "FALHOU"
            verdict_reason = (
                "detecção de proxy/VPN contornada: o app permaneceu utilizável"
            )
        elif bypass_successful is False:
            status_hint = "OK"
            verdict_reason = "a proteção de proxy/VPN resistiu ao bypass"
        else:
            status_hint = "SKIP"
            verdict_reason = (
                bypass_skipped_reason or "bypass de proxy/VPN não avaliado"
            )
        if app_detection.get("error") and not protection_detected:
            status_hint = "ERROR"
            verdict_reason = app_detection["error"]

        protection_sources: List[str] = []
        if static_present:
            protection_sources.append("static_apk")
        if dynamic_detected:
            protection_sources.append("dynamic")
        if probe_method == "module":
            protection_sources.append("module")
        if static_analysis and static_analysis.get("present"):
            protection_sources.append("static_asc")

        proxy_detected = any(
            "proxy" in str(item).lower()
            for item in app_detection.get("strong_signals") or []
        )
        vpn_detected = any(
            "vpn" in str(item).lower()
            for item in app_detection.get("strong_signals") or []
        )

        result = {
            "protection_detected": protection_detected,
            "proxy_detected": proxy_detected,
            "vpn_detected": vpn_detected,
            "bypass_successful": bypass_successful,
            "bypass_method": bypass_method if bypass_details else None,
            "bypass_skipped_reason": bypass_skipped_reason,
            "bypass_details": bypass_details,
            "probe_method": probe_method,
            "protection_sources": protection_sources,
            "static_detection": static,
            "static_analysis": static_analysis,
            "app_detection": app_detection,
            "evidence_strength": (
                (bypass_details or {}).get("evidence_strength")
                if bypass_details else None
            ),
            "device_coverage": MODULE_COVERAGE if probe_method == "module" else None,
            "status_hint": status_hint,
            "verdict_reason": verdict_reason,
            "timestamp": _now_iso(),
        }
        if status_hint == "ERROR":
            result["error"] = verdict_reason
        return result
