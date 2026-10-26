"""RASPilot — Gerenciador do módulo de instrumentação via framework Xposed.

O módulo (um APK) é compilado, instalado e limitado ao pacote alvo
informado em ``--package``. Com o módulo ativo o app é executado **sem
instrumentação externa**: o framework de hooking do próprio dispositivo
aplica, dentro do processo do app, as camadas de neutralização de
anti-hook e de spoofing de emulador.

Isso muda a natureza da medição: o alvo não enxerga um agente de
instrumentação inyectado do host, e sim um framework de hooking nativo do
sistema — que é exatamente o ambiente que a proteção anti-hook pretende
detectar.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:  # evita import circular em tempo de importação
    from device_manager import DeviceManager

logger = logging.getLogger("raspilot.instrumentation")

# Pacote do módulo de instrumentação.
MODULE_PACKAGE = "com.raspilot.module"

# Raiz do pacote de instrumentação (fontes, build e artefatos).
INSTRUMENTATION_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_SRC_DIR = os.path.join(INSTRUMENTATION_DIR, "xposed")
BUILD_SCRIPT = os.path.join(INSTRUMENTATION_DIR, "build.sh")
BUILD_DIR = os.path.join(INSTRUMENTATION_DIR, "build")

# Clis de frameworks de hooking conhecidos, em ordem de preferência.
FRAMEWORK_CLIS: Tuple[str, ...] = (
    "/data/adb/modules/zygisk_vector/cli",
    "/data/adb/modules/zygisk_lsposed/cli",
    "/data/adb/modules/edxposed/cli",
    "/data/adb/modules/riru_lsposed/cli",
)

# Diretórios de módulos que indicam a presença de um framework de hooking.
FRAMEWORK_MODULE_DIRS: Tuple[str, ...] = (
    "zygisk_vector",
    "zygisk_lsposed",
    "edxposed",
    "riru_lsposed",
    "riru",
)

# Propriedade do sistema usada para reconfigurar o módulo em execução.
RUNTIME_PROPERTY = "persist.raspilot.module.config"

# Padrão das linhas de evidência emitidas pelo módulo.
EVIDENCE_PATTERN = re.compile(
    r"EVT\|(?P<kind>[^|]*)\|(?P<channel>[^|]*)\|(?P<method>[^|]*)\|(?P<detail>.*)$"
)

# Tag usada pelo módulo no logcat.
MODULE_TAG = "RASPilotModule"

# Trechos que denunciam a presença do framework no processo alvo.
FRAMEWORK_ARTIFACT_TOKENS: Tuple[str, ...] = (
    "xposed",
    "lsposed",
    "lspd",
    "lsplant",
    "vector",
    "edxposed",
    "riru",
    "sandhook",
    "yahfa",
    "dobby",
)

# Intervalo entre as consultas de vida do app durante a janela.
POLL_INTERVAL = 1.0


class XposedError(Exception):
    """Erro operacional do gerenciador do módulo."""


@dataclass
class ModuleConfig:
    """Configuração do módulo para uma execução.

    Attributes:
        hook: Modo da camada anti-hook (``off``, ``observe``, ``bypass``).
        emulator: Modo da camada de emulador (``off``, ``observe``,
            ``probe``, ``mask``).
        target: Pacote alvo (vazio = qualquer pacote no escopo).
        label: Rótulo da execução, usado na correlação de evidência.
    """

    hook: str = "off"
    emulator: str = "off"
    target: str = ""
    label: str = ""

    def as_property(self) -> str:
        """Serializa a configuração para a propriedade do sistema.

        Returns:
            String no formato ``chave=valor;chave=valor``.
        """
        parts = [
            f"hook={self.hook}",
            f"emu={self.emulator}",
            f"target={self.target}",
            f"label={self.label}",
        ]
        return ";".join(parts)

    def as_build_args(self) -> List[str]:
        """Argumentos do script de build para esta configuração.

        Returns:
            Lista de argumentos prontos para o ``build.sh``.
        """
        return [
            "--hook", self.hook,
            "--emu", self.emulator,
            "--target", self.target,
            "--label", self.label,
        ]

    def fingerprint(self) -> str:
        """Identificador estável da configuração.

        Returns:
            Hash hexadecimal da configuração.
        """
        return hashlib.sha256(self.as_property().encode("utf-8")).hexdigest()[:12]


class XposedManager:
    """Prepara e executa o módulo de instrumentação no dispositivo."""

    @staticmethod
    def _source_digest() -> str:
        """Hash dos fontes do módulo, para invalidar builds antigos.

        O cache era indexado apenas pela configuração (hook/emu/target):
        uma mudança no código Java reutilizava o APK anterior e o
        dispositivo continuava executando a versão antiga do módulo.

        Returns:
            SHA-256 (primeiros 12 hex) de todos os arquivos-fonte, ou
            ``"nosrc"`` quando o diretório não existe.
        """
        digest = hashlib.sha256()
        try:
            for root, _, files in os.walk(MODULE_SRC_DIR):
                for name in sorted(files):
                    path = os.path.join(root, name)
                    digest.update(os.path.relpath(path, MODULE_SRC_DIR).encode())
                    try:
                        with open(path, "rb") as fh:
                            digest.update(fh.read())
                    except OSError:
                        continue
        except OSError:
            return "nosrc"
        return digest.hexdigest()[:12] or "nosrc"

    def __init__(
        self,
        dm: "DeviceManager",
        package_name: str,
        apk_path: Optional[str] = None,
        sdk_root: Optional[str] = None,
        java_home: Optional[str] = None,
        keep_installed: bool = False,
    ) -> None:
        """Inicializa o gerenciador.

        Args:
            dm: Gerenciador de dispositivo conectado.
            package_name: Pacote alvo da auditoria.
            apk_path: APK pré-construído (dispensa o build).
            sdk_root: Raiz do SDK do Android usada no build.
            java_home: JDK usado no build.
            keep_installed: Se True, o módulo permanece instalado no
                cleanup.
        """
        self.dm = dm
        self.package_name = package_name
        self.apk_path = apk_path
        self.sdk_root = sdk_root or os.environ.get("ANDROID_HOME") or os.environ.get(
            "ANDROID_SDK_ROOT"
        ) or os.path.expanduser("~/Android")
        self.java_home = java_home or os.environ.get("JAVA_HOME") or os.path.join(
            self.sdk_root, "jdk"
        )
        self.keep_installed = keep_installed

        self.framework: Dict[str, object] = {}
        self.cli_path: Optional[str] = None
        self.installed = False
        self.installed_apk: Optional[str] = None
        self.enabled_by_us = False
        self.original_scope: List[str] = []
        self.scope_applied = False
        self.last_error: Optional[str] = None
        self.apk_built: Optional[str] = None

    # ------------------------------------------------------------------
    # Detecção do framework
    # ------------------------------------------------------------------
    def detect(self) -> dict:
        """Detecta o framework de hooking instalado no dispositivo.

        Returns:
            Dict com ``available`` (bool), ``cli`` (caminho), ``name``,
            ``version`` e ``details``.
        """
        if self.framework:
            return self.framework

        result: Dict[str, object] = {
            "available": False,
            "cli": None,
            "name": None,
            "version": None,
            "details": "",
        }

        listing = self.dm.run_shell_root(
            "ls /data/adb/modules 2>/dev/null", timeout=15
        )
        modules = [
            line.strip()
            for line in (listing.get("stdout") or "").splitlines()
            if line.strip()
        ]
        found = [name for name in modules if name in FRAMEWORK_MODULE_DIRS]
        result["modules"] = found
        if found:
            result["details"] = f"módulos de framework: {', '.join(found)}"

        for candidate in FRAMEWORK_CLIS:
            probe = self.dm.run_shell_root(
                f"test -x {shlex.quote(candidate)} && echo yes", timeout=10
            )
            if "yes" in (probe.get("stdout") or ""):
                self.cli_path = candidate
                break

        if self.cli_path is None:
            if not found:
                result["details"] = (
                    result["details"] + "; " if result["details"] else ""
                ) + "nenhum framework de hooking detectado"
                self.framework = result
                return result
            # Há framework, mas sem cli utilizável: a configuração de
            # escopo pode ainda ser feita pelo banco de dados do
            # framework, tratado como indisponível aqui.
            result["details"] = (
                result["details"] + "; " if result["details"] else ""
            ) + "framework sem cli de configuração"
            self.framework = result
            return result

        status = self._cli(["status"])
        if status.get("ok"):
            name, version = _parse_status(status.get("stdout") or "")
            result["name"] = name or _framework_name(found)
            result["version"] = version
            result["available"] = True
            result["details"] = (
                f"{result['name'] or 'framework'} {version or ''}".strip()
                + (f" ({result['details']})" if result.get("details") else "")
            )
        self.framework = result
        logger.info(
            "Framework de hooking: available=%s cli=%s nome=%s",
            result["available"], self.cli_path, result.get("name"),
        )
        return result

    # ------------------------------------------------------------------
    # Operação via cli do framework
    # ------------------------------------------------------------------
    def _cli(self, args: List[str]) -> dict:
        """Executa o cli do framework de hooking.

        Args:
            args: Argumentos do cli.

        Returns:
            Dict ``{'ok', 'stdout', 'stderr'}``.
        """
        if not self.cli_path:
            return {"ok": False, "stdout": "", "stderr": "cli do framework indisponível"}
        command = " ".join(
            [shlex.quote(self.cli_path)] + [shlex.quote(arg) for arg in args]
        )
        res = self.dm.run_shell_root(command, timeout=30)
        return {
            "ok": bool(res.get("ok")),
            "stdout": res.get("stdout") or "",
            "stderr": res.get("stderr") or "",
        }

    def _cli_json(self, args: List[str]) -> dict:
        """Executa o cli do framework pedindo saída em JSON.

        Args:
            args: Argumentos do cli.

        Returns:
            Dict com ``ok`` e ``data`` (payload parseado ou ``None``).
        """
        res = self._cli(["--json"] + args)
        if not res.get("ok"):
            return {"ok": False, "data": None, "stdout": res.get("stdout", "")}
        try:
            payload = json.loads(res.get("stdout") or "{}")
        except (ValueError, TypeError):
            return {"ok": False, "data": None, "stdout": res.get("stdout", "")}
        return {"ok": bool(payload.get("success", True)), "data": payload.get("data"),
                "stdout": res.get("stdout", "")}

    def scope_list(self, module: str = MODULE_PACKAGE) -> List[str]:
        """Lista os pacotes no escopo de um módulo.

        Args:
            module: Pacote do módulo.

        Returns:
            Lista de pacotes no escopo (vazia se indisponível).
        """
        payload = self._cli_json(["scope", "ls", module])
        entries = payload.get("data")
        if isinstance(entries, list):
            packages = []
            for item in entries:
                if isinstance(item, dict):
                    name = item.get("APP_PACKAGE")
                    if name:
                        packages.append(str(name))
                elif isinstance(item, str):
                    packages.append(item)
            return packages
        res = self._cli(["scope", "ls", module])
        packages = []
        for line in (res.get("stdout") or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] not in ("APP_PACKAGE",) and not set(
                parts[0]
            ) <= {"-"}:
                packages.append(parts[0])
        return packages

    def set_scope(self, packages: List[str]) -> dict:
        """Substitui o escopo de um módulo.

        Args:
            packages: Pacotes que passam a receber o módulo.

        Returns:
            Dict ``{'ok', 'detail'}``.
        """
        if not packages:
            return {"ok": False, "detail": "escopo vazio"}
        entries = [f"{pkg}/0" for pkg in packages]
        res = self._cli(["scope", "set", MODULE_PACKAGE] + entries)
        return {
            "ok": bool(res.get("ok")),
            "detail": (res.get("stdout") or res.get("stderr") or "").strip(),
        }

    def module_enabled(self, module: str = MODULE_PACKAGE) -> Optional[bool]:
        """Informa se um módulo está habilitado no framework.

        Args:
            module: Pacote do módulo.

        Returns:
            True/False quando o estado é conhecido, None caso contrário.
        """
        payload = self._cli_json(["modules", "ls"])
        data = payload.get("data")
        rows: List[str] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rows.append(" ".join(str(v) for v in item.values()))
                elif isinstance(item, str):
                    rows.append(item)
        else:
            res = self._cli(["modules", "ls"])
            rows = (res.get("stdout") or "").splitlines()
        for row in rows:
            if module in row:
                lowered = row.lower()
                if "enabled" in lowered and "disabled" not in lowered:
                    return True
                if "disabled" in lowered:
                    return False
        return None

    def enable_module(self) -> dict:
        """Habilita o módulo no framework.

        Returns:
            Dict ``{'ok', 'detail'}``.
        """
        res = self._cli(["modules", "enable", MODULE_PACKAGE])
        failed = _failed_entries(res.get("stdout") or "")
        return {
            "ok": bool(res.get("ok")) and not failed,
            "detail": (res.get("stdout") or res.get("stderr") or "").strip(),
        }

    def disable_module(self) -> dict:
        """Desabilita o módulo no framework.

        Returns:
            Dict ``{'ok', 'detail'}``.
        """
        res = self._cli(["modules", "disable", MODULE_PACKAGE])
        failed = _failed_entries(res.get("stdout") or "")
        return {
            "ok": bool(res.get("ok")) and not failed,
            "detail": (res.get("stdout") or res.get("stderr") or "").strip(),
        }

    def scoped_modules_for(self, package: str) -> List[Dict[str, object]]:
        """Lista os módulos do framework ativos no escopo do pacote alvo.

        Outros módulos no escopo do alvo também são injetados no
        processo durante as fases do módulo: eles podem alterar o
        resultado da medição e precisam ficar visíveis no relatório.

        Args:
            package: Pacote alvo.

        Returns:
            Lista de dicts ``{'package', 'status'}`` dos módulos
            encontrados.
        """
        payload = self._cli_json(["modules", "ls"])
        data = payload.get("data")
        rows: List[Dict[str, object]] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rows.append({
                        "package": str(item.get("PACKAGE") or ""),
                        "status": str(item.get("STATUS") or ""),
                    })
        else:
            res = self._cli(["modules", "ls"])
            for line in (res.get("stdout") or "").splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] not in ("PACKAGE",) and not set(
                    parts[0]
                ) <= {"-"}:
                    rows.append({"package": parts[0], "status": parts[-1]})

        found: List[Dict[str, object]] = []
        for row in rows:
            name = str(row.get("package") or "")
            if not name or name == MODULE_PACKAGE:
                continue
            status = str(row.get("status") or "").lower()
            if "enabled" not in status or "disabled" in status:
                continue
            if package in self.scope_list(name):
                found.append({"package": name, "status": status})
        return found

    # ------------------------------------------------------------------
    # Build e instalação
    # ------------------------------------------------------------------
    def build(self, config: ModuleConfig) -> dict:
        """Compila o módulo para a configuração informada.

        Args:
            config: Configuração desejada.

        Returns:
            Dict ``{'ok', 'apk', 'detail'}``.
        """
        if self.apk_path:
            return {"ok": os.path.exists(self.apk_path), "apk": self.apk_path,
                    "detail": "APK pré-construído"}

        if not os.path.exists(BUILD_SCRIPT):
            return {"ok": False, "apk": None,
                    "detail": f"script de build ausente: {BUILD_SCRIPT}"}
        if not os.path.isdir(MODULE_SRC_DIR):
            return {"ok": False, "apk": None,
                    "detail": f"fontes do módulo ausentes: {MODULE_SRC_DIR}"}

        # A configuração identifica o comportamento; o hash dos fontes
        # garante que uma mudança no módulo gere um APK novo em vez de
        # reutilizar silenciosamente o build anterior.
        source_digest = self._source_digest()
        out_dir = os.path.join(
            BUILD_DIR, f"{config.fingerprint()}-{source_digest}"
        )
        apk = os.path.join(out_dir, "raspilot-module.apk")
        if os.path.exists(apk):
            self.apk_built = apk
            return {"ok": True, "apk": apk, "detail": "build reaproveitado"}

        env = dict(os.environ)
        env["ANDROID_HOME"] = self.sdk_root
        env["ANDROID_SDK_ROOT"] = self.sdk_root
        if os.path.isdir(self.java_home):
            env["JAVA_HOME"] = self.java_home
            env["PATH"] = f"{os.path.join(self.java_home, 'bin')}:{env.get('PATH', '')}"

        cmd = ["bash", BUILD_SCRIPT] + config.as_build_args() + ["--out", apk]
        try:
            proc = subprocess.run(
                cmd, env=env, capture_output=True, text=True, timeout=600, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "apk": None, "detail": f"falha no build: {exc}"}

        if proc.returncode != 0 or not os.path.exists(apk):
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            tail = " | ".join(detail[-3:]) if detail else "sem saída"
            return {"ok": False, "apk": None, "detail": f"build falhou: {tail}"}

        self.apk_built = apk
        logger.info("Módulo compilado: %s", apk)
        return {"ok": True, "apk": apk, "detail": "build concluído"}

    def install(self, apk: str) -> dict:
        """Instala (ou atualiza) o módulo no dispositivo.

        A instalação é refeita apenas quando o APK mudou: reinstalar a
        cada fase tornaria o pipeline lento sem ganho.

        Args:
            apk: Caminho do APK.

        Returns:
            Dict ``{'ok', 'detail'}``.
        """
        if self.installed and self.installed_apk == apk:
            return {"ok": True, "detail": "APK já instalado"}
        cmd = ["adb"]
        device_id = getattr(self.dm, "device_id", None)
        if device_id:
            cmd += ["-s", device_id]
        cmd += ["install", "-r", "-g", apk]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "detail": f"falha na instalação: {exc}"}
        output = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0 and "Success" in output
        if ok:
            self.installed = True
            self.installed_apk = apk
        return {"ok": ok, "detail": output.strip()}

    def uninstall(self) -> dict:
        """Remove o módulo do dispositivo.

        Returns:
            Dict ``{'ok', 'detail'}``.
        """
        cmd = ["adb"]
        device_id = getattr(self.dm, "device_id", None)
        if device_id:
            cmd += ["-s", device_id]
        cmd += ["uninstall", MODULE_PACKAGE]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=180, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "detail": f"falha na remoção: {exc}"}
        self.installed = False
        return {
            "ok": proc.returncode == 0,
            "detail": ((proc.stdout or "") + (proc.stderr or "")).strip(),
        }

    # ------------------------------------------------------------------
    # Configuração em execução
    # ------------------------------------------------------------------
    def apply_runtime_config(self, config: ModuleConfig) -> dict:
        """Aplica a configuração via propriedade do sistema.

        A propriedade é lida pelo módulo no início do processo: isso
        permite trocar de fase sem reinstalar o APK.

        Args:
            config: Configuração desejada.

        Returns:
            Dict ``{'ok', 'detail'}``.
        """
        value = config.as_property()
        command = (
            f"setprop {shlex.quote(RUNTIME_PROPERTY)} {shlex.quote(value)}"
        )
        res = self.dm.run_shell_root(command, timeout=15)
        ok = bool(res.get("ok"))
        detail = (res.get("stderr") or "").strip()
        if ok:
            check = self.dm.run_shell_root(
                f"getprop {shlex.quote(RUNTIME_PROPERTY)}", timeout=10
            )
            current = (check.get("stdout") or "").strip()
            ok = current == value
            if not ok:
                detail = f"propriedade não confirmada (valor atual: {current!r})"
        return {"ok": ok, "detail": detail or "propriedade aplicada"}

    # ------------------------------------------------------------------
    # Preparação e execução
    # ------------------------------------------------------------------
    def prepare(self, config: ModuleConfig) -> dict:
        """Prepara o módulo: build, instalação, habilitação e escopo.

        Args:
            config: Configuração desejada.

        Returns:
            Dict com ``ok``, ``steps`` (lista de detalhes) e ``error``.
        """
        steps: List[Dict[str, object]] = []
        framework = self.detect()
        if not framework.get("available"):
            return {
                "ok": False,
                "steps": steps,
                "error": framework.get("details") or "framework de hooking indisponível",
            }
        steps.append({"step": "framework", "ok": True,
                      "detail": framework.get("details")})

        build = self.build(config)
        steps.append({"step": "build", "ok": build["ok"], "detail": build["detail"]})
        if not build["ok"]:
            return {"ok": False, "steps": steps, "error": build["detail"]}

        install = self.install(build["apk"])
        steps.append({"step": "install", "ok": install["ok"], "detail": install["detail"]})
        if not install["ok"]:
            return {"ok": False, "steps": steps, "error": install["detail"]}

        self.original_scope = self.scope_list()
        enable = self.enable_module()
        steps.append({"step": "enable", "ok": enable["ok"], "detail": enable["detail"]})
        if not enable["ok"]:
            return {"ok": False, "steps": steps, "error": enable["detail"]}
        self.enabled_by_us = True

        scope = self.set_scope([self.package_name])
        self.scope_applied = scope["ok"]
        steps.append({"step": "scope", "ok": scope["ok"], "detail": scope["detail"]})
        if not scope["ok"]:
            return {"ok": False, "steps": steps, "error": scope["detail"]}

        runtime = self.apply_runtime_config(config)
        steps.append({"step": "config", "ok": runtime["ok"], "detail": runtime["detail"]})
        if not runtime["ok"]:
            # Sem override em execução, o comportamento do módulo é o
            # compilado no APK: só é equivalente se coincidir.
            fallback = self.build(ModuleConfig(
                hook=config.hook, emulator=config.emulator,
                target=config.target, label=config.label,
            ))
            steps.append({"step": "config_fallback", "ok": fallback["ok"],
                          "detail": fallback["detail"]})
            if fallback["ok"]:
                reinstall = self.install(fallback["apk"])
                steps.append({"step": "reinstall", "ok": reinstall["ok"],
                              "detail": reinstall["detail"]})
                if not reinstall["ok"]:
                    return {"ok": False, "steps": steps,
                            "error": reinstall["detail"]}

        return {"ok": True, "steps": steps, "error": None}

    def launch(self, window: int = 12, interact: bool = False) -> dict:
        """Executa o app alvo sem instrumentação externa e coleta a
        evidência emitida pelo módulo.

        Args:
            window: Janela de observação em segundos.
            interact: Quando True, dispara eventos de entrada ao app
                durante a janela. Proteções costumam rodar checagens de
                segurança em interação do usuário (lançamento de telas,
                toques); sem interação, uma parte delas não é exercitada
                na janela.

        Returns:
            Dict com ``pid``, ``app_alive_at_end``, ``died_after``,
            ``evidence``, ``neutralized``, ``observed``, ``contexts``,
            ``module_ready``, ``effective_config`` e ``error``.
        """
        mark = self.dm.logcat_mark()
        self.dm.run_shell(f"am force-stop {self.package_name}", timeout=20)
        time.sleep(1)

        launcher = self._start_interaction() if interact else None

        launch = self.dm.run_shell(
            f"monkey -p {self.package_name} -c android.intent.category.LAUNCHER 1",
            timeout=30,
        )
        if not launch.get("ok"):
            fallback = self._launch_activity()
            launch = fallback

        pid = self.dm.get_app_pid(self.package_name)
        died_after: Optional[int] = None
        elapsed = 0
        while elapsed < max(1, int(window)):
            time.sleep(POLL_INTERVAL)
            elapsed += 1
            if pid is not None and not self.dm.is_app_alive(pid):
                died_after = elapsed
                break

        lines = self.dm.logcat_since(mark)
        evidence = parse_evidence(lines)
        ready = [item for item in evidence if item["kind"] == "ready"]
        effective = _parse_ready(ready[-1]["detail"]) if ready else {}
        neutralized, observed, contexts = partition_evidence(evidence)

        alive = died_after is None
        result = {
            "pid": pid,
            "app_alive_at_end": alive,
            "died_after": died_after,
            "evidence": evidence,
            "lines": lines,
            "neutralized": neutralized,
            "observed": observed,
            "contexts": contexts,
            "module_ready": bool(ready),
            "effective_config": effective,
            "launch_output": (launch.get("stdout") or "")[:400],
            "interact": bool(interact),
            "error": None,
        }
        if not ready:
            result["error"] = (
                "o módulo não foi carregado no processo alvo — o escopo do "
                "framework não foi aplicado"
            )
        if launcher is not None and not launcher.is_alive():
            result["interaction_error"] = str(
                getattr(launcher, "error", None) or ""
            ) or None
        return result

    def _start_interaction(self) -> threading.Thread:
        """Dispara a simulação de interação em paralelo à janela.

        A simulação roda em thread daemon: uma falha aqui é registrada
        no retorno da fase e não derruba a observação — o resultado
        inconclusivo persiste, mas a evidência continua sendo coletada.

        Returns:
            Thread criada (para diagnóstico no retorno).
        """
        def run() -> None:
            try:
                time.sleep(2.0)
                self.dm.simulate_interaction(self.package_name)
            except Exception as exc:  # pragma: no cover - proteção
                run.error = exc  # type: ignore[attr-defined]

        run.error = None  # type: ignore[attr-defined]
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def _launch_activity(self) -> dict:
        """Inicia o app pela atividade principal resolvida.

        Returns:
            Dict no formato de :meth:`DeviceManager.run_shell`.
        """
        resolve = self.dm.run_shell(
            f"cmd package resolve-activity --brief {self.package_name} 2>/dev/null",
            timeout=20,
        )
        activity = ""
        for line in (resolve.get("stdout") or "").splitlines():
            line = line.strip()
            if "/" in line and " " not in line:
                activity = line
        if not activity:
            return {"ok": False, "stdout": "", "stderr": "atividade não resolvida"}
        return self.dm.run_shell(f"am start -n {activity}", timeout=30)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup(self) -> List[Dict[str, object]]:
        """Restaura o escopo e desabilita o módulo.

        O APK permanece instalado: ele pode ser reutilizado na fase
        seguinte. Use :meth:`finish` para removê-lo do dispositivo.

        Returns:
            Lista de detalhes das ações executadas.
        """
        actions: List[Dict[str, object]] = []
        if self.scope_applied:
            if self.original_scope:
                restore = self.set_scope(self.original_scope)
            else:
                restore = self.set_scope([])
            actions.append({"step": "scope_restore", "ok": restore["ok"],
                            "detail": restore["detail"]})
            self.scope_applied = False
        if self.enabled_by_us:
            disable = self.disable_module()
            actions.append({"step": "disable", "ok": disable["ok"],
                            "detail": disable["detail"]})
            self.enabled_by_us = False
        clear = self.dm.run_shell_root(
            f"setprop {shlex.quote(RUNTIME_PROPERTY)} ''", timeout=10
        )
        if clear.get("ok"):
            actions.append({"step": "config_reset", "ok": True,
                            "detail": "propriedade de execução limpa"})
        return actions

    def finish(self) -> List[Dict[str, object]]:
        """Restaura o dispositivo e remove o módulo instalado.

        Returns:
            Lista de detalhes das ações executadas.
        """
        actions = self.cleanup()
        if self.installed and not self.keep_installed:
            remove = self.uninstall()
            actions.append({"step": "uninstall", "ok": remove["ok"],
                            "detail": remove["detail"]})
        return actions

    def run_phase(
        self, config: ModuleConfig, window: int = 12, keep_enabled: bool = False,
        interact: bool = False,
    ) -> dict:
        """Executa uma fase completa com o módulo.

        A fase prepara o módulo (build, instalação, habilitação e
        escopo), executa o app alvo sem instrumentação externa e coleta a
        evidência emitida pelo módulo.

        Args:
            config: Configuração da fase.
            window: Janela de observação em segundos.
            keep_enabled: Se True, o módulo permanece habilitado e no
                escopo ao final da fase.
            interact: Quando True, dispara eventos de entrada ao app
                durante a janela. Proteções costumam exercitar checagens
                de segurança na interação do usuário; sem isso, parte
                delas não aparece na janela.

        Returns:
            Dict com ``ok``, ``steps``, ``run`` (resultado da execução),
            ``cleanup`` e ``error``.
        """
        steps: List[Dict[str, object]] = []
        prepared = self.prepare(config)
        steps.extend(prepared.get("steps", []))
        if not prepared.get("ok"):
            return {
                "ok": False,
                "steps": steps,
                "run": {},
                "cleanup": [],
                "error": prepared.get("error") or "preparação do módulo falhou",
            }

        run: Dict[str, object] = {}
        error: Optional[str] = None
        try:
            run = self.launch(window, interact=interact)
            error = run.get("error")
        except Exception as exc:  # pragma: no cover - proteção de fase
            error = str(exc)
            logger.warning("Fase do módulo falhou", exc_info=True)
        finally:
            cleanup = [] if keep_enabled else self.cleanup()
            if keep_enabled:
                self.scope_applied = False
                self.enabled_by_us = False

        return {
            "ok": bool(run) and not error,
            "steps": steps,
            "run": run,
            "cleanup": cleanup,
            "error": error,
        }

    def framework_artifacts(self, pid: Optional[int]) -> List[str]:
        """Lista os artefatos do framework visíveis no processo alvo.

        O framework de hooking injeta bibliotecas nativas no processo do
        app: mesmo com as camadas Java neutralizadas, um app que leia
        ``/proc/self/maps`` consegue enxergá-las. A lista é registrada no
        relatório para deixar a limitação explícita.

        Args:
            pid: PID do processo alvo.

        Returns:
            Lista de trechos de mapa relevantes (vazia se indisponível).
        """
        if not pid:
            return []
        res = self.dm.run_shell_root(
            f"cat /proc/{pid}/maps 2>/dev/null", timeout=15
        )
        if not res.get("ok") or not res.get("stdout"):
            return []
        artifacts: List[str] = []
        for line in res["stdout"].splitlines():
            lowered = line.lower()
            if any(token in lowered for token in FRAMEWORK_ARTIFACT_TOKENS):
                path = line.split()[-1] if line.split() else line.strip()
                if path not in artifacts:
                    artifacts.append(path)
        return artifacts


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def parse_evidence(lines: List[str]) -> List[Dict[str, str]]:
    """Extrai os eventos de evidência do módulo nas linhas de logcat.

    Args:
        lines: Linhas de logcat.

    Returns:
        Lista de eventos ``{'kind', 'channel', 'method', 'detail'}``.
    """
    events: List[Dict[str, str]] = []
    for line in lines:
        if MODULE_TAG not in line:
            continue
        match = EVIDENCE_PATTERN.search(line)
        if not match:
            continue
        events.append({
            "kind": match.group("kind").strip(),
            "channel": match.group("channel").strip(),
            "method": match.group("method").strip(),
            "detail": match.group("detail").strip(),
        })
    return events


def partition_evidence(
    events: List[Dict[str, str]],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], List[Dict[str, str]]]:
    """Separa os eventos de evidência por papel-veredito.

    Eventos internos do módulo (canal ``module``) não são evidência de
    aplicação. Entre os eventos de aplicação, a leitura de artefatos do
    próprio processo (``/proc``) tem uso legítimo — SDK de relatório de
    crash, por exemplo —, então ela vira **contexto**: é registrada para
    a análise, mas não sustenta veredito sozinha.

    Args:
        events: Eventos de :func:`parse_evidence`.

    Returns:
        Tupla ``(aplicados, observados, contextos)`` com os eventos por
        papel, na ordem original de emissão.
    """
    applied: List[Dict[str, str]] = []
    observed: List[Dict[str, str]] = []
    contexts: List[Dict[str, str]] = []
    for item in events:
        if item.get("channel") == "module":
            continue
        kind = item.get("kind")
        if kind == "neutralize":
            applied.append(item)
        elif kind == "observe":
            observed.append(item)
        elif kind == "context":
            contexts.append(item)
    return applied, observed, contexts


def _parse_ready(detail: str) -> Dict[str, str]:
    """Converte o resumo do módulo em um dicionário.

    Args:
        detail: Conteúdo do evento ``ready``.

    Returns:
        Dict com os pares ``chave=valor`` do resumo.
    """
    values: Dict[str, str] = {}
    for part in (detail or "").split():
        if "=" in part:
            key, _, value = part.partition("=")
            values[key.strip()] = value.strip()
    return values


def _framework_name(modules: List[str]) -> Optional[str]:
    """Deriva o nome do framework a partir do diretório do módulo.

    Args:
        modules: Diretórios de módulos de framework encontrados.

    Returns:
        Nome do framework ou None.
    """
    known = {
        "zygisk_vector": "Vector",
        "zygisk_lsposed": "LSPosed",
        "edxposed": "EdXposed",
        "riru_lsposed": "LSPosed (Riru)",
        "riru": "Riru",
    }
    for module in modules:
        if module in known:
            return known[module]
    return modules[0] if modules else None


def _failed_entries(stdout: str) -> List[str]:
    """Extrai a lista de falhas da saída do cli do framework.

    A saída do cli tem o formato ``Enabled: [...]`` / ``Failed: [...]``:
    a seção ``Failed`` vazia significa que a operação foi concluída.

    Args:
        stdout: Saída do cli.

    Returns:
        Lista de itens com falha (vazia quando não houve falha).
    """
    entries: List[str] = []
    collecting = False
    for line in (stdout or "").splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("failed"):
            collecting = True
            remainder = stripped.split(":", 1)[1] if ":" in stripped else ""
            remainder = remainder.strip().strip("[]").strip()
            if remainder:
                entries.append(remainder)
            continue
        if collecting:
            if stripped.startswith("["):
                remainder = stripped.strip("[]").strip()
                if remainder:
                    entries.append(remainder)
                continue
            if stripped:
                entries.append(stripped)
            collecting = False
    return entries


def _parse_status(stdout: str) -> Tuple[Optional[str], Optional[str]]:
    """Extrai nome e versão do framework a partir da saída do cli.

    Args:
        stdout: Saída do comando ``status``.

    Returns:
        Tupla ``(nome, versão)`` com valores possivelmente nulos.
    """
    name = None
    version = None
    for line in (stdout or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "framework version" and version is None:
            version = value
        elif key == "framework name" and name is None:
            name = value
    if name is None and version is not None:
        name = None
    return name, version
