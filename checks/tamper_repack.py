"""RASPilot — teste de repack do APK.

O check de anti-tampering em memória cobre apenas checagens que passam pelo
``PackageManager`` em runtime. Este módulo faz o teste destrutivo, porém
controlado: altera o APK, reconstrói, re-assina e reinstala no dispositivo
para verificar se o app detecta o repack.

A instalação é sempre opt-in (``allow_reinstall``). O fluxo salva os APKs
originais, testa um controle re-assinado sem alteração de conteúdo e, por
fim, restaura o APK original. Dados do app são perdidos no uninstall.
"""

from __future__ import annotations

import glob
import logging
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from checks.apk_utils import pull_apk
from logcat_analyzer import analyze_since

logger = logging.getLogger("raspilot.checks.tamper_repack")

CONTENT_VARIANTS = ("asset", "dex", "resource", "manifest")
ALL_VARIANTS = ("resigned", "rebuilt") + CONTENT_VARIANTS
ASSET_NAME = "assets/raspilot_repack_probe.txt"
ASSET_CONTENT = b"RASPilot repack probe\n"
SMALI_CLASS = """\
.class public Lcom/raspilot/repack/Probe;
.super Ljava/lang/Object;
.source "Probe.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static marker()Ljava/lang/String;
    .locals 1
    const-string v0, "raspilot-repack-probe"
    return-object v0
.end method
"""
RESOURCE_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="raspilot_repack_probe">raspilot</string>
</resources>
"""
MANIFEST_META = (
    '<meta-data android:name="raspilot.repack.probe" '
    'android:value="1"/>'
)
KEYSTORE_PASSWORD = "android"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_tool(name: str, env_var: Optional[str] = None) -> Optional[str]:
    """Localiza uma ferramenta do SDK/JDK no PATH ou em ~/Android."""
    roots = []
    if env_var:
        roots.append(os.environ.get(env_var))
    roots.extend([
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        os.path.expanduser("~/Android"),
    ])
    for root in roots:
        if not root:
            continue
        build_tools = sorted(glob.glob(os.path.join(root, "build-tools", "*")))
        for directory in reversed(build_tools):
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return shutil.which(name)


def _run(
    cmd: Sequence[str],
    timeout: int = 300,
) -> Tuple[bool, str]:
    """Executa um comando local e devolve ``(ok, output)``."""
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return False, str(exc)
    except subprocess.TimeoutExpired:
        return False, f"timeout após {timeout}s"
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, output


def _keystore(path: Optional[str] = None) -> Tuple[Optional[str], str]:
    """Garante um keystore de debug e devolve ``(caminho, erro)``."""
    target = path or os.path.expanduser("~/.raspilot/keys/raspilot-debug.jks")
    if os.path.isfile(target):
        return target, ""
    os.makedirs(os.path.dirname(target), exist_ok=True)
    keytool = _find_tool("keytool")
    if keytool is None:
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            keytool = os.path.join(java_home, "bin", "keytool")
    if not keytool or not os.path.isfile(keytool):
        return None, "keytool não encontrado"
    ok, output = _run([
        keytool, "-genkeypair", "-keystore", target,
        "-storepass", KEYSTORE_PASSWORD, "-keypass", KEYSTORE_PASSWORD,
        "-alias", "raspilot", "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000", "-dname",
        "CN=RASPilot Repack, OU=Audit, O=RASPilot, C=BR",
    ], timeout=120)
    if not ok:
        return None, output or "falha ao criar keystore"
    return target, ""


def _copy_apks(paths: Sequence[str], dest_dir: str) -> List[str]:
    os.makedirs(dest_dir, exist_ok=True)
    copied: List[str] = []
    for path in paths:
        target = os.path.join(dest_dir, os.path.basename(path))
        if os.path.abspath(path) != os.path.abspath(target):
            shutil.copy2(path, target)
        copied.append(target)
    return copied


def _add_asset(apk: str, output: str) -> Tuple[bool, str]:
    """Copia o APK adicionando um asset marcador."""
    try:
        with zipfile.ZipFile(apk, "r") as src, zipfile.ZipFile(
            output, "w", zipfile.ZIP_DEFLATED
        ) as dst:
            for item in src.infolist():
                if item.filename == ASSET_NAME:
                    continue
                dst.writestr(item, src.read(item.filename))
            dst.writestr(ASSET_NAME, ASSET_CONTENT)
        return True, ""
    except Exception as exc:  # noqa: BLE001 - convertido em resultado
        return False, str(exc)


def _apktool_modify(
    apk: str,
    output: str,
    work_dir: str,
    variant: str,
    apktool: Optional[str],
    timeout: int,
) -> Tuple[bool, str]:
    """Decodifica com apktool, injeta a alteração e reconstrói o APK."""
    if not apktool:
        return False, "apktool não encontrado"
    decoded = os.path.join(work_dir, f"decoded-{variant}")
    if os.path.isdir(decoded):
        shutil.rmtree(decoded)
    decode_args = [apktool, "d", "-f", "-o", decoded, apk]
    if variant == "dex":
        # O DEX é a única parte alterada: mantém recursos e manifesto
        # originais intactos no rebuild.
        decode_args.insert(2, "-r")
    ok, text = _run(decode_args, timeout=timeout)
    if not ok:
        return False, f"apktool d: {text}"
    try:
        if variant == "rebuilt":
            pass
        elif variant == "dex":
            target = os.path.join(
                decoded, "smali", "com", "raspilot", "repack", "Probe.smali"
            )
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(SMALI_CLASS)
        elif variant == "resource":
            target = os.path.join(
                decoded, "res", "values", "raspilot_repack.xml"
            )
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(RESOURCE_XML)
        elif variant == "manifest":
            manifest = os.path.join(decoded, "AndroidManifest.xml")
            with open(manifest, "r", encoding="utf-8") as handle:
                text = handle.read()
            if "raspilot.repack.probe" not in text:
                if "</application>" not in text:
                    return False, "manifest sem </application>"
                text = text.replace(
                    "</application>",
                    f"    {MANIFEST_META}\n    </application>",
                    1,
                )
                with open(manifest, "w", encoding="utf-8") as handle:
                    handle.write(text)
        else:
            return False, f"variante desconhecida: {variant}"
        build_args = [apktool, "b"]
        if variant == "dex":
            build_args.append("--copy-original")
        build_args.extend([decoded, "-o", output])
        ok, text = _run(build_args, timeout=timeout)
        if not ok:
            return False, f"apktool b: {text}"
        return True, ""
    finally:
        if os.path.isdir(decoded):
            # O diretório decodificado é grande; libera assim que possível.
            shutil.rmtree(decoded, ignore_errors=True)


def _sign_apk(
    apk: str,
    output: str,
    keystore: str,
    zipalign: Optional[str],
    apksigner: Optional[str],
) -> Tuple[bool, str]:
    if not zipalign or not apksigner:
        return False, "zipalign/apksigner não encontrados"
    aligned = output + ".aligned"
    ok, text = _run([zipalign, "-f", "4", apk, aligned], timeout=180)
    if not ok:
        return False, f"zipalign: {text}"
    try:
        ok, text = _run([
            apksigner, "sign",
            "--ks", keystore,
            "--ks-pass", f"pass:{KEYSTORE_PASSWORD}",
            "--key-pass", f"pass:{KEYSTORE_PASSWORD}",
            "--out", output, aligned,
        ], timeout=180)
    finally:
        try:
            os.remove(aligned)
        except OSError:
            pass
    if not ok:
        return False, f"apksigner: {text}"
    return True, ""


def _signature(apk: str, apksigner: Optional[str]) -> str:
    if not apksigner:
        return ""
    ok, text = _run([apksigner, "verify", "--print-certs", apk], timeout=120)
    return text if ok else ""


class RepackTester:
    """Executa o teste destrutivo de repack com controles e restore."""

    def __init__(
        self,
        dm,
        package_name: str,
        apk_path: Optional[str] = None,
        output_dir: Optional[str] = None,
        window: int = 15,
        variants: Sequence[str] = ("asset", "dex"),
        installer: Optional[str] = None,
        allow_reinstall: bool = False,
        restore: bool = True,
        keep_artifacts: bool = False,
        timeout: int = 600,
    ) -> None:
        self.dm = dm
        self.package_name = package_name
        self.apk_path = apk_path
        self.output_dir = output_dir or os.path.expanduser("~/.raspilot/repack")
        self.window = max(1, int(window))
        self.variants = [item for item in variants if item in CONTENT_VARIANTS]
        self.installer = installer
        self.allow_reinstall = bool(allow_reinstall)
        self.restore = bool(restore)
        self.keep_artifacts = bool(keep_artifacts)
        self.timeout = int(timeout)
        self._resolved_installer: Optional[str] = None

    def _apks(self, dest: str) -> List[str]:
        if self.apk_path:
            if os.path.isdir(self.apk_path):
                paths = sorted(glob.glob(os.path.join(self.apk_path, "*.apk")))
            else:
                paths = [self.apk_path]
        else:
            paths = pull_apk(self.dm, self.package_name, dest)
        return _copy_apks(paths, dest)

    def _installer_name(self) -> Optional[str]:
        if self.installer is not None:
            return self.installer or None
        res = self.dm.run_shell(f"dumpsys package {self.package_name}", timeout=30)
        for line in (res.get("stdout") or "").splitlines():
            text = line.strip()
            if text.startswith("installerPackageName="):
                value = text.split("=", 1)[1].strip()
                if value and value != "null":
                    return value
        return None

    def _install(self, apks: Sequence[str], replace: bool = True) -> Tuple[bool, str]:
        if not apks:
            return False, "lista de APKs vazia"
        installer = (
            self._resolved_installer
            if self._resolved_installer is not None
            else self._installer_name()
        )
        args: List[str] = ["install-multiple" if len(apks) > 1 else "install"]
        if replace:
            args.append("-r")
        if installer:
            args.extend(["-i", installer])
        args.extend(apks)
        try:
            output = self.dm._run_adb(args, timeout=300)
            return True, output
        except Exception as exc:  # noqa: BLE001 - reportado no resultado
            return False, str(exc)

    def _uninstall(self) -> Tuple[bool, str]:
        try:
            output = self.dm._run_adb(["uninstall", self.package_name], timeout=120)
            return True, output
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def _launch(self) -> Optional[int]:
        self.dm.run_shell(f"am force-stop {self.package_name}", timeout=20)
        self.dm.run_shell(
            f"monkey -p {self.package_name} -c android.intent.category.LAUNCHER 1",
            timeout=30,
        )
        deadline = time.monotonic() + 20
        pid = None
        while time.monotonic() < deadline:
            pid = self.dm.get_app_pid(self.package_name)
            if pid is not None:
                break
            time.sleep(1)
        return pid

    def _observe(self, label: str) -> dict:
        mark = self.dm.logcat_mark()
        pid = self._launch()
        started = time.monotonic()
        if pid is not None:
            self.dm.wait_for_app_ready(self.package_name, timeout=8, pid=pid)
            try:
                self.dm.drive_ui(self.package_name, taps=3, timeout=90)
            except Exception:
                logger.debug("drive_ui falhou no repack %s", label, exc_info=True)
        died_after = None
        while time.monotonic() - started < self.window:
            time.sleep(1)
            if pid is not None and not self.dm.is_app_alive(pid):
                died_after = int(time.monotonic() - started)
                break
        alive = bool(pid is not None and self.dm.is_app_alive(pid))
        foreground = False
        if alive:
            try:
                foreground = bool(self.dm.wait_for_app_ready(
                    self.package_name, timeout=2, pid=pid
                ))
            except Exception:
                foreground = False
        logcat = {}
        try:
            logcat = analyze_since(self.dm, mark, self.package_name, pid)
        except Exception:
            logger.debug("logcat do repack %s falhou", label, exc_info=True)
        return {
            "label": label,
            "pid": pid,
            "alive": alive,
            "foreground": foreground,
            "usable": bool(alive and foreground),
            "died_after": died_after,
            "logcat": logcat,
        }

    def _build(
        self,
        original: Sequence[str],
        artifacts: str,
        keystore: str,
        zipalign: Optional[str],
        apksigner: Optional[str],
        apktool: Optional[str],
    ) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        built: Dict[str, List[str]] = {}
        errors: Dict[str, str] = {}
        base = original[0]
        signed_splits: List[str] = []
        for index, split in enumerate(original[1:]):
            signed_split = os.path.join(
                artifacts, f"split-{index}-{os.path.basename(split)}"
            )
            ok, text = _sign_apk(
                split, signed_split, keystore, zipalign, apksigner
            )
            if not ok:
                errors["splits"] = text
                break
            signed_splits.append(signed_split)

        signed_base = os.path.join(artifacts, "resigned-base.apk")
        ok, text = _sign_apk(base, signed_base, keystore, zipalign, apksigner)
        if not ok:
            errors["resigned"] = text
        else:
            built["resigned"] = [signed_base] + signed_splits

        tool_variants = [
            item for item in self.variants
            if item in ("dex", "resource", "manifest")
        ]
        if tool_variants:
            rebuilt = os.path.join(artifacts, "rebuilt-base.apk")
            ok, text = _apktool_modify(
                base, rebuilt, artifacts, "rebuilt", apktool, self.timeout
            )
            if ok:
                signed_rebuilt = os.path.join(artifacts, "rebuilt-signed.apk")
                ok, text = _sign_apk(
                    rebuilt, signed_rebuilt, keystore, zipalign, apksigner
                )
                if ok:
                    built["rebuilt"] = [signed_rebuilt] + signed_splits
            if not ok:
                errors["rebuilt"] = text

        for variant in self.variants:
            modified = os.path.join(artifacts, f"{variant}-base.apk")
            if variant == "asset":
                ok, text = _add_asset(base, modified)
            else:
                ok, text = _apktool_modify(
                    base, modified, artifacts, variant, apktool, self.timeout
                )
            if not ok:
                errors[variant] = text
                continue
            signed = os.path.join(artifacts, f"{variant}-signed.apk")
            ok, text = _sign_apk(modified, signed, keystore, zipalign, apksigner)
            if not ok:
                errors[variant] = text
                continue
            built[variant] = [signed] + signed_splits
        return built, errors

    def _interpret(self, observations: Dict[str, dict], errors: Dict[str, str]) -> dict:
        original = observations.get("original") or {}
        resigned = observations.get("resigned") or {}
        variants = [item for item in self.variants if item in observations]
        if not original.get("usable"):
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "attribution": "environment",
                "status_hint": "SKIP",
                "verdict_reason": "app original não ficou vivo/utilizável como controle",
            }
        if not resigned:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "attribution": "inconclusive",
                "status_hint": "SKIP",
                "verdict_reason": "não foi possível testar o controle re-assinado",
            }
        resigned_usable = bool(resigned.get("usable"))
        content = {
            name: observations[name]
            for name in variants
            if name in observations
        }
        detected = [name for name, item in content.items() if not item.get("usable")]
        usable = [name for name, item in content.items() if item.get("usable")]
        if not content:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "attribution": "inconclusive",
                "status_hint": "SKIP",
                "verdict_reason": "nenhuma variante de conteúdo foi exercitada",
            }
        tool_variants = [
            item for item in self.variants
            if item in ("dex", "resource", "manifest")
            and item in observations
        ]
        rebuilt = observations.get("rebuilt") or {}
        if tool_variants and not rebuilt.get("usable"):
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "attribution": "tooling",
                "status_hint": "SKIP",
                "verdict_reason": (
                    "o controle reconstruído sem alteração não ficou utilizável; "
                    "o rebuild isolado não pode ser atribuído ao app"
                ),
            }
        if not resigned_usable:
            attribution = "signature" if not detected else "signature/content"
            return {
                "tamper_detected": True,
                "bypass_successful": False,
                "attribution": attribution,
                "status_hint": "OK",
                "verdict_reason": (
                    "o app rejeitou o APK re-assinado sem alteração de conteúdo"
                ),
            }
        if detected:
            return {
                "tamper_detected": True,
                "bypass_successful": False,
                "attribution": "content",
                "status_hint": "OK",
                "verdict_reason": (
                    "o app rejeitou variante(s) com conteúdo alterado: "
                    + ", ".join(detected)
                ),
            }
        return {
            "tamper_detected": False,
            "bypass_successful": True,
            "attribution": "none",
            "status_hint": "FALHOU",
            "verdict_reason": (
                "o app sobreviveu às variantes de repack: "
                + ", ".join(usable)
            ),
        }

    def run(self) -> dict:
        if not self.allow_reinstall:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": "repack",
                "status_hint": "SKIP",
                "skipped_reason": (
                    "teste de repack exige --tamper-allow-reinstall "
                    "(desinstala e reinstala o app; dados são perdidos)"
                ),
                "timestamp": _now_iso(),
            }
        if not self.variants:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": "repack",
                "status_hint": "SKIP",
                "skipped_reason": "nenhuma variante de repack selecionada",
                "timestamp": _now_iso(),
            }
        keystore, error = _keystore()
        if not keystore:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": "repack",
                "status_hint": "ERROR",
                "skipped_reason": error,
                "timestamp": _now_iso(),
            }
        zipalign = _find_tool("zipalign", "ANDROID_SDK_ROOT")
        apksigner = _find_tool("apksigner", "ANDROID_SDK_ROOT")
        apktool = shutil.which("apktool")
        if not zipalign or not apksigner:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "probe_method": "repack",
                "status_hint": "ERROR",
                "skipped_reason": "zipalign/apksigner não encontrados",
                "timestamp": _now_iso(),
            }
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        root = os.path.join(self.output_dir, f"{self.package_name}_{stamp}")
        os.makedirs(root, exist_ok=True)
        artifacts = root if self.keep_artifacts else tempfile.mkdtemp(
            prefix="raspilot_repack_"
        )
        observations: Dict[str, dict] = {}
        errors: Dict[str, str] = {}
        built: Dict[str, List[str]] = {}
        original: List[str] = []
        restore_result: dict = {}
        touched = False
        result: dict = {}
        try:
            original = self._apks(os.path.join(artifacts, "original"))
            if not original:
                return {
                    "tamper_detected": None,
                    "bypass_successful": None,
                    "probe_method": "repack",
                    "status_hint": "ERROR",
                    "skipped_reason": "APK original indisponível",
                    "timestamp": _now_iso(),
                }
            self._resolved_installer = self._installer_name()
            signature_before = _signature(original[0], apksigner)
            observations["original"] = self._observe("original")
            if not observations["original"].get("usable"):
                verdict = self._interpret(observations, errors)
                return {
                    **verdict,
                    "probe_method": "repack",
                    "observations": observations,
                    "errors": errors,
                    "artifacts": {"directory": None},
                    "timestamp": _now_iso(),
                }
            built, errors = self._build(
                original, artifacts, keystore, zipalign, apksigner, apktool
            )
            if "resigned" not in built:
                return {
                    "tamper_detected": None,
                    "bypass_successful": None,
                    "probe_method": "repack",
                    "status_hint": "ERROR",
                    "skipped_reason": (
                        "não foi possível construir o controle re-assinado: "
                        + "; ".join(f"{key}={value}" for key, value in errors.items())
                    ),
                    "observations": observations,
                    "errors": errors,
                    "timestamp": _now_iso(),
                }
            uninstalled, text = self._uninstall()
            if not uninstalled:
                errors["uninstall"] = text
            else:
                touched = True
                installed, text = self._install(built["resigned"], replace=False)
                if installed:
                    observations["resigned"] = self._observe("resigned")
                else:
                    errors["resigned_install"] = text
            if "rebuilt" in built:
                installed, text = self._install(built["rebuilt"], replace=True)
                if installed:
                    observations["rebuilt"] = self._observe("rebuilt")
                else:
                    errors["rebuilt_install"] = text
            for variant in self.variants:
                if variant not in built:
                    continue
                installed, text = self._install(built[variant], replace=True)
                if not installed:
                    errors[variant + "_install"] = text
                    continue
                observations[variant] = self._observe(variant)
            verdict = self._interpret(observations, errors)
            result = {
                **verdict,
                "probe_method": "repack",
                "method": "repack",
                "success": verdict.get("bypass_successful"),
                "details": verdict.get("verdict_reason"),
                "original_alive": (observations.get("original") or {}).get("alive"),
                "control_alive": (observations.get("resigned") or {}).get("alive"),
                "tamper_alive": (observations.get(variant) or {}).get("alive")
                if self.variants else None,
                "observations": observations,
                "errors": errors,
                "signature_before": signature_before,
                "signature_after": _signature(
                    (built.get("asset") or built.get("dex")
                     or built.get("resource") or built.get("manifest")
                     or built.get("resigned") or [""])[0],
                    apksigner,
                ),
                "installer": self._installer_name(),
                "data_warning": (
                    "o uninstall removeu os dados do app; não há backup automático"
                ),
                "artifacts": {
                    "directory": artifacts if self.keep_artifacts else None,
                },
                "timestamp": _now_iso(),
            }
            if not self.keep_artifacts:
                result["artifacts"]["temporary"] = True
            return result
        finally:
            if self.restore and original and touched:
                try:
                    self._uninstall()
                    restored, text = self._install(original, replace=False)
                    restore_result = {"ok": restored, "detail": text}
                except Exception as exc:  # noqa: BLE001
                    restore_result = {"ok": False, "detail": str(exc)}
            if not self.keep_artifacts:
                shutil.rmtree(artifacts, ignore_errors=True)
            if result:
                result["restore"] = restore_result
            if restore_result:
                logger.info("Restore do repack: %s", restore_result)
