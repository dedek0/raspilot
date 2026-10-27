"""RASPilot — teste de repack do APK.

O check de anti-tampering em memória cobre apenas checagens que passam pelo
``PackageManager`` em runtime. Este módulo faz o teste destrutivo, porém
controlado: altera o APK, reconstrói, re-assina e reinstala no dispositivo
para verificar se o app detecta o repack. Variantes de conteúdo cobrem
asset, DEX, recurso, manifesto e o payload de Frida Gadget. O assinante
pode ser o de debug ou o keystore original (``key_path``); o Gadget
suporta listen/wait/script. A observação separa app, UI, logcat e payload.

A instalação é sempre opt-in (``allow_reinstall``). O fluxo salva os APKs
originais, testa um controle re-assinado sem alteração de conteúdo e, por
fim, restaura o APK original. Dados do app são perdidos no uninstall.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from checks.apk_utils import pull_apk
from logcat_analyzer import analyze_since

logger = logging.getLogger("raspilot.checks.tamper_repack")

CONTENT_VARIANTS = ("asset", "dex", "resource", "manifest", "gadget")
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
GADGET_PROVIDER_SMALI = """.class public Lcom/raspilot/repack/GadgetProvider;
.super Landroid/content/ContentProvider;
.source "GadgetProvider.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V
    return-void
.end method

.method public onCreate()Z
    .locals 2
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lcom/raspilot/repack/GadgetLoader;
    invoke-direct {v1}, Lcom/raspilot/repack/GadgetLoader;-><init>()V
    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V
    const/4 v0, 0x1
    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
"""
GADGET_PROVIDER_SCRIPT_SMALI = """\
.class public Lcom/raspilot/repack/GadgetProvider;
.super Landroid/content/ContentProvider;
.source "GadgetProvider.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V
    return-void
.end method

.method public onCreate()Z
    .locals 5
    :try_start_0
    invoke-virtual {p0}, Lcom/raspilot/repack/GadgetProvider;->getContext()Landroid/content/Context;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;
    move-result-object v0
    const-string v1, "raspilot_gadget.js"
    invoke-virtual {v0, v1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
    move-result-object v0
    invoke-virtual {p0}, Lcom/raspilot/repack/GadgetProvider;->getContext()Landroid/content/Context;
    move-result-object v1
    invoke-virtual {v1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v1
    new-instance v2, Ljava/io/File;
    const-string v3, "raspilot-gadget.js"
    invoke-direct {v2, v1, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    new-instance v4, Ljava/io/FileOutputStream;
    invoke-direct {v4, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    const/16 v1, 0x1000
    new-array v1, v1, [B
    :goto_0
    invoke-virtual {v0, v1}, Ljava/io/InputStream;->read([B)I
    move-result v2
    if-lez v2, :goto_1
    const/4 v3, 0x0
    invoke-virtual {v4, v1, v3, v2}, Ljava/io/FileOutputStream;->write([BII)V
    goto :goto_0
    :goto_1
    invoke-virtual {v4}, Ljava/io/FileOutputStream;->close()V
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0
    goto :goto_2
    :catch_0
    move-exception v0
    :goto_2
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lcom/raspilot/repack/GadgetLoader;
    invoke-direct {v1}, Lcom/raspilot/repack/GadgetLoader;-><init>()V
    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V
    const/4 v0, 0x1
    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
"""
GADGET_PROVIDER_CONTROL_SMALI = """\
.class public Lcom/raspilot/repack/GadgetProvider;
.super Landroid/content/ContentProvider;
.source "GadgetProvider.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V
    return-void
.end method

.method public onCreate()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
"""
GADGET_LOADER_SMALI = """\
.class public Lcom/raspilot/repack/GadgetLoader;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;
.source "GadgetLoader.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public run()V
    .locals 1
    const-string v0, "gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
"""
GADGET_MARKER_NAME = "raspilot-gadget-ok"
GADGET_MARKER_JS = b"""
try {
    var marker = new File('/data/user/0/__RASPILOT_PACKAGE_NAME__/files/raspilot-gadget-ok', 'w');
    marker.write('ok');
    marker.flush();
    marker.close();
} catch (e) { }
"""
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


def _apktool_prefix(apktool: str) -> List[str]:
    """Adiciona heap maior quando o apktool é o wrapper Java padrão."""
    try:
        with open(apktool, "r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(4096)
        if "exec java" in head and "-J" in head:
            heap = os.environ.get("RASPILOT_APKTOOL_XMX", "6G")
            return [apktool, f"-JXmx{heap}"]
    except OSError:
        pass
    return [apktool]


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


def _resolve_keystore(
    key_path: Optional[str],
    key_alias: str,
    key_pass: str,
    store_pass: str,
) -> Tuple[Optional[str], str, str]:
    """Resolve a chave de assinatura e informa o modo usado."""
    if key_path:
        if not os.path.isfile(key_path):
            return None, "original", f"keystore não encontrado: {key_path}"
        return key_path, "original", ""
    path, error = _keystore()
    return path, "debug", error


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
    package_name: str = "",
    gadget_mode: str = "listen",
) -> Tuple[bool, str]:
    """Decodifica com apktool, injeta a alteração e reconstrói o APK."""
    if not apktool:
        return False, "apktool não encontrado"
    decoded = os.path.join(work_dir, f"decoded-{variant}")
    if os.path.isdir(decoded):
        shutil.rmtree(decoded)
    decode_args = _apktool_prefix(apktool) + [
        "d", "-f", "-j", "4", "-o", decoded, apk,
    ]
    if variant in ("dex", "rebuilt-dex"):
        # O DEX é a única parte alterada: mantém recursos e manifesto
        # originais intactos no rebuild.
        decode_args.insert(3, "-r")
    ok, text = _run(decode_args, timeout=timeout)
    if not ok:
        return False, f"apktool d: {text}"
    try:
        if variant in ("rebuilt", "rebuilt-dex"):
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
        elif variant in ("gadget", "gadget-control"):
            target = os.path.join(
                decoded, "smali", "com", "raspilot", "repack",
                "GadgetProvider.smali",
            )
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if variant == "gadget":
                provider_smali = (
                    GADGET_PROVIDER_SCRIPT_SMALI
                    if gadget_mode == "script"
                    else GADGET_PROVIDER_SMALI
                )
            else:
                provider_smali = GADGET_PROVIDER_CONTROL_SMALI
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(provider_smali)
            if variant == "gadget":
                loader = os.path.join(
                    decoded, "smali", "com", "raspilot", "repack",
                    "GadgetLoader.smali",
                )
                with open(loader, "w", encoding="utf-8") as handle:
                    handle.write(GADGET_LOADER_SMALI)
            manifest = os.path.join(decoded, "AndroidManifest.xml")
            with open(manifest, "r", encoding="utf-8") as handle:
                text = handle.read()
            if "</application>" not in text:
                return False, "manifest sem </application>"
            authority = f"{package_name or 'com.raspilot.repack'}.raspilot.gadget"
            provider = (
                '<provider\n'
                '        android:name="com.raspilot.repack.GadgetProvider"\n'
                f'        android:authorities="{authority}"\n'
                '        android:exported="false" />'
            )
            text = re.sub(
                r'android:extractNativeLibs="[^"]*"',
                'android:extractNativeLibs="true"',
                text,
                count=1,
            )
            if 'android:extractNativeLibs=' not in text:
                text = re.sub(
                    r"<application\b",
                    '<application android:extractNativeLibs="true"',
                    text,
                    count=1,
                )
            text = text.replace(
                "</application>", f"    {provider}\n</application>", 1
            )
            with open(manifest, "w", encoding="utf-8") as handle:
                handle.write(text)
        else:
            return False, f"variante desconhecida: {variant}"
        build_args = _apktool_prefix(apktool) + [
            "b", "-j", "4",
        ]
        if variant in ("dex", "rebuilt-dex"):
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
    alias: str = "raspilot",
    key_pass: str = KEYSTORE_PASSWORD,
    store_pass: str = KEYSTORE_PASSWORD,
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
            "--ks-pass", f"pass:{store_pass}",
            "--key-pass", f"pass:{key_pass}",
            "--ks-key-alias", alias,
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


def _gadget_config(
    mode: str, port: int, package_name: str, script_device: str = ""
) -> dict:
    """Monta a configuração do Gadget para o modo escolhido."""
    if mode == "script":
        return {
            "interaction": {
                "type": "script",
                "path": script_device,
                "on_change": "reload",
            }
        }
    return {
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": int(port),
            "on_port_conflict": "pick-next",
            "on_load": "wait" if mode == "wait" else "resume",
        }
    }


def _device_gadget_arch(abi: str) -> Optional[str]:
    return {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86_64": "x86_64",
        "x86": "x86",
    }.get((abi or "").strip())


def _resolve_gadget(path: Optional[str], abi: str) -> Tuple[Optional[str], str]:
    """Localiza (e descomprime) o Frida Gadget para a ABI do device."""
    arch = _device_gadget_arch(abi)
    if not arch:
        return None, f"ABI sem Gadget suportado: {abi}"
    candidate = path
    if not candidate:
        matches = sorted(glob.glob(os.path.expanduser(
            f"~/.raspilot/gadgets/*{arch}*.so*"
        )))
        if matches:
            candidate = matches[-1]
    if not candidate:
        return None, (
            "Frida Gadget não encontrado; baixe o binário da ABI "
            f"{arch} e use --tamper-gadget"
        )
    if not os.path.isfile(candidate):
        return None, f"Frida Gadget não encontrado: {candidate}"
    if candidate.endswith(".xz"):
        import lzma

        target = candidate[:-3]
        try:
            with lzma.open(candidate, "rb") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
        except OSError as exc:
            return None, f"falha ao descomprimir Gadget: {exc}"
        candidate = target
    return candidate, ""


def _inject_gadget_libs(
    apk: str,
    output: str,
    gadget_path: str,
    abi: str,
    port: int,
    mode: str = "listen",
    package_name: str = "",
    script: Optional[bytes] = None,
) -> Tuple[bool, str]:
    """Adiciona libgadget.so, configuração e script opcional ao APK."""
    try:
        with open(gadget_path, "rb") as handle:
            gadget = handle.read()
        script_device = (
            f"/data/user/0/{package_name}/files/raspilot-gadget.js"
            if package_name else ""
        )
        config = json.dumps(
            _gadget_config(mode, port, package_name, script_device),
            ensure_ascii=False,
        ).encode("utf-8")
        lib_dir = f"lib/{abi}"
        gadget_entry = f"{lib_dir}/libgadget.so"
        config_entry = f"{lib_dir}/libgadget.config.so"
        with zipfile.ZipFile(apk, "r") as src, zipfile.ZipFile(
            output, "w", zipfile.ZIP_DEFLATED
        ) as dst:
            for item in src.infolist():
                if item.filename in (gadget_entry, config_entry):
                    continue
                dst.writestr(item, src.read(item.filename))
            dst.writestr(gadget_entry, gadget)
            dst.writestr(config_entry, config)
            if mode == "script" and script is not None:
                marker = GADGET_MARKER_JS.replace(
                    b"__RASPILOT_PACKAGE_NAME__",
                    (package_name or "").encode("utf-8"),
                )
                dst.writestr(
                    "assets/raspilot_gadget.js",
                    script.rstrip() + b"\n" + marker,
                )
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


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
        gadget_path: Optional[str] = None,
        gadget_port: int = 27043,
        gadget_mode: str = "listen",
        gadget_script: Optional[str] = None,
        key_path: Optional[str] = None,
        key_alias: str = "raspilot",
        key_pass: str = KEYSTORE_PASSWORD,
        store_pass: str = KEYSTORE_PASSWORD,
    ) -> None:
        self.dm = dm
        self.package_name = package_name
        self.apk_path = apk_path
        self.output_dir = output_dir or os.path.expanduser("~/.raspilot/repack")
        self.window = max(1, int(window))
        requested = list(variants)
        if "all" in requested:
            requested = list(CONTENT_VARIANTS)
        self.variants = [item for item in requested if item in CONTENT_VARIANTS]
        self.installer = installer
        self.allow_reinstall = bool(allow_reinstall)
        self.restore = bool(restore)
        self.keep_artifacts = bool(keep_artifacts)
        self.timeout = int(timeout)
        self.gadget_path = gadget_path
        self.gadget_port = int(gadget_port)
        self.gadget_mode = gadget_mode or "listen"
        self.gadget_script = gadget_script
        self.key_path = key_path
        self.key_alias = key_alias or "raspilot"
        self.key_pass = key_pass or KEYSTORE_PASSWORD
        self.store_pass = store_pass or KEYSTORE_PASSWORD
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
            if "Success" not in output:
                return False, output
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

    def _device_abi(self) -> str:
        try:
            info = self.dm.get_device_info()
            abi = (info or {}).get("abi")
            if abi:
                return str(abi)
        except Exception:
            logger.debug("get_device_info falhou no repack", exc_info=True)
        res = self.dm.run_shell("getprop ro.product.cpu.abi", timeout=10)
        return (res.get("stdout") or "").strip()

    def _app_pids(self) -> List[int]:
        """Lista todos os processos do app (apps podem ter vários)."""
        pids: List[int] = []
        res = self.dm.run_shell(
            f"pidof {self.package_name} 2>/dev/null", timeout=10
        )
        for token in (res.get("stdout") or "").split():
            try:
                pids.append(int(token))
            except ValueError:
                continue
        if not pids:
            pid = self.dm.get_app_pid(self.package_name)
            if pid is not None:
                pids.append(pid)
        return pids

    def _gadget_loaded(self, pid: Optional[int] = None) -> bool:
        pids = [pid] if pid is not None else self._app_pids()
        for candidate in [item for item in pids if item is not None]:
            command = (
                f"cat /proc/{candidate}/maps 2>/dev/null | grep -m1 libgadget"
            )
            res = self.dm.run_shell(command, timeout=10)
            if (res.get("stdout") or "").strip():
                return True
            try:
                res = self.dm.run_shell_root(command, timeout=10)
                if (res.get("stdout") or "").strip():
                    return True
            except Exception:
                continue
        return False

    def _gadget_connected(self) -> bool:
        """Confirma que o endpoint do Gadget responde no host."""
        port = self.gadget_port
        frida_ps = shutil.which("frida-ps")
        if not frida_ps:
            candidate = os.path.join(os.path.dirname(sys.executable), "frida-ps")
            if os.path.isfile(candidate):
                frida_ps = candidate
        if not frida_ps:
            return False
        try:
            self.dm._run_adb(
                ["forward", f"tcp:{port}", f"tcp:{port}"], timeout=30
            )
            time.sleep(1)
            ok, _ = _run(
                [frida_ps, "-H", f"127.0.0.1:{port}"], timeout=12
            )
            return bool(ok)
        except Exception:
            logger.debug("Conexão com o Gadget falhou", exc_info=True)
            return False
        finally:
            try:
                self.dm._run_adb(
                    ["forward", "--remove", f"tcp:{port}"], timeout=15
                )
            except Exception:
                pass

    def _gadget_script_ran(self) -> bool:
        path = (
            f"/data/user/0/{self.package_name}/files/{GADGET_MARKER_NAME}"
        )
        res = self.dm.run_shell(
            f"run-as {self.package_name} cat files/{GADGET_MARKER_NAME} "
            "2>/dev/null",
            timeout=10,
        )
        if "ok" in (res.get("stdout") or ""):
            return True
        try:
            res = self.dm.run_shell_root(
                f"test -f {path} && echo ok", timeout=10
            )
            return "ok" in (res.get("stdout") or "")
        except Exception:
            return False

    def _ui_snapshot(self) -> dict:
        """Captura texto da UI para detectar telas de bloqueio."""
        dump = (
            f"/sdcard/raspilot_repack_ui.xml"
        )
        res = self.dm.run_shell(
            f"uiautomator dump {dump} >/dev/null 2>&1 && cat {dump}",
            timeout=30,
        )
        text = res.get("stdout") or ""
        try:
            self.dm.run_shell(f"rm -f {dump}", timeout=10)
        except Exception:
            pass
        values = re.findall(r'text="([^"]*)"', text)
        merged = " | ".join(
            value.strip() for value in values if value.strip()
        )[:800]
        lowered = merged.lower()
        strong = (
            "root detected", "tamper detected", "app modified",
            "modified app", "integrity check", "untrusted app",
            "security check failed", "device compromised",
            "dispositivo modificado", "app modificado",
            "integridade do app", "bloqueado por segurança",
            "não é possível continuar", "ambiente não confiável",
        )
        matched = [token for token in strong if token in lowered]
        return {
            "ui_text": merged,
            "ui_signals": matched,
            "ui_blocked": bool(matched),
        }

    def _observe(self, label: str) -> dict:
        mark = self.dm.logcat_mark()
        pid = self._launch()
        started = time.monotonic()
        foreground = False
        gadget_loaded = False
        gadget_connected = False
        gadget_script_ran = False
        if pid is not None:
            # O foco é medido logo após o launch. A navegação posterior
            # pode abrir outra tela/app; isso não significa que o app foi
            # bloqueado pelo anti-tampering.
            try:
                foreground = bool(self.dm.wait_for_app_ready(
                    self.package_name, timeout=20
                ))
            except Exception:
                foreground = False
            if foreground:
                try:
                    self.dm.drive_ui(self.package_name, taps=3, timeout=90)
                except Exception:
                    logger.debug("drive_ui falhou no repack %s", label, exc_info=True)
        died_after = None
        pids = self._app_pids()
        while time.monotonic() - started < self.window:
            time.sleep(1)
            pids = self._app_pids()
            if not pids:
                died_after = int(time.monotonic() - started)
                break
            if label == "gadget":
                if not gadget_loaded:
                    gadget_loaded = self._gadget_loaded()
                if gadget_loaded and self.gadget_mode == "script":
                    gadget_script_ran = self._gadget_script_ran()
                elif gadget_loaded and not gadget_connected:
                    gadget_connected = self._gadget_connected()
        pids = self._app_pids()
        alive = bool(pids)
        foreground_end = False
        if alive:
            try:
                foreground_end = bool(self.dm.wait_for_app_ready(
                    self.package_name, timeout=2
                ))
            except Exception:
                foreground_end = False
            if label == "gadget" and not gadget_loaded:
                gadget_loaded = self._gadget_loaded()
                if gadget_loaded:
                    if self.gadget_mode == "script":
                        gadget_script_ran = self._gadget_script_ran()
                    else:
                        gadget_connected = self._gadget_connected()
        logcat = {}
        try:
            logcat = analyze_since(
                self.dm, mark, self.package_name,
                pids[0] if pids else pid,
            )
        except Exception:
            logger.debug("logcat do repack %s falhou", label, exc_info=True)
        ui = self._ui_snapshot() if alive else {
            "ui_text": "", "ui_signals": [], "ui_blocked": False,
        }
        return {
            "label": label,
            "pid": pid,
            "pids": pids,
            "alive": alive,
            "foreground": foreground,
            "foreground_at_end": foreground_end,
            "usable": bool(alive and foreground and not ui.get("ui_blocked")),
            "ui": ui,
            "signals": {
                "death": bool((logcat or {}).get("death", {}).get("detected")),
                "security": len((logcat or {}).get("security_signals") or []),
                "tls": len((logcat or {}).get("tls_errors") or []),
                "vendor": len((logcat or {}).get("vendor_signals") or []),
            },
            "gadget_loaded": gadget_loaded,
            "gadget_connected": gadget_connected,
            "gadget_script_ran": gadget_script_ran,
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
        gadget_path: Optional[str] = None,
        gadget_abi: str = "",
        gadget_port: int = 27043,
        gadget_mode: str = "listen",
        gadget_script: Optional[bytes] = None,
        key_alias: str = "raspilot",
        key_pass: str = KEYSTORE_PASSWORD,
        store_pass: str = KEYSTORE_PASSWORD,
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
                split, signed_split, keystore, zipalign, apksigner,
                alias=key_alias, key_pass=key_pass, store_pass=store_pass,
            )
            if not ok:
                errors["splits"] = text
                break
            signed_splits.append(signed_split)

        signed_base = os.path.join(artifacts, "resigned-base.apk")
        ok, text = _sign_apk(
            base, signed_base, keystore, zipalign, apksigner,
            alias=key_alias, key_pass=key_pass, store_pass=store_pass,
        )
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
            rebuilt_mode = (
                "rebuilt-dex"
                if all(item == "dex" for item in tool_variants)
                else "rebuilt"
            )
            ok, text = _apktool_modify(
                base, rebuilt, artifacts, rebuilt_mode, apktool, self.timeout,
                package_name=self.package_name,
            )
            if ok:
                signed_rebuilt = os.path.join(artifacts, "rebuilt-signed.apk")
                ok, text = _sign_apk(
                    rebuilt, signed_rebuilt, keystore, zipalign, apksigner,
                    alias=key_alias, key_pass=key_pass, store_pass=store_pass,
                )
                if ok:
                    built["rebuilt"] = [signed_rebuilt] + signed_splits
            if not ok:
                errors["rebuilt"] = text

        if "gadget" in self.variants and gadget_path:
            control_apk = os.path.join(artifacts, "gadget-control-base.apk")
            ok, text = _apktool_modify(
                base, control_apk, artifacts, "gadget-control", apktool,
                self.timeout, package_name=self.package_name,
            )
            if ok:
                control_injected = os.path.join(
                    artifacts, "gadget-control-injected.apk"
                )
                ok, text = _inject_gadget_libs(
                    control_apk, control_injected, gadget_path,
                    gadget_abi, gadget_port, mode="listen",
                    package_name=self.package_name,
                )
                if ok:
                    control_signed = os.path.join(
                        artifacts, "gadget-control-signed.apk"
                    )
                    ok, text = _sign_apk(
                        control_injected, control_signed, keystore,
                        zipalign, apksigner, alias=key_alias,
                        key_pass=key_pass, store_pass=store_pass,
                    )
                    if ok:
                        built["gadget-control"] = [control_signed] + signed_splits
            if not ok:
                errors["gadget-control"] = text

        for variant in self.variants:
            modified = os.path.join(artifacts, f"{variant}-base.apk")
            if variant == "asset":
                ok, text = _add_asset(base, modified)
            else:
                ok, text = _apktool_modify(
                    base, modified, artifacts, variant, apktool,
                    self.timeout, package_name=self.package_name,
                    gadget_mode=gadget_mode,
                )
            if not ok:
                errors[variant] = text
                continue
            if variant == "gadget":
                if not gadget_path:
                    errors[variant] = "Frida Gadget não informado"
                    continue
                injected = os.path.join(artifacts, "gadget-injected.apk")
                ok, text = _inject_gadget_libs(
                    modified, injected, gadget_path, gadget_abi, gadget_port,
                    mode=gadget_mode, package_name=self.package_name,
                    script=gadget_script,
                )
                if not ok:
                    errors[variant] = text
                    continue
                modified = injected
            signed = os.path.join(artifacts, f"{variant}-signed.apk")
            ok, text = _sign_apk(
                modified, signed, keystore, zipalign, apksigner,
                alias=key_alias, key_pass=key_pass, store_pass=store_pass,
            )
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
        resigned_alive = bool(resigned.get("alive"))
        content = {
            name: observations[name]
            for name in variants
            if name in observations
        }
        detected = [
            name for name, item in content.items()
            if item.get("alive") is False
        ]
        usable = [
            name for name, item in content.items()
            if item.get("usable")
            and (
                name != "gadget"
                or (
                    item.get("gadget_loaded")
                    and (
                        item.get("gadget_connected")
                        or item.get("gadget_script_ran")
                    )
                )
            )
        ]
        inconclusive = [
            name for name, item in content.items()
            if item.get("alive") is True and name not in usable
        ]
        tool_variants = [
            item for item in self.variants
            if item in ("dex", "resource", "manifest")
            and item in observations
        ]
        rebuilt = observations.get("rebuilt") or {}
        if tool_variants and not rebuilt.get("usable"):
            if rebuilt.get("alive") is True:
                return {
                    "tamper_detected": None,
                    "bypass_successful": None,
                    "attribution": "inconclusive",
                    "status_hint": "SKIP",
                    "verdict_reason": (
                        "o controle reconstruído ficou vivo, mas não em foco; "
                        "não é possível atribuir o resultado"
                    ),
                }
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
            if resigned_alive:
                return {
                    "tamper_detected": None,
                    "bypass_successful": None,
                    "attribution": "inconclusive",
                    "status_hint": "SKIP",
                    "verdict_reason": (
                        "o controle re-assinado ficou vivo, mas não em foco; "
                        "resultado inconclusivo"
                    ),
                }
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
        gadget_control = observations.get("gadget-control") or {}
        if gadget_control:
            if gadget_control.get("alive") is False:
                return {
                    "tamper_detected": True,
                    "bypass_successful": False,
                    "attribution": "content",
                    "status_hint": "OK",
                    "verdict_reason": (
                        "o app rejeitou o controle de provider/manifesto "
                        "usado pelo payload"
                    ),
                    "payload_failure": False,
                }
            if not gadget_control.get("usable"):
                return {
                    "tamper_detected": None,
                    "bypass_successful": None,
                    "attribution": "inconclusive",
                    "status_hint": "SKIP",
                    "verdict_reason": (
                        "o controle de provider/manifesto do payload ficou "
                        "vivo, mas não em foco"
                    ),
                }
        if not content:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "attribution": "inconclusive",
                "status_hint": "SKIP",
                "verdict_reason": "nenhuma variante de conteúdo foi exercitada",
            }
        real_detected = [name for name in detected if name != "gadget"]
        gadget_detected = (
            "gadget" in detected
            and bool(content["gadget"].get("gadget_loaded"))
            and bool(
                content["gadget"].get("gadget_connected")
                or content["gadget"].get("gadget_script_ran")
            )
        )
        payload_failed = "gadget" in detected and not gadget_detected
        if real_detected or gadget_detected:
            names = real_detected + (["gadget"] if gadget_detected else [])
            return {
                "tamper_detected": True,
                "bypass_successful": False,
                "attribution": "content",
                "status_hint": "OK",
                "verdict_reason": (
                    "o app rejeitou variante(s) com conteúdo alterado: "
                    + ", ".join(names)
                ),
                "payload_failure": payload_failed,
            }
        if payload_failed:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "attribution": "payload",
                "status_hint": "SKIP",
                "verdict_reason": (
                    "a variante gadget encerrou antes de o Gadget carregar/conectar; "
                    "não é possível atribuir ao anti-tampering"
                ),
                "payload_failure": True,
            }
        if inconclusive:
            return {
                "tamper_detected": None,
                "bypass_successful": None,
                "attribution": "inconclusive",
                "status_hint": "SKIP",
                "verdict_reason": (
                    "variante(s) viva(s), mas sem foco para confirmar uso: "
                    + ", ".join(inconclusive)
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
        keystore, signature_mode, error = _resolve_keystore(
            self.key_path, self.key_alias, self.key_pass, self.store_pass
        )
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
        base_dir = os.path.join(self.output_dir, "repack")
        os.makedirs(base_dir, exist_ok=True)
        if self.keep_artifacts:
            artifacts = os.path.join(base_dir, f"{self.package_name}_{stamp}")
            os.makedirs(artifacts, exist_ok=True)
        else:
            artifacts = tempfile.mkdtemp(
                prefix=f"{self.package_name}_{stamp}_", dir=base_dir
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
            gadget_path = None
            gadget_abi = ""
            gadget_script: Optional[bytes] = None
            if "gadget" in self.variants:
                gadget_abi = self._device_abi()
                gadget_path, gadget_error = _resolve_gadget(
                    self.gadget_path, gadget_abi
                )
                if not gadget_path:
                    if self.variants == ["gadget"]:
                        return {
                            "tamper_detected": None,
                            "bypass_successful": None,
                            "probe_method": "repack",
                            "status_hint": "SKIP",
                            "skipped_reason": gadget_error,
                            "observations": observations,
                            "errors": errors,
                            "timestamp": _now_iso(),
                        }
                    errors["gadget"] = gadget_error
                    self.variants = [
                        item for item in self.variants if item != "gadget"
                    ]
                if gadget_path and self.gadget_mode == "script":
                    if not self.gadget_script:
                        return {
                            "tamper_detected": None,
                            "bypass_successful": None,
                            "probe_method": "repack",
                            "status_hint": "SKIP",
                            "skipped_reason": (
                                "modo script exige --tamper-gadget-script"
                            ),
                            "observations": observations,
                            "errors": errors,
                            "timestamp": _now_iso(),
                        }
                    try:
                        with open(self.gadget_script, "rb") as handle:
                            gadget_script = handle.read()
                    except OSError as exc:
                        return {
                            "tamper_detected": None,
                            "bypass_successful": None,
                            "probe_method": "repack",
                            "status_hint": "ERROR",
                            "skipped_reason": (
                                f"não foi possível ler o script do Gadget: {exc}"
                            ),
                            "observations": observations,
                            "errors": errors,
                            "timestamp": _now_iso(),
                        }
            if signature_mode == "original":
                build_alias = self.key_alias
                build_key_pass = self.key_pass
                build_store_pass = self.store_pass
            else:
                build_alias = "raspilot"
                build_key_pass = KEYSTORE_PASSWORD
                build_store_pass = KEYSTORE_PASSWORD
            built, errors = self._build(
                original, artifacts, keystore, zipalign, apksigner, apktool,
                gadget_path=gadget_path, gadget_abi=gadget_abi,
                gadget_port=self.gadget_port, gadget_mode=self.gadget_mode,
                gadget_script=gadget_script,
                key_alias=build_alias, key_pass=build_key_pass,
                store_pass=build_store_pass,
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
            if "gadget-control" in built:
                installed, text = self._install(
                    built["gadget-control"], replace=True
                )
                if installed:
                    observations["gadget-control"] = self._observe(
                        "gadget-control"
                    )
                else:
                    errors["gadget-control_install"] = text
            for variant in self.variants:
                if variant not in built:
                    continue
                if (
                    variant == "gadget"
                    and (observations.get("gadget-control") or {}).get("alive") is False
                ):
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
                "signature_mode": signature_mode,
                "signature_before": signature_before,
                "signature_after": _signature(
                    (built.get("asset") or built.get("dex")
                     or built.get("resource") or built.get("manifest")
                     or built.get("resigned") or [""])[0],
                    apksigner,
                ),
                "installer": self._installer_name(),
                "splits": [os.path.basename(item) for item in original[1:]],
                "ui_blocked": [
                    name for name, item in observations.items()
                    if (item.get("ui") or {}).get("ui_blocked")
                ],
                "server_signals": {
                    name: (item.get("signals") or {})
                    for name, item in observations.items()
                },
                "gadget": {
                    "path": gadget_path,
                    "abi": gadget_abi,
                    "port": self.gadget_port,
                    "mode": self.gadget_mode,
                    "script": self.gadget_script,
                    "loaded": bool(
                        (observations.get("gadget") or {}).get("gadget_loaded")
                    ),
                    "connected": bool(
                        (observations.get("gadget") or {}).get("gadget_connected")
                    ),
                    "script_ran": bool(
                        (observations.get("gadget") or {}).get("gadget_script_ran")
                    ),
                    "objection_command": (
                        f"objection -N -h 127.0.0.1 -p {self.gadget_port} "
                        "-g Gadget explore"
                        if (observations.get("gadget") or {}).get(
                            "gadget_connected"
                        )
                        else None
                    ),
                } if "gadget" in self.variants else None,
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
