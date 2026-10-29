"""RASPilot — Ambiente emulado (AVD) opcional.

Permite rodar a auditoria contra um **AVD** (Android Virtual Device) em
vez do device físico. Todo o suporte é opcional: sem a flag ``--avd``
nada muda, e o RASPilot não depende do SDK Android instalado.

O ambiente é **configurado fora** da ferramenta (documentação no README)
e a flag ``--avd`` apenas o **ativa**: sobe o emulador, espera o boot,
entrega o serial para o ``DeviceManager`` e encerra o emulador no fim.

Por que importa: sobre um AVD, os artefatos de emulador são reais. O
check anti-emulador passa a medir o bypass de verdade — o app recebe os
valores de um device físico enquanto a máquina é um emulador de fato.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import paths

logger = logging.getLogger("raspilot.avd")

# Caminho padrão da configuração do ambiente emulado.
DEFAULT_CONFIG_PATH = str(paths.avd_config_path())

# Variável de ambiente que aponta para outra configuração.
CONFIG_ENV_VAR = "RASPILOT_AVD_CONFIG"

# AVDs criados para a auditoria costumam rodar sem tela; nesse caso o
# boot pode demorar (snapshot frio) — o limite padrão é generoso.
DEFAULT_BOOT_TIMEOUT = 300


class AvdConfigError(Exception):
    """Configuração do AVD ausente ou inválida."""


class AvdError(Exception):
    """Falha ao preparar ou operar o ambiente emulado."""


@dataclass
class AvdConfig:
    """Descreve o ambiente emulado a ser ativado.

    Attributes:
        sdk_root: Raiz do SDK Android (``$ANDROID_SDK_ROOT``).
        avd_name: Nome do AVD a ser iniciado.
        system_image: System image usado para criar o AVD (apenas
            para as instruções de configuração).
        device_profile: Perfil de hardware do AVD (idem).
        port: Porta do console/adb do emulador.
        headless: Se True, sobe sem janela e sem áudio.
        wipe_data: Se True, reinicia o AVD com dados limpos.
        boot_timeout: Tempo máximo de espera pelo boot, em segundos.
        extra_args: Argumentos extras passados ao ``emulator``.
    """

    sdk_root: str = ""
    avd_name: str = ""
    system_image: str = "system-images;android-33;google_apis;x86_64"
    device_profile: str = "pixel_6"
    port: int = 5554
    headless: bool = True
    wipe_data: bool = False
    boot_timeout: int = DEFAULT_BOOT_TIMEOUT
    extra_args: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Carga
    # ------------------------------------------------------------------
    @staticmethod
    def default_path() -> str:
        """Retorna o caminho da configuração usado por padrão.

        Returns:
            Caminho absoluto do arquivo de configuração.
        """
        return os.environ.get(CONFIG_ENV_VAR) or str(paths.avd_config_path())

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AvdConfig":
        """Carrega a configuração do ambiente emulado.

        Args:
            path: Caminho do arquivo JSON. Se None, usa o padrão
                (``~/.raspilot/avd.json`` ou ``$RASPILOT_AVD_CONFIG``).

        Returns:
            Configuração carregada.

        Raises:
            AvdConfigError: se o arquivo não existir, não for JSON
                válido ou faltar campos obrigatórios.
        """
        config_path = path or cls.default_path()
        if not os.path.isfile(config_path):
            raise AvdConfigError(
                f"configuração do AVD não encontrada: {config_path}\n"
                + cls.setup_instructions(config_path)
            )
        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise AvdConfigError(
                f"não foi possível ler a configuração do AVD ({config_path}): {exc}\n"
                + cls.setup_instructions(config_path)
            ) from exc
        if not isinstance(raw, dict):
            raise AvdConfigError(
                f"configuração do AVD inválida ({config_path}): "
                "esperado um objeto JSON"
            )

        known = {
            "sdk_root", "avd_name", "system_image", "device_profile",
            "port", "headless", "wipe_data", "boot_timeout", "extra_args",
        }
        config = cls(
            sdk_root=str(raw.get("sdk_root") or "").strip(),
            avd_name=str(raw.get("avd_name") or "").strip(),
            system_image=str(raw.get("system_image") or cls.system_image),
            device_profile=str(raw.get("device_profile") or cls.device_profile),
            port=int(raw.get("port") or 5554),
            headless=bool(raw.get("headless", True)),
            wipe_data=bool(raw.get("wipe_data", False)),
            boot_timeout=int(raw.get("boot_timeout") or DEFAULT_BOOT_TIMEOUT),
            extra_args=[str(a) for a in (raw.get("extra_args") or [])],
        )
        unknown = set(raw) - known
        if unknown:
            logger.warning(
                "Chaves desconhecidas na configuração do AVD: %s",
                ", ".join(sorted(unknown)),
            )
        if not config.avd_name:
            raise AvdConfigError(
                f"configuração do AVD sem 'avd_name' ({config_path})\n"
                + cls.setup_instructions(config_path)
            )
        return config

    # ------------------------------------------------------------------
    # Instruções
    # ------------------------------------------------------------------
    @staticmethod
    def setup_instructions(config_path: Optional[str] = None) -> str:
        """Monta as instruções de configuração do ambiente emulado.

        Args:
            config_path: Caminho onde a configuração deve ficar.

        Returns:
            Texto com os passos e os comandos exatos.
        """
        target = config_path or AvdConfig.default_path()
        return (
            "\nPara configurar o ambiente emulado:\n"
            "  1. Instale o SDK Android (cmdline-tools) e defina "
            "ANDROID_SDK_ROOT.\n"
            "  2. Baixe a system image e crie o AVD:\n"
            "       sdkmanager \"system-images;android-33;google_apis;x86_64\"\n"
            "       echo no | avdmanager create avd --name raspilot_avd \\\n"
            "           --package \"system-images;android-33;google_apis;x86_64\" \\\n"
            "           --device \"pixel_6\"\n"
            "  3. Descreva o ambiente em "
            f"{target}:\n"
            "       {\n"
            '         "sdk_root": "/caminho/do/Android/Sdk",\n'
            '         "avd_name": "raspilot_avd",\n'
            '         "system_image": '
            '"system-images;android-33;google_apis;x86_64",\n'
            '         "device_profile": "pixel_6",\n'
            '         "port": 5554,\n'
            '         "headless": true,\n'
            "         \"wipe_data\": false,\n"
            '         "boot_timeout": 300,\n'
            '         "extra_args": ["-no-snapshot-save", '
            '"-gpu", "swiftshader_indirect"]\n'
            "       }\n"
            "  4. Rode a auditoria com --avd (ou valide com --avd-check).\n"
        )


@dataclass
class AvdEnvironment:
    """Resultado da validação do ambiente emulado.

    Attributes:
        ok: True quando tudo o que a ferramenta precisa está presente.
        problems: Lista de problemas encontrados.
        hints: Lista de instruções de correção.
        details: Informações do ambiente (caminhos, AVD, etc.).
    """

    ok: bool = True
    problems: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    details: Dict[str, str] = field(default_factory=dict)


class AvdManager:
    """Sobe, espera o boot e encerra um AVD configurado."""

    def __init__(self, config: AvdConfig) -> None:
        """Inicializa o gerenciador.

        Args:
            config: Configuração do ambiente emulado.
        """
        self.config = config
        self.process: Optional[subprocess.Popen] = None
        self._started = False

    # ------------------------------------------------------------------
    # Caminhos e Ferramentas
    # ------------------------------------------------------------------
    @property
    def serial(self) -> str:
        """Serial ADB do emulador (``emulator-<porta>``)."""
        return f"emulator-{self.config.port}"

    def emulator_binary(self) -> Optional[str]:
        """Localiza o binário ``emulator`` do SDK.

        Returns:
            Caminho absoluto do binário, ou None se não encontrado.
        """
        root = self.config.sdk_root
        if root:
            candidate = os.path.join(root, "emulator", "emulator")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            # Em alguns installs o layout é <root>/emulator-linux/emulator.
            candidate = os.path.join(root, "emulator-linux", "emulator")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        found = shutil.which("emulator")
        if found:
            return found
        return None

    def avd_home(self) -> str:
        """Retorna o diretório de AVDs do usuário.

        Returns:
            Caminho de ``~/.android/avd``.
        """
        return os.path.join(os.path.expanduser("~"), ".android", "avd")

    def avd_exists(self) -> bool:
        """Indica se o AVD configurado existe.

        Returns:
            True se o diretório do AVD (ou o .ini) estiver presente.
        """
        name = self.config.avd_name
        if not name:
            return False
        return os.path.isdir(os.path.join(self.avd_home(), f"{name}.avd")) or \
            os.path.isfile(os.path.join(self.avd_home(), f"{name}.ini"))

    # ------------------------------------------------------------------
    # Validação
    # ------------------------------------------------------------------
    def check(self) -> AvdEnvironment:
        """Valida o ambiente sem iniciar nada.

        Returns:
            Resultado da validação com problemas e instruções.
        """
        env = AvdEnvironment()
        binary = self.emulator_binary()
        if binary:
            env.details["emulator"] = binary
        else:
            env.ok = False
            env.problems.append(
                "binário 'emulator' não encontrado "
                f"(sdk_root={self.config.sdk_root or 'não configurado'})"
            )
            env.hints.append(
                "Instale o SDK Android e informe 'sdk_root' na configuração, "
                "ou deixe o 'emulator' no PATH."
            )

        if self.avd_exists():
            env.details["avd"] = self.config.avd_name
        else:
            env.ok = False
            env.problems.append(
                f"AVD '{self.config.avd_name}' não encontrado em {self.avd_home()}"
            )
            env.hints.append(
                "Crie o AVD com avdmanager (veja a documentação do README)."
            )

        if not shutil.which("adb"):
            env.ok = False
            env.problems.append("'adb' não encontrado no PATH")
            env.hints.append("Instale as Platform Tools do SDK Android.")

        env.details["serial"] = self.serial
        env.details["sdk_root"] = self.config.sdk_root or "(PATH)"
        env.details["system_image"] = self.config.system_image
        return env

    # ------------------------------------------------------------------
    # Operação
    # ------------------------------------------------------------------
    def _adb(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Executa um comando adb.

        Args:
            args: Argumentos do adb (sem o executável).
            timeout: Timeout em segundos.

        Returns:
            CompletedProcess com o resultado.
        """
        adb = shutil.which("adb") or "adb"
        return subprocess.run(
            [adb] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def is_running(self) -> bool:
        """Indica se o emulador da porta configurada já está online.

        Returns:
            True se o serial correspondente aparecer no ``adb devices``.
        """
        try:
            proc = self._adb(["devices"], timeout=15)
        except (OSError, subprocess.SubprocessError):
            return False
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == self.serial and parts[1] == "device":
                return True
        return False

    def command(self) -> List[str]:
        """Monta o comando de inicialização do emulador.

        Returns:
            Lista de argumentos (sem o executável).
        """
        args = [
            "-avd", self.config.avd_name,
            "-port", str(self.config.port),
            "-no-boot-anim",
        ]
        if self.config.headless:
            args += ["-no-window", "-no-audio"]
        if self.config.wipe_data:
            args.append("-wipe-data")
        args += list(self.config.extra_args)
        return args

    def start(self) -> str:
        """Inicia o AVD e espera o boot completo.

        Se o emulador já estiver online na porta configurada, ele é
        reaproveitado (e não será encerrado no fim da auditoria).

        Returns:
            Serial ADB do emulador.

        Raises:
            AvdError: se o ambiente não estiver pronto ou o boot
                exceder o tempo limite.
        """
        env = self.check()
        if not env.ok:
            raise AvdError(
                "ambiente emulado não pronto:\n"
                + "\n".join(f"  - {p}" for p in env.problems)
                + ("\n" + "\n".join(f"  {h}" for h in env.hints) if env.hints else "")
            )

        if self.is_running():
            logger.info("AVD %s já está online", self.serial)
            return self.serial

        binary = self.emulator_binary()
        cmd = [binary or "emulator"] + self.command()
        logger.info("Iniciando AVD: %s", " ".join(cmd))
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise AvdError(f"não foi possível iniciar o emulador: {exc}") from exc
        self._started = True

        self._wait_for_device()
        self._wait_for_boot()
        return self.serial

    def _wait_for_device(self) -> None:
        """Espera o emulador aparecer no ``adb devices``."""
        deadline = time.monotonic() + self.config.boot_timeout
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                output = ""
                try:
                    if self.process.stdout is not None:
                        output = self.process.stdout.read() or ""
                except (OSError, ValueError):
                    output = ""
                raise AvdError(
                    "o emulador encerrou durante a inicialização"
                    + (f":\n{output.strip()}" if output.strip() else "")
                )
            if self.is_running():
                return
            time.sleep(2)
        raise AvdError(
            f"o emulador não apareceu no adb em {self.config.boot_timeout}s"
        )

    def _wait_for_boot(self) -> None:
        """Espera o boot do sistema (``sys.boot_completed``)."""
        deadline = time.monotonic() + self.config.boot_timeout
        while time.monotonic() < deadline:
            try:
                proc = self._adb(
                    ["-s", self.serial, "shell", "getprop", "sys.boot_completed"],
                    timeout=20,
                )
                if "1" in (proc.stdout or ""):
                    logger.info("AVD %s inicializado", self.serial)
                    return
            except (OSError, subprocess.SubprocessError):
                pass
            time.sleep(2)
        raise AvdError(
            f"o boot do AVD não concluiu em {self.config.boot_timeout}s"
        )

    def stop(self) -> None:
        """Encerra o emulador iniciado por esta instância.

        Um emulador que já estava rodando antes da auditoria **não** é
        encerrado: quem abriu o ambiente continua com ele.
        """
        if not self._started:
            return
        try:
            self._adb(["-s", self.serial, "emu", "kill"], timeout=20)
        except (OSError, subprocess.SubprocessError):
            logger.debug("Falha ao encerrar o AVD via adb", exc_info=True)
        if self.process is not None:
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logger.warning("Emulador não encerrou; matando o processo")
                    self.process.kill()
            except (OSError, ValueError):
                pass
        logger.info("AVD %s encerrado", self.serial)
