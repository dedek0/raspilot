"""RASPilot — Gerenciador de dispositivo Android e Frida server.

Módulo responsável por toda a camada de baixo nível da ferramenta:
conexão ADB (USB e Wi-Fi), leitura de informações do dispositivo,
detecção de root, e o ciclo de vida completo do Frida server
(download, push, start, validação e cleanup).

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import List, Optional

try:
    import frida
except ImportError:  # pragma: no cover - dependência declarada em requirements.txt
    frida = None  # type: ignore[assignment]

logger = logging.getLogger("raspilot.device")

# Versão do pacote RASPilot (usada também nos metadados do relatório).
TOOL_NAME = "RASPilot"
TOOL_VERSION = "0.1.0"

# Timeout padrão (segundos) para qualquer comando adb — nunca travar o pipeline.
DEFAULT_ADB_TIMEOUT = 20

# Timeout para o dispositivo ficar em estado 'device' após `adb connect`.
CONNECT_TIMEOUT = 15


class DeviceConnectionError(Exception):
    """Erro de conexão/estado do dispositivo ADB.

    Levantada quando o adb não encontra o dispositivo, quando o dispositivo
    permanece 'offline'/'unauthorized', ou quando um comando adb falha.
    """


class FridaSetupError(Exception):
    """Erro no ciclo de vida do Frida server.

    Levantada quando o download, push, start ou a validação do
    frida-server no dispositivo falham.
    """


class DeviceManager:
    """Gerencia conexão ADB e o ciclo de vida do Frida server no Android.

    Exemplos de uso::

        dm = DeviceManager(wifi_target="192.168.0.10:5555")
        dm.connect_adb()
        info = dm.get_device_info()
        dm.setup_frida_server()
    """

    def __init__(
        self,
        device_id: Optional[str] = None,
        wifi_target: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        """Inicializa o gerenciador.

        Args:
            device_id: Serial ADB do dispositivo alvo (ex: ``emulator-5554``).
                Se ``None``, o primeiro dispositivo disponível é usado.
            wifi_target: Endereço ``ip:porta`` para ``adb connect``.
            verbose: Se True, força log em nível DEBUG neste módulo.
        """
        self.device_id: Optional[str] = device_id
        self.wifi_target: Optional[str] = wifi_target
        self.verbose = verbose
        if verbose:
            logger.setLevel(logging.DEBUG)

        self._abi: Optional[str] = None
        self._device_info: Optional[dict] = None
        self.frida_ready: bool = False

    # ------------------------------------------------------------------
    # Wrapper de comandos
    # ------------------------------------------------------------------
    def _run(
        self, cmd: List[str], timeout: int = DEFAULT_ADB_TIMEOUT, check: bool = True
    ) -> str:
        """Executa um comando externo capturando stdout/stderr.

        Args:
            cmd: Lista de argumentos do comando (ex: ``["adb", "devices"]``).
            timeout: Timeout em segundos (default 20s).
            check: Se True, levanta exceção quando o returncode != 0.

        Returns:
            stdout do comando como string (strip).

        Raises:
            DeviceConnectionError: Se o comando falhar e ``check=True``.
        """
        logger.debug("exec: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise DeviceConnectionError(
                f"Binário não encontrado: {cmd[0]}. Verifique se está no PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise DeviceConnectionError(
                f"Timeout ({timeout}s) ao executar: {' '.join(cmd)}"
            ) from exc

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        logger.debug("rc=%s stdout=%r stderr=%r", proc.returncode, stdout[:500], stderr[:500])

        if check and proc.returncode != 0:
            raise DeviceConnectionError(
                f"Comando falhou (rc={proc.returncode}): {' '.join(cmd)}\n"
                f"stderr: {stderr.strip() or stdout.strip()}"
            )
        # Preserva stdout mesmo em falha para o chamador inspecionar.
        self._last_stdout = stdout
        self._last_stderr = stderr
        self._last_rc = proc.returncode
        return stdout.strip()

    def _run_adb(self, cmd: List[str], timeout: int = DEFAULT_ADB_TIMEOUT) -> str:
        """Executa ``adb`` com os argumentos fornecidos.

        Se ``self.device_id`` estiver definido, injeta ``-s <serial>``.

        Args:
            cmd: Argumentos após ``adb`` (ex: ``["shell", "id"]``).
            timeout: Timeout em segundos.

        Returns:
            stdout limpo.

        Raises:
            DeviceConnectionError: em falha ou timeout.
        """
        full_cmd = ["adb"]
        if self.device_id:
            full_cmd += ["-s", self.device_id]
        full_cmd += cmd
        return self._run(full_cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # Conexão ADB
    # ------------------------------------------------------------------
    def connect_adb(self) -> bool:
        """Inicia o adb server, lista dispositivos e conecta via Wi-Fi se pedido.

        Aguarda até 15s que o dispositivo alvo atinja o estado ``device``
        (diferente de ``offline``/``unauthorized``).

        Returns:
            True se o dispositivo está ``device`` (pronto para uso).

        Raises:
            DeviceConnectionError: se nenhum dispositivo ficar pronto no timeout.
        """
        logger.info("Iniciando servidor ADB...")
        try:
            self._run(["adb", "start-server"], timeout=30)
        except DeviceConnectionError as exc:
            raise DeviceConnectionError(
                "Não foi possível iniciar o servidor adb. "
                "Verifique se o Android Platform Tools está instalado e no PATH."
            ) from exc

        if self.wifi_target:
            logger.info("Conectando via Wi-Fi em %s ...", self.wifi_target)
            # `adb connect` retorna rc=0 mesmo quando já conectado; não é check fatal.
            out = self._run(["adb", "connect", self.wifi_target], check=False)
            logger.debug("adb connect: %s", out)

        deadline = time.time() + CONNECT_TIMEOUT
        last_state = "none"
        while time.time() < deadline:
            serials = self._list_devices()
            if not serials:
                last_state = "nenhum dispositivo"
                time.sleep(1)
                continue

            # Escolhe o dispositivo: o explicitado ou o primeiro disponível.
            target_serial = self.device_id or serials[0][0]
            state = dict(serials).get(target_serial, "absent")

            if state == "device":
                self.device_id = target_serial
                logger.info("Dispositivo pronto: %s", target_serial)
                return True
            if state == "unauthorized":
                raise DeviceConnectionError(
                    f"Dispositivo {target_serial} está AUNAUTHORIZED. "
                    "Aceite a depuração USB no aparelho e tente novamente."
                )
            last_state = state
            logger.debug("Aguardando estado 'device' (atual: %s)", state)
            time.sleep(1)

        available = ", ".join(f"{s}={st}" for s, st in serials) or "nenhum"
        raise DeviceConnectionError(
            f"Dispositivo não ficou pronto em {CONNECT_TIMEOUT}s "
            f"(estado: {last_state}). Dispositivos vistos: {available}"
        )

    def _list_devices(self) -> List[tuple]:
        """Lista pares ``(serial, estado)`` reportados por ``adb devices``.

        Returns:
            Lista de tuplas ``(serial, state)`` ignorando a linha do daemon.
        """
        try:
            out = self._run(["adb", "devices"], timeout=10)
        except DeviceConnectionError:
            logger.warning("Falha ao listar dispositivos adb", exc_info=True)
            return []
        devices: List[tuple] = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                devices.append((parts[0], parts[1]))
        return devices

    # ------------------------------------------------------------------
    # Informações do dispositivo
    # ------------------------------------------------------------------
    def get_device_info(self) -> dict:
        """Coleta informações do dispositivo alvo.

        Returns:
            Dict com chaves: ``serial``, ``model``, ``android_version``,
            ``sdk``, ``abi``, ``is_rooted_shell``.

        Raises:
            DeviceConnectionError: se algum comando essencial falhar.
        """
        if self._device_info is not None:
            return dict(self._device_info)

        serial = self.device_id or "unknown"
        model = self._getprop("ro.product.model") or "unknown"
        android_version = self._getprop("ro.build.version.release") or "unknown"
        sdk = self._getprop("ro.build.version.sdk") or "unknown"
        abi = self._detect_abi()
        is_rooted = self.verify_root_access()

        info = {
            "serial": serial,
            "model": model,
            "android_version": android_version,
            "sdk": sdk,
            "abi": abi,
            "is_rooted_shell": is_rooted,
        }
        self._device_info = info
        logger.info(
            "Dispositivo: %s (%s, Android %s, %s)",
            model, serial, android_version, abi,
        )
        return dict(info)

    def _getprop(self, prop: str) -> str:
        """Lê uma propriedade Android via ``getprop``.

        Args:
            prop: Nome da propriedade (ex: ``ro.product.model``).

        Returns:
            Valor da propriedade ou string vazia se ausente.
        """
        try:
            return self._run_adb(["shell", "getprop", prop], timeout=10)
        except DeviceConnectionError:
            logger.warning("Falha ao ler propriedade %s", prop, exc_info=True)
            return ""

    def verify_root_access(self) -> bool:
        """Verifica se o shell ADB roda como root.

        Executa ``adb shell id`` e procura por ``uid=0(root)``.

        Returns:
            True se o shell tem privilégios de root.
        """
        try:
            out = self._run_adb(["shell", "id"], timeout=10)
        except DeviceConnectionError:
            logger.warning("Não foi possível executar 'id' no dispositivo", exc_info=True)
            return False
        rooted = "uid=0(root)" in out
        logger.debug("shell id: %s -> rooted=%s", out, rooted)
        return rooted

    def _detect_abi(self) -> str:
        """Detecta a ABI primária do dispositivo.

        Returns:
            ``'arm64-v8a'``, ``'armeabi-v7a'`` ou ``'x86_64'``
            (fallback: ``'armeabi-v7a'``).

        Raises:
            DeviceConnectionError: se o getprop falhar.
        """
        if self._abi:
            return self._abi
        abi = self._getprop("ro.product.cpu.abi")
        if not abi:
            # Fallback tolerante: tenta o primeiro item da lista de ABIs.
            abi_list = self._getprop("ro.product.cpu.abilist")
            abi = abi_list.split(",")[0].strip() if abi_list else "armeabi-v7a"
        if abi not in ("arm64-v8a", "armeabi-v7a", "x86_64"):
            # Mapeia ABI desconhecidas para a mais próxima esperada pelo Frida.
            if abi.startswith("arm64"):
                abi = "arm64-v8a"
            elif abi.startswith("armeabi"):
                abi = "armeabi-v7a"
            elif abi.startswith("x86_64"):
                abi = "x86_64"
            else:
                logger.warning("ABI desconhecida %r, usando armeabi-v7a", abi)
                abi = "armeabi-v7a"
        self._abi = abi
        logger.debug("ABI detectada: %s", abi)
        return abi

    # ------------------------------------------------------------------
    # Frida server
    # ------------------------------------------------------------------
    def _local_frida_version(self) -> str:
        """Retorna a versão do pacote frida instalado localmente.

        Returns:
            Versão no formato ``X.Y.Z``.

        Raises:
            FridaSetupError: se o pacote frida não estiver importável.
        """
        if frida is None:
            raise FridaSetupError(
                "Pacote 'frida' não instalado. Execute: pip install -r requirements.txt"
            )
        return frida.__version__

    def kill_frida_server(self) -> None:
        """Mata processos frida-server existentes antes de subir um novo.

        Tenta ``pkill -f frida-server`` e, como fallback, ``killall``.
        Nunca propaga exceção — é uma operação de limpeza.

        Returns:
            None.
        """
        logger.debug("Encerrando frida-server existente (se houver)...")
        for cmd in (
            ["shell", "pkill", "-f", "frida-server"],
            ["shell", "killall", "frida-server"],
        ):
            try:
                self._run_adb(cmd, timeout=10)
            except DeviceConnectionError:
                # pkill/killall retornam rc!=0 quando não há processo — normal.
                logger.debug("Nenhum processo para encerrar via %s", cmd[-1])
        time.sleep(0.5)

    def _frida_binary_name(self) -> str:
        """Nome do binário frida-server na release do GitHub.

        Returns:
            Ex: ``frida-server-16.2.1-android-arm64``.
        """
        version = self._local_frida_version()
        abi = self._detect_abi()
        return f"frida-server-{version}-android-{abi}"

    def _ensure_frida_binary(self, dest_dir: str) -> str:
        """Garante que o binário frida-server compatível exista localmente.

        Verifica cache local (``~/.raspilot/cache``); se ausente, baixa a
        release correspondente à versão local do frida e extrai o xz.

        Args:
            dest_dir: Diretório onde extrair o binário.

        Returns:
            Caminho absoluto do binário frida-server extraído.

        Raises:
            FridaSetupError: em falha de download ou extração.
        """
        bin_name = self._frida_binary_name()
        cache_dir = os.path.join(os.path.expanduser("~"), ".raspilot", "cache")
        os.makedirs(cache_dir, exist_ok=True)
        cached = os.path.join(cache_dir, bin_name)
        if os.path.isfile(cached) and os.path.getsize(cached) > 0:
            logger.debug("Binário em cache: %s", cached)
            return cached

        version = self._local_frida_version()
        abi = self._detect_abi()
        url = (
            "https://github.com/frida/frida/releases/download/"
            f"{version}/{bin_name}.xz"
        )
        xz_path = os.path.join(dest_dir, bin_name + ".xz")
        logger.info("Baixando frida-server %s (%s)...", version, abi)
        logger.debug("URL: %s", url)
        try:
            # urllib em vez de curl/wget para evitar dependência extra.
            import urllib.error
            import urllib.request

            req = urllib.request.Request(url, headers={"User-Agent": TOOL_NAME})
            with urllib.request.urlopen(req, timeout=120) as resp, open(xz_path, "wb") as out:
                shutil.copyfileobj(resp, out)
        except (urllib.error.URLError, OSError) as exc:
            raise FridaSetupError(
                f"Falha ao baixar frida-server de {url}: {exc}"
            ) from exc

        # Extrai xz via lzma (stdlib) — sem depender de binário `xz` do sistema.
        try:
            import lzma

            with lzma.open(xz_path, "rb") as src, open(cached, "wb") as dst:
                shutil.copyfileobj(src, dst)
        except (lzma.LZMAError, OSError) as exc:
            raise FridaSetupError(f"Falha ao extrair {xz_path}: {exc}") from exc

        os.chmod(cached, 0o755)
        logger.info("Binário frida-server preparado: %s", cached)
        return cached

    def setup_frida_server(self) -> bool:
        """Sobe o frida-server no dispositivo (pipeline completo).

        Passos: detecta ABI, garante binário compatível, faz push para
        ``/data/local/tmp/``, aplica ``chmod +x``, mata instâncias antigas,
        inicia em background com ``nohup`` e valida via ``frida-ps -U``.

        Returns:
            True se o frida-server está respondendo (``frida-ps -U`` ok).

        Raises:
            FridaSetupError: em qualquer etapa do pipeline.
        """
        logger.info("Configurando frida-server no dispositivo...")
        abi = self._detect_abi()
        logger.debug("ABI: %s", abi)

        with tempfile.TemporaryDirectory(prefix="raspilot_frida_") as tmp:
            local_bin = self._ensure_frida_binary(tmp)
            remote_path = "/data/local/tmp/frida-server"

            try:
                self._run_adb(["push", local_bin, remote_path], timeout=120)
                self._run_adb(["shell", "chmod", "755", remote_path])
            except DeviceConnectionError as exc:
                raise FridaSetupError(f"Falha ao fazer push do frida-server: {exc}") from exc

        # Sobe com root quando disponível (necessário para attach em apps de outros usuários).
        self.kill_frida_server()
        try:
            self._run_adb(["shell", f"nohup {remote_path} >/dev/null 2>&1 &"], timeout=15)
        except DeviceConnectionError as exc:
            raise FridaSetupError(f"Falha ao iniciar frida-server: {exc}") from exc

        # Aguarda o servidor responder no host.
        if not self._wait_frida_ready(timeout=15):
            raise FridaSetupError(
                "frida-server não respondeu via `frida-ps -U` em 15s. "
                "Verifique se a versão do frida local corresponde à do servidor."
            )

        self.frida_ready = True
        logger.info("frida-server ativo e validado via frida-ps -U")
        return True

    def _wait_frida_ready(self, timeout: int = 15) -> bool:
        """Aguarda o frida-server ficar acessível pelo host.

        Args:
            timeout: Tempo máximo em segundos.

        Returns:
            True se ``frida-ps -U`` retornar com sucesso dentro do timeout.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self._run(["frida-ps", "-U"], timeout=10)
                return True
            except DeviceConnectionError:
                logger.debug("frida-ps ainda não responde, tentando novamente...")
                time.sleep(1)
        return False

    def remove_frida_server(self) -> None:
        """Remove o binário temporário do dispositivo (cleanup final).

        Executa ``rm -f /data/local/tmp/frida-server`` e encerra o processo.

        Returns:
            None.
        """
        logger.debug("Limpando frida-server do dispositivo...")
        try:
            self.kill_frida_server()
            self._run_adb(["shell", "rm", "-f", "/data/local/tmp/frida-server"], timeout=10)
            for extra in (
                "/data/local/tmp/re.frida.server",
                "/data/local/tmp/fs",
            ):
                self._run_adb(["shell", "rm", "-rf", extra], timeout=10)
        except DeviceConnectionError:
            logger.warning("Falha ao limpar arquivos temporários", exc_info=True)
        self.frida_ready = False

    # ------------------------------------------------------------------
    # Integração Frida (host)
    # ------------------------------------------------------------------
    def _require_frida(self):
        """Retorna o módulo ``frida`` ou levanta erro instrutivo.

        Returns:
            Módulo frida importado.

        Raises:
            FridaSetupError: se frida não estiver instalado.
        """
        if frida is None:
            raise FridaSetupError(
                "Pacote 'frida' não instalado. Execute: pip install -r requirements.txt"
            )
        return frida

    def _frida_device(self):
        """Retorna o objeto ``frida.core.Device`` alvo.

        Returns:
            Dispositivo Frida correspondente a ``self.device_id``.

        Raises:
            FridaSetupError: se o dispositivo não for encontrado.
        """
        f = self._require_frida()
        serial = self.device_id
        if serial:
            try:
                return f.get_device(serial)
            except Exception as exc:
                raise FridaSetupError(f"Dispositivo Frida {serial} não encontrado: {exc}") from exc
        # Sem serial explícito: primeiro dispositivo USB/remoto disponível.
        manager = f.get_device_manager()
        devices = [
            d for d in manager.enumerate_devices() if d.type in ("usb", "remote", "local")
        ]
        if not devices:
            raise FridaSetupError("Nenhum dispositivo Frida disponível.")
        return devices[0]

    def spawn_app(self, package_name: str) -> "frida.core.Session":
        """Spawna o app e retorna a sessão Frida já anexada (com resume).

        Args:
            package_name: Package name do app alvo (ex: ``com.example.app``).

        Returns:
            Sessão Frida ativa após ``resume(pid)``.

        Raises:
            FridaSetupError: se o spawn falhar.
        """
        f = self._require_frida()
        device = self._frida_device()
        logger.info("Spawning %s...", package_name)
        try:
            pid = device.spawn([package_name])
            session = device.attach(pid)
            device.resume(pid)
        except Exception as exc:  # frida raising frida.core.ExecutableNotFoundError etc.
            raise FridaSetupError(f"Falha ao spawna {package_name}: {exc}") from exc
        time.sleep(1.0)  # aguarda a Activity subir
        logger.info("App spawna (pid=%s), sessão anexada", pid)
        return session

    def attach_app(self, package_name: str) -> "frida.core.Session":
        """Anexa a um processo do app já em execução.

        Args:
            package_name: Package name do app alvo.

        Returns:
            Sessão Frida ativa.

        Raises:
            FridaSetupError: se o processo não existir ou o attach falhar.
        """
        f = self._require_frida()
        device = self._frida_device()
        logger.info("Anexando a %s...", package_name)
        try:
            pid = device.get_process(package_name).pid
            session = device.attach(pid)
        except Exception as exc:
            raise FridaSetupError(
                f"Falha ao anexar em {package_name} (app rodando?): {exc}"
            ) from exc
        logger.info("Anexado a %s (pid=%s)", package_name, pid)
        return session

    def get_app_pid(self, package_name: str) -> Optional[int]:
        """Retorna o PID do processo do app, se estiver em execução.

        Args:
            package_name: Package name do app alvo.

        Returns:
            PID ou ``None`` se o processo não estiver rodando.
        """
        try:
            f = self._require_frida()
            device = self._frida_device()
            return device.get_process(package_name).pid
        except Exception:
            return None

    def list_running_processes(self) -> List[str]:
        """Lista processos visíveis no dispositivo (equivalente a ``frida-ps -U``).

        Returns:
            Lista de nomes de processos.

        Raises:
            FridaSetupError: se o frida server não responder.
        """
        f = self._require_frida()
        device = self._frida_device()
        try:
            return [p.name for p in device.enumerate_processes()]
        except Exception as exc:
            raise FridaSetupError(f"Falha ao listar processos: {exc}") from exc
