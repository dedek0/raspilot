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
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from typing import Deque, List, Optional, Tuple

from logcat_analyzer import analyze_logcat, analyze_since

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

# Intervalo entre as tentativas de conexão.
CONNECT_RETRY_INTERVAL = 1.0

# Intervalo entre as consultas de pid durante o baseline.
BASELINE_POLL_INTERVAL = 1.0

# Tempo máximo de espera pelo app alvo ficar em foco antes de carregar a
# camada Java. É um limite de paciência, não uma garantia: um app lento
# (splash longo) pode demorar mais, e forçar o prazo aqui só adia o
# carregamento da bridge, que já tem o próprio timeout.
APP_READY_TIMEOUT = 8.0

# Intervalo entre as consultas de foco do app alvo.
APP_READY_POLL = 0.5

# Stealth do frida-server: porta não-padrão + nome de binário opaco.
# Apps com anti-frida varrem /proc/net/tcp pelas portas 27042/27043
# (:69A2/:69A3) e o `ps`/paths pelo nome 'frida-server' — evitar esses
# dois artefatos óbvios remove o gatilho mais barato de auto-destruição
# (o port-scan via /proc/net/tcp foi confirmado no dex de um alvo real).
# A porta pode ser sobrescrita com RASPILOT_FRIDA_PORT.
FRIDA_PORT = int(os.environ.get("RASPILOT_FRIDA_PORT", "27999"))
FRIDA_REMOTE_PATH = "/data/local/tmp/.lloader"

# Rename das strings do memfd do agente no binário do servidor (mesmo
# tamanho ⇒ patch binário seguro). O agente injetado aparece em
# /proc/self/maps como ``/memfd:frida-agent-64.so (deleted)`` — o
# vetor de detecção anti-frida mais comum (leitura direta do maps,
# inclusive via syscall raw, fora do alcance de hooks de libc).
MEMFD_RENAMES: Tuple[bytes, bytes] = (
    (b"frida-agent-64.so", b"libloader64_v8.so"),
    (b"frida-agent-32.so", b"libloader32_v7.so"),
)


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
        self._su_ok: Optional[bool] = None
        self.last_spawn_pid: Optional[int] = None
        self.last_spawn_package: Optional[str] = None
        self._pending_resume: Optional[tuple] = None
        self.frida_ready: bool = False
        self.frida_port: int = FRIDA_PORT

        # Baseline sem instrumentação (preenchido por run_app_baseline).
        self.baseline: Optional[dict] = None

        # Captura contínua de logcat (thread leitora + buffer circular).
        self._logcat_proc: Optional[subprocess.Popen] = None
        self._logcat_thread: Optional[threading.Thread] = None
        self._logcat_lines: Deque[str] = deque(maxlen=50000)
        self._logcat_count = 0
        self._logcat_lock = threading.Lock()
        self._logcat_available = False

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

    def run_shell(self, command: str, timeout: int = DEFAULT_ADB_TIMEOUT) -> dict:
        """Executa um comando shell no dispositivo **sem** levantar exceção.

        Pensado para os checks de auditoria: qualquer falha (dispositivo
        offline, comando inexistente, permissão negada) é capturada e
        devolvida estruturada, para que o check registre ``error`` e
        continue com os demais vetores.

        Args:
            command: Comando shell completo (ex: ``"ls /system/bin/su"``).
                Pode usar pipes/redirecionamentos — o shell do dispositivo
                processa a string inteira.
            timeout: Timeout em segundos.

        Returns:
            Dict com ``ok`` (bool), ``rc`` (int), ``stdout`` e ``stderr``
            (str). Em falha de execução local: ``ok=False, rc=-1``.
        """
        full_cmd = ["adb"]
        if self.device_id:
            full_cmd += ["-s", self.device_id]
        full_cmd += ["shell", command]
        try:
            proc = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
            return {
                "ok": proc.returncode == 0,
                "rc": proc.returncode,
                "stdout": (proc.stdout or "").strip(),
                "stderr": (proc.stderr or "").strip(),
            }
        except FileNotFoundError as exc:
            logger.warning("adb não encontrado no PATH: %s", exc)
            return {"ok": False, "rc": -1, "stdout": "", "stderr": str(exc)}
        except subprocess.TimeoutExpired:
            logger.warning("Timeout (%ss) no shell: %s", timeout, command)
            return {
                "ok": False,
                "rc": -1,
                "stdout": "",
                "stderr": f"timeout após {timeout}s",
            }

    def run_shell_root(self, command: str, timeout: int = DEFAULT_ADB_TIMEOUT) -> dict:
        """Executa um comando shell elevando privilégios quando possível.

        Muitos paths relevantes para auditoria (``/data/adb/ap``,
        ``/data/adb/magisk``, etc.) são ``drwx------ root`` e invisíveis
        ao usuário ``shell`` (uid 2000). Este helper reusa
        :meth:`_su_cmd`, que envolve o comando em ``su -c`` quando há root
        via ``su`` (APatch/Magisk/KernelSU) e devolve o comando original
        caso contrário.

        Args:
            command: Comando shell completo.
            timeout: Timeout em segundos.

        Returns:
            Mesmo contrato de :meth:`run_shell`.
        """
        return self.run_shell(self._su_cmd(command), timeout=timeout)

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
                time.sleep(CONNECT_RETRY_INTERVAL)
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
            time.sleep(CONNECT_RETRY_INTERVAL)

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
    # Logcat
    # ------------------------------------------------------------------
    def start_logcat_capture(self) -> bool:
        """Inicia a captura contínua de logcat em uma thread de fundo.

        O buffer é circular (50k linhas) e cada check recebe um marcador
        (:meth:`logcat_mark`) para analisar apenas as linhas do seu
        intervalo. Nunca propaga exceção: em ambientes sem ``adb`` a
        captura fica indisponível e os checks usam um snapshot sob
        demanda.

        Returns:
            True se o processo de logcat foi iniciado.
        """
        if self._logcat_proc is not None:
            return True

        cmd = ["adb"]
        if self.device_id:
            cmd += ["-s", self.device_id]
        # O buffer "crash" traz o backtrace completo do tombstone: é o
        # que permite distinguir "o app se protegeu" de "a instrumentação
        # derrubou o app". Não exige root.
        cmd += ["logcat", "-b", "main", "-b", "crash", "-v", "threadtime"]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                errors="replace",
            )
        except (FileNotFoundError, OSError) as exc:
            logger.warning("logcat indisponível: %s", exc)
            self._logcat_available = False
            return False

        self._logcat_proc = proc
        self._logcat_available = True

        def _reader() -> None:
            try:
                if proc.stdout is None:
                    return
                for line in proc.stdout:
                    with self._logcat_lock:
                        self._logcat_lines.append(line.rstrip("\n"))
                        self._logcat_count += 1
            except Exception:  # noqa: BLE001 - leitura encerrada é esperada
                logger.debug("Thread de logcat encerrou", exc_info=True)

        self._logcat_thread = threading.Thread(
            target=_reader, name="raspilot-logcat", daemon=True
        )
        self._logcat_thread.start()
        logger.debug("Captura de logcat iniciada (%s)", " ".join(cmd))
        return True

    def stop_logcat_capture(self) -> None:
        """Encerra a captura de logcat e a thread leitora.

        Returns:
            None.
        """
        proc = self._logcat_proc
        thread = self._logcat_thread
        self._logcat_proc = None
        self._logcat_thread = None
        self._logcat_available = False
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:  # noqa: BLE001 - processo já encerrado
                try:
                    proc.kill()
                except Exception:
                    logger.debug("Falha ao encerrar logcat", exc_info=True)
        if thread is not None:
            thread.join(timeout=2)

    def logcat_mark(self) -> int:
        """Retorna o índice atual (monotônico) do buffer de logcat.

        Returns:
            Número de linhas já capturadas desde o início da sessão.
        """
        with self._logcat_lock:
            return self._logcat_count

    def logcat_since(self, mark: int = 0) -> List[str]:
        """Retorna as linhas de logcat posteriores a um marcador.

        Se a captura contínua não estiver ativa, tenta um snapshot
        ``logcat -d -t 500`` para ainda fornecer evidências.

        Args:
            mark: Marcador retornado por :meth:`logcat_mark`.

        Returns:
            Lista de linhas (possivelmente vazia).
        """
        with self._logcat_lock:
            # Índice da primeira linha ainda presente no deque.
            first_available = self._logcat_count - len(self._logcat_lines)
            start = int(mark or 0) - first_available
            if start < 0:
                start = 0
            if start > len(self._logcat_lines):
                start = len(self._logcat_lines)
            captured = list(self._logcat_lines)[start:]

        if captured:
            return captured
        if self._logcat_proc is not None:
            return []

        res = self.run_shell("logcat -d -v threadtime -t 500 2>/dev/null", timeout=10)
        if res.get("ok") and res.get("stdout"):
            return res["stdout"].splitlines()
        return []

    def run_app_baseline(self, package_name: str, window: int = 5) -> dict:
        """Executa o app sem instrumentação para estabelecer um baseline.

        O baseline responde: "o app já morre sozinho após o launch?".
        Sem ele, uma morte durante a observação com Frida pode ser
        confundida com reação do RASP, quando na verdade é crash/lifecycle
        normal. Também captura o logcat do intervalo.

        Args:
            package_name: Package name do app alvo.
            window: Tempo de observação em segundos.

        Returns:
            Dict com ``available``, ``pid``, ``alive_at_end``,
            ``died_after``, ``death_cause`` e ``logcat``.
        """
        mark = self.logcat_mark()
        result: dict = {
            "available": False,
            "package": package_name,
            "pid": None,
            "alive_at_end": None,
            "died_after": None,
            "death_cause": None,
            "logcat": analyze_logcat([], package=package_name),
            "window": window,
        }
        try:
            self.run_shell(f"am force-stop {package_name}", timeout=10)
            launch = self.run_shell(
                f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
                timeout=20,
            )
            logger.debug("Baseline launch: rc=%s %s", launch.get("rc"), launch.get("stderr"))

            pid: Optional[int] = None
            for _ in range(5):
                res = self.run_shell(f"pidof -s {package_name} 2>/dev/null", timeout=5)
                value = (res.get("stdout") or "").strip()
                if res.get("ok") and value.isdigit():
                    pid = int(value)
                    break
                time.sleep(BASELINE_POLL_INTERVAL)

            if pid is None:
                result["reason"] = "app não iniciou (sem pid)"
                return result

            result["available"] = True
            result["pid"] = pid
            died_after: Optional[int] = None
            for elapsed in range(max(1, int(window))):
                time.sleep(BASELINE_POLL_INTERVAL)
                if not self.is_app_alive(pid):
                    died_after = elapsed + 1
                    break
            result["died_after"] = died_after
            result["alive_at_end"] = died_after is None
            if died_after is not None:
                result["death_cause"] = self.capture_death_cause(
                    pid=pid, package=package_name
                )
            result["logcat"] = analyze_since(
                self, mark, package=package_name, pid=pid
            )
            logger.info(
                "Baseline: pid=%s alive=%s died_after=%s",
                pid, result["alive_at_end"], died_after,
            )
            return result
        finally:
            try:
                self.run_shell(f"am force-stop {package_name}", timeout=10)
            except Exception:
                logger.debug("Falha ao encerrar baseline", exc_info=True)

    # ------------------------------------------------------------------
    # Informações do dispositivo
    # ------------------------------------------------------------------
    def get_device_info(self) -> dict:
        """Coleta informações do dispositivo alvo.

        Returns:
            Dict com chaves: ``serial``, ``model``, ``android_version``,
            ``sdk``, ``abi``, ``is_rooted_shell`` (shell ADB é uid 0) e
            ``root_via_su`` (root disponível via ``su``).

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
        root_via_su = self.has_su_access()

        info = {
            "serial": serial,
            "model": model,
            "android_version": android_version,
            "sdk": sdk,
            "abi": abi,
            "is_rooted_shell": is_rooted,
            "root_via_su": root_via_su,
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

    def has_su_access(self) -> bool:
        """Verifica se root está disponível via ``su -c`` (APatch/Magisk/SuperSU).

        O shell ADB em aparelhos rooteados normalmente roda como ``shell``
        (uid 2000), mas o ``su`` permite elevar privilégios — necessário
        para spawna/attach de apps não-debuggable de outros usuários.

        Returns:
            True se ``su -c id`` retornar ``uid=0(root)``.
        """
        if self._su_ok is not None:
            return self._su_ok
        res = self.run_shell("su -c id", timeout=10)
        rooted = res["ok"] and "uid=0" in res["stdout"]
        logger.debug("su -c id: ok=%s stdout=%r -> rooted=%s", res["ok"], res["stdout"], rooted)
        self._su_ok = rooted
        return rooted

    def _su_cmd(self, command: str) -> str:
        """Envolve um comando shell com ``su -c`` quando root via su existe.

        Args:
            command: Comando shell a elevar.

        Returns:
            ``su -c '<command>'`` ou o comando original (sem root).
        """
        if self.has_su_access():
            escaped = command.replace("'", "'\\''")
            return f"su -c '{escaped}'"
        return command

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
        if abi not in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64", "riscv64"):
            # Mapeia ABI desconhecidas para a mais próxima esperada pelo Frida.
            if abi.startswith("arm64"):
                abi = "arm64-v8a"
            elif abi.startswith("armeabi"):
                abi = "armeabi-v7a"
            elif abi.startswith("x86_64"):
                abi = "x86_64"
            elif abi.startswith("x86"):
                abi = "x86"
            elif abi.startswith("riscv64"):
                abi = "riscv64"
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

        Tenta ``pkill``/``killall`` como shell e, quando disponível,
        via ``su -c`` (o frida-server root não morre via shell).
        Nunca propaga exceção — é uma operação de limpeza.

        Returns:
            None.
        """
        logger.debug("Encerrando frida-server existente (se houver)...")
        base_cmds = (
            "pkill -f frida-server",
            "killall frida-server",
            f"pkill -f {FRIDA_REMOTE_PATH}",
            "pkill -f .lloader",  # binário stealth do RASPilot
            # Fallback por PID: alguns ROMs não têm pkill/ps completo e o
            # nome truncado pode escapar do pkill -f.
            "for p in $(pidof .lloader 2>/dev/null) $(pidof frida-server 2>/dev/null); "
            "do kill -9 $p 2>/dev/null; done",
        )
        for cmd in base_cmds:
            for wrapped in (cmd, self._su_cmd(cmd)):
                try:
                    self.run_shell(wrapped, timeout=10)
                except DeviceConnectionError:
                    logger.debug("Nenhum processo para encerrar via %s", wrapped)
        time.sleep(0.5)

    def _frida_binary_name(self) -> str:
        """Nome do binário frida-server na release do GitHub.

        Mapeia a ABI Android para o nome de arquitetura usado nas assets
        do Frida (``arm64-v8a``→``arm64``, ``armeabi-v7a``→``arm``,
        ``x86_64``→``x86_64``).

        Returns:
            Ex: ``frida-server-17.23.3-android-arm64``.
        """
        version = self._local_frida_version()
        abi = self._detect_abi()
        arch = {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86": "x86",
            "x86_64": "x86_64",
            "riscv64": "riscv64",
        }.get(abi, "arm64")
        return f"frida-server-{version}-android-{arch}"

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

    @staticmethod
    def _patch_frida_binary(src: str, dst: str) -> int:
        """Copia o binário do frida-server renomeando strings do memfd.

        Aplica :data:`MEMFD_RENAMES` (trocas de mesmo tamanho, seguras
        binariamente) para que o agente injetado apareça em
        ``/proc/self/maps`` com nome opaco em vez de ``frida-agent``.

        Args:
            src: Binário original (cache local).
            dst: Caminho de saída do binário patcheado.

        Returns:
            Número de strings substituídas.
        """
        with open(src, "rb") as fh:
            data = fh.read()
        replacements = 0
        for old, new in MEMFD_RENAMES:
            count = data.count(old)
            if count:
                data = data.replace(old, new)
                replacements += count
        with open(dst, "wb") as fh:
            fh.write(data)
        os.chmod(dst, 0o755)
        logger.debug(
            "Binário patcheado: %d string(s) de memfd renomeada(s)", replacements
        )
        return replacements

    def setup_frida_server(self) -> bool:
        """Sobe o frida-server no dispositivo (pipeline completo, stealth).

        Passos: detecta ABI, garante binário compatível, faz push para
        ``/data/local/tmp/.lloader`` (nome opaco), aplica ``chmod +x``,
        mata instâncias antigas, inicia em background escutando em
        ``127.0.0.1:<FRIDA_PORT>`` (porta não-padrão), encaminha a porta
        via ``adb forward`` e valida via ``frida-ps -H``.

        Returns:
            True se o frida-server está respondendo.

        Raises:
            FridaSetupError: em qualquer etapa do pipeline.
        """
        logger.info("Configurando frida-server stealth (porta %s)...", FRIDA_PORT)
        abi = self._detect_abi()
        logger.debug("ABI: %s", abi)

        with tempfile.TemporaryDirectory(prefix="raspilot_frida_") as tmp:
            local_bin = self._ensure_frida_binary(tmp)
            # Patch de stealth: renomeia o memfd do agente no binário.
            patched_bin = os.path.join(tmp, "server.bin")
            self._patch_frida_binary(local_bin, patched_bin)
            remote_path = FRIDA_REMOTE_PATH

            try:
                self._run_adb(["push", patched_bin, remote_path], timeout=120)
                self._run_adb(["shell", "chmod", "755", remote_path])
            except DeviceConnectionError as exc:
                raise FridaSetupError(f"Falha ao fazer push do frida-server: {exc}") from exc

        # Sobe com root quando disponível (necessário para attach/spawn de
        # apps não-debuggable de outros usuários). Escuta em loopback na
        # porta não-padrão — acessível via adb forward.
        listen = f"-l 127.0.0.1:{FRIDA_PORT}"
        self.kill_frida_server()
        try:
            if self.verify_root_access():
                # Shell ADB já é root — direto (daemoniza).
                self.run_shell(f"{remote_path} -D {listen}", timeout=15)
            elif self.has_su_access():
                # Root via su (APatch/Magisk): eleva para rodar o servidor.
                # nohup + & dentro do su: o shell do dispositivo retorna na
                # hora e o daemon não herda os pipes do adb (evita timeout).
                su_wrapped = self._su_cmd(
                    f"nohup {remote_path} {listen} >/dev/null 2>&1 &"
                )
                self.run_shell(su_wrapped, timeout=15)
            else:
                # Último recurso: como shell (só serve para apps debuggable).
                logger.warning(
                    "Root indisponível — frida-server rodará como shell; "
                    "spawn de apps não-debuggable pode falhar."
                )
                self.run_shell(
                    f"nohup {remote_path} {listen} >/dev/null 2>&1 &", timeout=15
                )
        except DeviceConnectionError as exc:
            raise FridaSetupError(f"Falha ao iniciar frida-server: {exc}") from exc

        # Tunel do host para a porta do servidor (stealth: só loopback).
        try:
            self._run_adb(
                ["forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}"], timeout=15
            )
        except DeviceConnectionError as exc:
            raise FridaSetupError(f"Falha no adb forward: {exc}") from exc

        # Aguarda o servidor responder no host.
        if not self._wait_frida_ready(timeout=15):
            raise FridaSetupError(
                f"frida-server não respondeu via `frida-ps -H` em 15s "
                f"(porta {FRIDA_PORT}). Verifique se a versão do frida "
                "local corresponde à do servidor."
            )

        self.frida_ready = True
        logger.info("frida-server ativo e validado (porta %s)", FRIDA_PORT)
        return True

    def _wait_frida_ready(self, timeout: int = 15) -> bool:
        """Aguarda o frida-server ficar acessível pelo host (via forward).

        Args:
            timeout: Tempo máximo em segundos.

        Returns:
            True se ``frida-ps -H`` retornar com sucesso dentro do timeout.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self._run(
                    ["frida-ps", "-H", f"127.0.0.1:{FRIDA_PORT}"], timeout=10
                )
                return True
            except DeviceConnectionError:
                logger.debug("frida-ps ainda não responde, tentando novamente...")
                time.sleep(1)
        return False

    def remove_frida_server(self) -> None:
        """Remove o binário temporário do dispositivo (cleanup final).

        Executa ``rm`` do binário stealth e dos nomes legados, encerra o
        processo e remove o ``adb forward``.

        Returns:
            None.
        """
        logger.debug("Limpando frida-server do dispositivo...")
        try:
            self.kill_frida_server()
            rm_cmd = (
                f"rm -rf {FRIDA_REMOTE_PATH} /data/local/tmp/frida-server "
                "/data/local/tmp/re.frida.server /data/local/tmp/fs"
            )
            self.run_shell(rm_cmd, timeout=10)
            if self._su_ok:
                self.run_shell(self._su_cmd(rm_cmd), timeout=10)
        except DeviceConnectionError:
            logger.warning("Falha ao limpar arquivos temporários", exc_info=True)
        try:
            self._run_adb(
                ["forward", "--remove", f"tcp:{FRIDA_PORT}"], timeout=10
            )
        except Exception:
            logger.debug("adb forward já removido ou inexistente", exc_info=True)
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

        Prioriza o servidor stealth do RASPilot (``add_remote_device``
        via ``adb forward`` na :data:`FRIDA_PORT`); como fallback, o
        dispositivo USB/remoto enumerado (ex: servidor iniciado à mão).

        Returns:
            Dispositivo Frida correspondente.

        Raises:
            FridaSetupError: se nenhum dispositivo for encontrado.
        """
        f = self._require_frida()
        manager = f.get_device_manager()
        try:
            return manager.add_remote_device(f"127.0.0.1:{FRIDA_PORT}")
        except Exception as exc:
            logger.debug("add_remote_device falhou (%s); tentando enumeração", exc)
        serial = self.device_id
        if serial:
            try:
                return f.get_device(serial)
            except Exception as exc:
                raise FridaSetupError(f"Dispositivo Frida {serial} não encontrado: {exc}") from exc
        # Sem serial explícito: primeiro dispositivo USB/remoto disponível.
        # Nunca usar 'local': isso injetaria no host, não no Android.
        devices = [
            d for d in manager.enumerate_devices() if d.type in ("usb", "remote")
        ]
        if not devices:
            raise FridaSetupError("Nenhum dispositivo Frida disponível.")
        return devices[0]

    def spawn_app(self, package_name: str, resume: bool = True) -> "frida.core.Session":
        """Spawna o app e retorna a sessão Frida já anexada.

        Com ``resume=False`` o processo fica **suspenso** após o attach —
        permitindo instalar hooks ANTES do código do app rodar (essencial
        para observar/burlar detecções de RASP que executam na inicialização).
        Chame :meth:`resume_app` depois de carregar os scripts.

        Args:
            package_name: Package name do app alvo (ex: ``com.example.app``).
            resume: Se True (default), retoma o processo imediatamente.

        Returns:
            Sessão Frida ativa.

        Raises:
            FridaSetupError: se o spawn falhar.
        """
        f = self._require_frida()
        device = self._frida_device()
        logger.info("Spawning %s... (resume=%s)", package_name, resume)

        # Nunca deixar um spawn anterior suspenso ao iniciar outro.
        self.resume_app()

        pid = None
        try:
            pid = device.spawn([package_name])
            session = device.attach(pid)
        except Exception as exc:  # frida raising frida.core.ExecutableNotFoundError etc.
            # Se o spawn aconteceu mas o attach falhou, o processo ficaria
            # suspenso para sempre. Retoma para não travar o alvo.
            if pid is not None:
                try:
                    device.resume(pid)
                except Exception:
                    logger.debug("Falha ao retomar pid %s após erro de attach", pid, exc_info=True)
            raise FridaSetupError(f"Falha ao spawna {package_name}: {exc}") from exc
        self.last_spawn_pid = pid
        self.last_spawn_package = package_name
        if resume:
            device.resume(pid)
            time.sleep(1.0)  # aguarda a Activity subir
        else:
            self._pending_resume = (device, pid)
        logger.info("App spawna (pid=%s), sessão anexada", pid)
        return session

    def resume_app(self) -> None:
        """Retoma um processo deixado suspenso por ``spawn_app(resume=False)``.

        Idempotente: se não há retomada pendente, é um no-op.

        Returns:
            None.
        """
        if self._pending_resume is None:
            return
        device, pid = self._pending_resume
        self._pending_resume = None
        try:
            device.resume(pid)
            logger.debug("Processo %s retomado", pid)
        except Exception:
            logger.warning("Falha ao retomar pid %s", pid, exc_info=True)

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
            pid = self.get_app_pid(package_name)
            if pid is None:
                raise FridaSetupError(
                    f"Processo de {package_name} não encontrado (app rodando?)"
                )
            session = device.attach(pid)
        except FridaSetupError:
            raise
        except Exception as exc:
            raise FridaSetupError(
                f"Falha ao anexar em {package_name} (app rodando?): {exc}"
            ) from exc
        logger.info("Anexado a %s (pid=%s)", package_name, pid)
        return session

    def get_app_pid(self, package_name: str) -> Optional[int]:
        """Retorna o PID do processo do app, se estiver em execução.

        Tenta ``get_process`` pelo nome e, como fallback, varre
        ``enumerate_processes`` casando pelo nome/package. Se o processo
        sumir (app com anti-debug que se mata), devolve o último PID
        registrado no ``spawn_app`` mais recente.

        Args:
            package_name: Package name do app alvo.

        Returns:
            PID ou ``None`` se o processo não estiver rodando.
        """
        try:
            f = self._require_frida()
            device = self._frida_device()
            try:
                return device.get_process(package_name).pid
            except Exception:
                pass
            for proc in device.enumerate_processes():
                if proc.name == package_name or package_name in proc.name:
                    return proc.pid
        except Exception:
            logger.debug("Falha ao resolver pid de %s", package_name, exc_info=True)

        res = self.run_shell(f"pidof -s {package_name} 2>/dev/null", timeout=10)
        if res["ok"] and res["stdout"].strip().isdigit():
            return int(res["stdout"].strip())

        # Só reaproveita o PID do último spawn se ele pertencer ao mesmo
        # package (evita devolver PID obsoleto de outro app).
        if self.last_spawn_package in (None, package_name):
            return self.last_spawn_pid
        return None

    def wait_for_app_ready(
        self,
        package_name: str,
        timeout: Optional[float] = None,
        poll: float = APP_READY_POLL,
        pid: Optional[int] = None,
    ) -> bool:
        """Aguarda o app alvo ter uma activity em foco.

        A bridge Java do Frida resolve a classe do app pelo class loader
        da aplicação, que só existe depois que o processo cria o
        ``Application``. Enquanto isso não acontece, a bridge fica em
        espera ativa — e a espera bloqueia a thread de JavaScript do
        agente, o que faz o carregamento do script estourar o limite do
        agente e ser descartado no meio.

        A espera é uma otimização, não um pré-requisito: ela é
        interrompida assim que o app entra em foco, assim que o processo
        morre (ele nunca mais vai entrar em foco) e assim que o prazo
        acaba. O carregamento da bridge tem timeout próprio e continua
        mesmo sem a espera.

        Args:
            package_name: Package name do app alvo.
            timeout: Tempo máximo de espera em segundos. ``None`` usa
                :data:`APP_READY_TIMEOUT`.
            poll: Intervalo entre as consultas.
            pid: PID do processo alvo, quando conhecido. Permite encerrar
                a espera assim que o processo morre.

        Returns:
            True se o app ficou em foco dentro do tempo limite.
        """
        limit = APP_READY_TIMEOUT if timeout is None else max(0.0, timeout)
        deadline = time.monotonic() + limit
        while True:
            try:
                out = self.run_shell(
                    "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
                    timeout=8,
                ).get("stdout", "")
                if package_name in out:
                    return True
            except Exception:
                logger.debug("Falha ao consultar a activity em foco", exc_info=True)

            # O app já morreu: ele não vai chegar a ficar em foco, e
            # insistir só consome a janela de observação.
            if pid is not None and not self.is_app_alive(pid):
                return False

            if time.monotonic() >= deadline:
                return False
            time.sleep(poll)

    def is_app_alive(self, pid: int) -> bool:
        """Verifica se um processo continua em execução no dispositivo.

        A verificação usa o **estado** do processo em ``/proc/<pid>/stat``,
        e não apenas a existência do diretório: um processo que já morreu
        permanece como *zumbi* até ser recolhido pelo zygote, e a
        existência do diretório ``/proc/<pid>`` continua verdadeira nesse
        intervalo. Um app que se auto-destruiu (reação do RASP) ficaria
        reportado como vivo durante essa janela — e um bypass avaliado
        nesse instante seria dado como bem-sucedido sobre um processo
        morto.

        Args:
            pid: PID do processo alvo.

        Returns:
            True se o processo existe e não está em estado zumbi ou morto.
        """
        # O campo ``state`` é o terceiro campo de /proc/<pid>/stat, mas o
        # nome do processo (campo 2) pode conter espaços e parênteses: a
        # posição é obtida a partir do último ')' da linha.
        res = self.run_shell(
            f"if [ -r /proc/{pid}/stat ]; then "
            f"sed 's/.*) //' /proc/{pid}/stat | cut -d' ' -f1; fi",
            timeout=5,
        )
        state = (res.get("stdout") or "").strip().split()
        if not state:
            return False
        # 'Z' = zumbi (terminado, aguardando reaping), 'X' = morto.
        return state[0] not in ("Z", "X", "x")

    def capture_death_cause(
        self, pid: Optional[int] = None, package: Optional[str] = None
    ) -> dict:
        """Captura evidências externas de como um processo morreu.

        Lê os buffers de logcat (crash, events e main) em busca de sinais
        fatais (SIGSEGV/SIGABRT), kills do ActivityManager e menções ao
        processo — para distinguir crash nativo, kill externo (SIGKILL) e
        saída limpa quando um RASP se auto-destrói.

        Args:
            pid: PID do processo que morreu (melhora o filtro).
            package: Package name do alvo (melhora o filtro).

        Returns:
            Dict com ``evidence`` (linhas), ``signal`` (ex: ``'SIGSEGV'``,
            ou ``None``) e ``summary`` (str legível).
        """
        needles: List[str] = []
        if pid is not None:
            needles.append(str(pid))
        if package:
            needles.append(package)

        crash_pid_re = (
            re.compile(rf"\bpid:? {re.escape(str(pid))}\b")
            if pid is not None
            else None
        )

        evidence: List[str] = []
        death_keywords = (
            "fatal signal", "sigsegv", "sigabrt", "sigbus", "sigkill",
            "native crash", "tombstone", "has died", "am_proc_died",
            "am_kill", "killing ", "force stop", "fatal exception",
            "anr in", "application not responding", "exited due to signal",
        )
        # crash: com pid conhecido, exige o pid como palavra na linha
        # (evita atribuir crash antigo cujo endereço/pid contenha o nº
        # por acaso); sem pid, aceita linhas fatais genéricas.
        # events: só linhas que citam o alvo.
        # main: só linhas que citam o alvo E têm conteúdo de morte (evita
        # despejar centenas de logs normais no relatório).
        for cmd, tag, generic_ok in (
            ("logcat -d -b crash -t 300 2>/dev/null", "crash", pid is None),
            ("logcat -d -b events -t 500 2>/dev/null", "events", False),
            ("logcat -d -t 400 2>/dev/null", "main", False),
        ):
            res = self.run_shell(cmd, timeout=10)
            if not res["ok"]:
                continue
            for line in res["stdout"].splitlines():
                low = line.lower()
                if tag == "crash" and crash_pid_re is not None:
                    matched = bool(crash_pid_re.search(line))
                elif tag == "main":
                    matched = any(n in line for n in needles) and any(
                        k in low for k in death_keywords
                    )
                else:
                    matched = any(n in line for n in needles)
                if matched:
                    evidence.append(f"{tag}: {line.strip()}")
                    continue
                if not generic_ok:
                    continue
                if any(k in low for k in death_keywords):
                    evidence.append(f"{tag}: {line.strip()}")

        signal: Optional[str] = None
        signal_nr: Optional[int] = None
        for line in evidence:
            m = re.search(r"Fatal signal \d+ \((SIG[A-Z]+)\)", line)
            if m:
                signal = m.group(1)
                break
            m = re.search(r"exited due to signal (\d+)", line)
            if m and signal is None:
                # Morte por sinal fora do processo (ex: 9 = SIGKILL).
                signal_nr = int(m.group(1))
        if signal is None and signal_nr is not None:
            signal = {9: "SIGKILL", 6: "SIGABRT", 11: "SIGSEGV"}.get(
                signal_nr, f"signal {signal_nr}"
            )

        if signal == "SIGKILL":
            summary = "SIGKILL (morte por sinal — não interceptável in-process)"
        elif signal:
            summary = f"sinal fatal {signal}"
        elif evidence:
            summary = "morte registrada em logcat"
        else:
            summary = "sem registro externo (SIGKILL externo ou exit_group direto)"

        logger.debug(
            "capture_death_cause: pid=%s signal=%s linhas=%d",
            pid, signal, len(evidence),
        )
        return {"evidence": evidence[-40:], "signal": signal, "summary": summary}

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
