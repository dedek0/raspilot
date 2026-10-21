"""Testes do suporte opcional ao ambiente emulado (AVD).

O suporte ao AVD é totalmente opcional: sem a flag ``--avd`` nada muda.
Estes testes cobrem a configuração, a validação do ambiente e o comando
de inicialização do emulador — sempre com o filesystem e o ``adb``
mockados.
"""

from __future__ import annotations

import json
import os

import pytest

from avd_manager import (
    CONFIG_ENV_VAR,
    AvdConfig,
    AvdConfigError,
    AvdEnvironment,
    AvdError,
    AvdManager,
)

CONFIG = {
    "sdk_root": "/opt/android-sdk",
    "avd_name": "raspilot_avd",
    "system_image": "system-images;android-33;google_apis;x86_64",
    "device_profile": "pixel_6",
    "port": 5556,
    "headless": True,
    "wipe_data": False,
    "boot_timeout": 120,
    "extra_args": ["-no-snapshot-save"],
}


def _write_config(tmp_path, payload=None, name="avd.json"):
    """Grava um arquivo de configuração e devolve o caminho."""
    path = tmp_path / name
    path.write_text(json.dumps(payload if payload is not None else CONFIG), encoding="utf-8")
    return str(path)


class TestAvdConfig:
    """Carga e validação da configuração."""

    def test_load_valid_config(self, tmp_path):
        """Configuração completa é carregada."""
        config = AvdConfig.load(_write_config(tmp_path))
        assert config.sdk_root == "/opt/android-sdk"
        assert config.avd_name == "raspilot_avd"
        assert config.port == 5556
        assert config.headless is True
        assert config.boot_timeout == 120
        assert config.extra_args == ["-no-snapshot-save"]

    def test_defaults_for_optional_fields(self, tmp_path):
        """Campos ausentes recebem o padrão."""
        config = AvdConfig.load(_write_config(tmp_path, {"avd_name": "x"}))
        assert config.port == 5554
        assert config.headless is True
        assert config.boot_timeout > 0
        assert config.extra_args == []

    def test_missing_file_raises_with_instructions(self, tmp_path):
        """Arquivo ausente: erro com as instruções de configuração."""
        with pytest.raises(AvdConfigError) as exc:
            AvdConfig.load(str(tmp_path / "nao-existe.json"))
        assert "avdmanager" in str(exc.value)

    def test_invalid_json_raises(self, tmp_path):
        """JSON inválido: erro explícito."""
        path = tmp_path / "quebrado.json"
        path.write_text("{nao é json", encoding="utf-8")
        with pytest.raises(AvdConfigError):
            AvdConfig.load(str(path))

    def test_missing_avd_name_raises(self, tmp_path):
        """Sem 'avd_name' a configuração é incompleta."""
        with pytest.raises(AvdConfigError):
            AvdConfig.load(_write_config(tmp_path, {"sdk_root": "/x"}))

    def test_not_a_mapping_raises(self, tmp_path):
        """O arquivo precisa conter um objeto JSON."""
        path = tmp_path / "lista.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(AvdConfigError):
            AvdConfig.load(str(path))

    def test_env_var_overrides_default_path(self, tmp_path, monkeypatch):
        """$RASPILOT_AVD_CONFIG aponta para outra configuração."""
        path = _write_config(tmp_path, name="outro.json")
        monkeypatch.setenv(CONFIG_ENV_VAR, path)
        assert AvdConfig.default_path() == path
        assert AvdConfig.load().avd_name == "raspilot_avd"

    def test_setup_instructions_mention_config_and_flag(self):
        """As instruções cobrem a configuração e a flag de uso."""
        text = AvdConfig.setup_instructions("/tmp/avd.json")
        assert "/tmp/avd.json" in text
        assert "--avd" in text


class TestAvdManager:
    """Validação do ambiente e comando de inicialização."""

    def _fake_sdk(self, tmp_path):
        """Cria um SDK fake com o binário do emulador."""
        emulator = tmp_path / "sdk" / "emulator" / "emulator"
        emulator.parent.mkdir(parents=True, exist_ok=True)
        emulator.write_text("#!/bin/sh\n", encoding="utf-8")
        emulator.chmod(0o755)
        return str(tmp_path / "sdk")

    def _fake_avd(self, tmp_path, monkeypatch, name="raspilot_avd"):
        """Cria o diretório de AVDs do usuário."""
        home = tmp_path / "home"
        avd_dir = home / ".android" / "avd" / f"{name}.avd"
        avd_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HOME", str(home))
        return home

    def test_command_headless(self, tmp_path):
        """Modo headless: sem janela e sem áudio."""
        config = AvdConfig(avd_name="avd", port=5556, headless=True,
                           extra_args=["-gpu", "swiftshader_indirect"])
        cmd = AvdManager(config).command()
        assert "-avd" in cmd and "avd" in cmd
        assert "-port" in cmd and "5556" in cmd
        assert "-no-window" in cmd and "-no-audio" in cmd
        assert "-wipe-data" not in cmd
        assert cmd[-2:] == ["-gpu", "swiftshader_indirect"]

    def test_command_with_wipe_data(self):
        """--wipe-data entra no comando quando configurado."""
        config = AvdConfig(avd_name="avd", wipe_data=True, headless=False)
        cmd = AvdManager(config).command()
        assert "-wipe-data" in cmd
        assert "-no-window" not in cmd

    def test_serial_follows_port(self):
        """O serial acompanha a porta configurada."""
        assert AvdManager(AvdConfig(avd_name="a", port=5558)).serial == "emulator-5558"

    def test_check_reports_missing_environment(self, tmp_path, monkeypatch):
        """Sem SDK e sem AVD: os problemas são listados."""
        monkeypatch.setenv("HOME", str(tmp_path))
        config = AvdConfig(sdk_root=str(tmp_path / "nada"), avd_name="avd")
        env = AvdManager(config).check()
        assert env.ok is False
        assert len(env.problems) >= 2
        assert env.hints

    def test_check_ok_when_environment_is_ready(self, tmp_path, monkeypatch):
        """Com SDK, AVD e adb presentes: o ambiente está pronto."""
        sdk = self._fake_sdk(tmp_path)
        self._fake_avd(tmp_path, monkeypatch)
        config = AvdConfig(sdk_root=sdk, avd_name="raspilot_avd")
        env = AvdManager(config).check()
        assert env.ok is True
        assert env.problems == []
        assert env.details["avd"] == "raspilot_avd"

    def test_start_refuses_when_environment_is_not_ready(self, tmp_path, monkeypatch):
        """Sem ambiente pronto, start() falha com a lista de problemas."""
        monkeypatch.setenv("HOME", str(tmp_path))
        config = AvdConfig(sdk_root=str(tmp_path / "nada"), avd_name="avd")
        with pytest.raises(AvdError) as exc:
            AvdManager(config).start()
        assert "não pronto" in str(exc.value)

    def test_stop_does_nothing_when_emulator_was_not_started(self):
        """Um AVD que já estava rodando não é encerrado."""
        manager = AvdManager(AvdConfig(avd_name="avd"))
        manager.stop()  # não deve levantar

    def test_environment_defaults(self):
        """Estrutura de resultado com defaults coerentes."""
        env = AvdEnvironment()
        assert env.ok is True
        assert env.problems == []
        assert env.hints == []
        assert env.details == {}
