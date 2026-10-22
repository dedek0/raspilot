"""Testes da CLI do RASPilot (parse de argumentos e validações)."""

from __future__ import annotations

import json

import pytest

import main as mainmod


class TestParseArgs:
    """Parsing e validação da linha de comando."""

    def test_minimal_args(self):
        """Só --package é obrigatório."""
        args = mainmod.parse_args(["--package", "com.example.app"])
        assert args.package == "com.example.app"
        assert args.device_id is None
        assert args.wifi is None
        assert args.output_dir == "reports/"
        assert args.verbose is False
        assert args.skip == []

    def test_all_args(self):
        """Todos os argumentos são aceitos."""
        args = mainmod.parse_args([
            "--package", "com.foo",
            "--device-id", "emulator-5554",
            "--wifi", "192.168.0.10:5555",
            "--output-dir", "/tmp/out",
            "--verbose",
            "--skip", "anti_emulator", "ssl_pinning",
        ])
        assert args.device_id == "emulator-5554"
        assert args.wifi == "192.168.0.10:5555"
        assert args.output_dir == "/tmp/out"
        assert args.verbose is True
        assert args.skip == ["anti_emulator", "ssl_pinning"]

    def test_module_flags_are_optional(self):
        """O módulo é opcional: o padrão é ``auto``."""
        args = mainmod.parse_args(["--package", "com.example.app"])
        assert args.hook_method == "auto"
        assert args.emulator_method == "auto"
        assert args.module_apk is None

    def test_module_flags_are_accepted(self, tmp_path):
        """As flags do módulo são aceitas."""
        apk = tmp_path / "module.apk"
        apk.write_bytes(b"apk")
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--hook-method", "module",
            "--emulator-method", "frida",
            "--module-apk", str(apk),
        ])
        assert args.hook_method == "module"
        assert args.emulator_method == "frida"
        assert args.module_apk == str(apk)

    def test_unknown_method_exits(self):
        """Um método desconhecido é rejeitado."""
        with pytest.raises(SystemExit) as exc:
            mainmod.parse_args(["--package", "x", "--hook-method", "zzz"])
        assert exc.value.code == 2

    def test_missing_package_exits(self):
        """Sem --package o argparse encerra com código 2."""
        with pytest.raises(SystemExit) as exc:
            mainmod.parse_args([])
        assert exc.value.code == 2

    def test_unknown_skip_exits(self):
        """--skip com check desconhecido é rejeitado."""
        with pytest.raises(SystemExit) as exc:
            mainmod.parse_args(["--package", "x", "--skip", "foo"])
        assert exc.value.code == 2

    def test_known_checks_constant(self):
        """A lista de checks conhecidos cobre as 6 verificações."""
        assert set(mainmod.KNOWN_CHECKS) == {
            "anti_root", "anti_frida", "anti_emulator",
            "anti_hooking", "ssl_pinning", "revoked_ca",
        }

    def test_avd_flags_are_optional(self):
        """O suporte ao AVD é opcional: nada é ativado por padrão."""
        args = mainmod.parse_args(["--package", "com.example.app"])
        assert args.avd is False
        assert args.avd_check is False
        assert args.avd_config is None
        assert args.avd_name is None

    def test_avd_flags_are_accepted(self, tmp_path):
        """As flags do ambiente emulado são aceitas."""
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--avd",
            "--avd-config", str(tmp_path / "avd.json"),
            "--avd-name", "meu_avd",
        ])
        assert args.avd is True
        assert args.avd_config.endswith("avd.json")
        assert args.avd_name == "meu_avd"


class TestBanner:
    """Banner de marca."""

    def test_banner_mentions_tool(self, capsys):
        """O banner exibe o nome RASPilot."""
        mainmod.print_banner()
        captured = capsys.readouterr()
        assert "RASPilot" in captured.out


class TestAvdCheck:
    """Validação do ambiente emulado pela CLI."""

    def test_missing_config_returns_error(self, tmp_path, capsys):
        """Sem configuração, --avd-check explica o que fazer."""
        rc = mainmod.main([
            "--package", "com.example.app",
            "--avd-check",
            "--avd-config", str(tmp_path / "nao-existe.json"),
        ])
        assert rc == 1
        out = capsys.readouterr().out
        assert "avdmanager" in out

    def test_config_without_environment_reports_problems(self, tmp_path, capsys):
        """Configuração que aponta para um SDK inexistente é apontada."""
        config = tmp_path / "avd.json"
        config.write_text(
            json.dumps({"sdk_root": str(tmp_path / "sdk"), "avd_name": "avd"}),
            encoding="utf-8",
        )
        rc = mainmod.main([
            "--package", "com.example.app",
            "--avd-check",
            "--avd-config", str(config),
        ])
        assert rc == 1
        assert "emulator" in capsys.readouterr().out
