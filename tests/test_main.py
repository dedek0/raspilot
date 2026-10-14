"""Testes da CLI do RASPilot (parse de argumentos e validações)."""

from __future__ import annotations

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
        """A lista de checks conhecidos cobre os 4 verificações."""
        assert set(mainmod.KNOWN_CHECKS) == {
            "anti_root", "anti_frida", "anti_emulator", "ssl_pinning",
        }


class TestBanner:
    """Banner de marca."""

    def test_banner_mentions_tool(self, capsys):
        """O banner exibe o nome RASPilot."""
        mainmod.print_banner()
        captured = capsys.readouterr()
        assert "RASPilot" in captured.out
