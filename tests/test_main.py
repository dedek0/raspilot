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
        """A lista de checks conhecidos cobre as verificações."""
        assert set(mainmod.KNOWN_CHECKS) == {
            "anti_root", "anti_frida", "anti_tampering",
            "anti_emulator", "anti_hooking", "ssl_pinning",
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


class TestStagedFlags:
    """Flags de análise por etapas e automação."""

    def test_defaults(self):
        args = mainmod.parse_args(["--package", "com.example.app"])
        assert args.stage == "full"
        assert args.only is None
        assert args.apk is None
        assert args.json_only is False

    def test_stage_only_apk_json(self, tmp_path):
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"apk")
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--stage", "detect",
            "--only", "anti_frida",
            "--only", "anti_root",
            "--apk", str(apk),
            "--json-only",
        ])
        assert args.stage == "detect"
        assert args.only == ["anti_frida", "anti_root"]
        assert args.apk == str(apk)
        assert args.json_only is True

    def test_static_stage_runs_without_device(self, tmp_path, monkeypatch):
        profile = {
            "available": True,
            "engine": "builtin",
            "classes_count": 0,
            "cached": False,
            "summary": {
                "vectors": {
                    "frida": {
                        "present": True,
                        "confidence": "medium",
                        "total": 1,
                    }
                }
            },
        }
        monkeypatch.setattr(
            mainmod, "build_static_profile", lambda *a, **k: profile
        )
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--stage", "static",
            "--apk", str(tmp_path / "app.apk"),
            "--output-dir", str(tmp_path),
        ])
        rc = mainmod.run_static_stage(args)
        assert rc == 0
        files = list(tmp_path.glob("*_static.json"))
        assert len(files) == 1
        doc = json.loads(files[0].read_text(encoding="utf-8"))
        assert doc["metadata"]["run"]["stage"] == "static"
        assert doc["static_profile"]["engine"] == "builtin"


class TestRepackFlags:
    """Flags do teste destrutivo de repack."""

    def test_repack_requires_explicit_reinstall_permission(self):
        with pytest.raises(SystemExit) as exc:
            mainmod.parse_args([
                "--package", "com.example.app",
                "--tamper-method", "repack",
            ])
        assert exc.value.code == 2

    def test_repack_accepts_permission_and_variants(self):
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--tamper-method", "repack",
            "--tamper-allow-reinstall",
            "--tamper-variant", "asset",
            "--tamper-variant", "dex",
            "--tamper-installer", "com.android.vending",
            "--tamper-keep-artifacts",
        ])
        assert args.tamper_allow_reinstall is True
        assert args.tamper_variant == ["asset", "dex"]
        assert args.tamper_installer == "com.android.vending"
        assert args.tamper_keep_artifacts is True

    def test_gadget_flags(self):
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--tamper-method", "repack",
            "--tamper-allow-reinstall",
            "--tamper-variant", "gadget",
            "--tamper-gadget", "/tmp/libgadget.so",
            "--tamper-gadget-port", "27044",
        ])
        assert args.tamper_variant == ["gadget"]
        assert args.tamper_gadget == "/tmp/libgadget.so"
        assert args.tamper_gadget_port == 27044
        assert args.tamper_gadget_mode == "listen"

    def test_script_and_original_key_flags(self):
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--tamper-method", "repack",
            "--tamper-allow-reinstall",
            "--tamper-variant", "gadget",
            "--tamper-gadget-mode", "script",
            "--tamper-gadget-script", "/tmp/probe.js",
            "--tamper-key", "/tmp/original.jks",
            "--tamper-key-alias", "release",
            "--tamper-key-pass", "kp",
            "--tamper-store-pass", "sp",
        ])
        assert args.tamper_gadget_mode == "script"
        assert args.tamper_gadget_script == "/tmp/probe.js"
        assert args.tamper_key == "/tmp/original.jks"
        assert args.tamper_key_alias == "release"
        assert args.tamper_key_pass == "kp"
        assert args.tamper_store_pass == "sp"

    def test_detect_stage_does_not_require_reinstall(self):
        args = mainmod.parse_args([
            "--package", "com.example.app",
            "--tamper-method", "repack",
            "--stage", "detect",
        ])
        assert args.stage == "detect"
