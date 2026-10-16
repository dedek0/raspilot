"""Testes do script_loader — prelúdio da bridge Java (Frida 17+)."""

from __future__ import annotations

from unittest import mock

import script_loader


class TestJavaBridge:
    """Prelúdio da bridge Java do frida-tools."""

    def test_bridge_available_in_frida_tools_14(self):
        """A bridge pré-compilada existe no frida-tools instalado."""
        assert script_loader.java_bridge_available() is True

    def test_prelude_defines_java(self):
        """O prelúdio define `var Java = bridge` após o bundle da bridge."""
        prelude = script_loader.java_bridge_prelude()
        assert "var bridge" in prelude
        assert prelude.rstrip().endswith("var Java = bridge;")

    def test_prepare_script_prepends_bridge(self):
        """prepare_script concatena prelúdio + código original."""
        source = "send(typeof Java);"
        prepared = script_loader.prepare_script(source)
        assert prepared.endswith(source)
        assert "var Java = bridge;" in prepared

    def test_prepare_without_bridge_returns_raw(self):
        """Sem a bridge (instalação antiga), o script fica cru."""
        with mock.patch.object(script_loader, "_BRIDGES_DIR", None):
            source = "send('x');"
            assert script_loader.prepare_script(source) == source

    def test_load_script_uses_prepared_source(self):
        """load_script cria o script com o código preparado e carrega."""
        fake_script = mock.MagicMock()
        fake_session = mock.MagicMock()
        fake_session.create_script.return_value = fake_script

        cb = mock.MagicMock()
        script_loader.load_script(
            fake_session, "send(1);", on_message=cb, name="t"
        )

        kwargs = fake_session.create_script.call_args
        prepared = kwargs[0][0] if kwargs[0] else kwargs[1]["source"]
        assert "var Java = bridge;" in prepared
        assert prepared.endswith("send(1);")
        fake_script.on.assert_called_once_with("message", cb)
        fake_script.load.assert_called_once()

    def test_load_script_file_reads_disk(self, tmp_path):
        """load_script_file lê o arquivo e delega ao load_script."""
        js = tmp_path / "x.js"
        js.write_text("send('file');", encoding="utf-8")
        fake_script = mock.MagicMock()
        fake_session = mock.MagicMock()
        fake_session.create_script.return_value = fake_script

        script_loader.load_script_file(fake_session, str(js))
        prepared = fake_session.create_script.call_args[0][0]
        assert prepared.endswith("send('file');")


class TestSafeUnload:
    """``safe_unload`` tolera scripts destruídos (processo alvo morreu)."""

    def test_calls_unload(self):
        """Script saudável é descarregado normalmente."""
        script = mock.MagicMock()
        script_loader.safe_unload(script)
        script.unload.assert_called_once()

    def test_ignores_destroyed_script(self):
        """`script is destroyed` não propaga exceção nem stacktrace."""
        script = mock.MagicMock()
        script.unload.side_effect = RuntimeError("script is destroyed")
        script_loader.safe_unload(script)  # não deve levantar

    def test_handles_none(self):
        """``None`` é um no-op."""
        script_loader.safe_unload(None)
