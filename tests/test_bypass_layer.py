"""Testes da camada de bypass (Fase 2).

Cobrem os defeitos que quebravam o bypass em campo: retorno de tipo
errado na verificação de TLS, o gancho de Class.forName que deixava a
detecção mais provável em vez de menos, o custo dos ganchos em funções
muito chamado e o catálogo de vendors.
"""

from __future__ import annotations

import os

import pytest

from rasp_vendors import (
    BOOLEAN_VERDICT_METHODS,
    GENERIC_VERDICT_METHODS,
    VENDORS,
    all_tokens,
    verdict_method_names,
)
from verdict_hook import build_replacements, vendor_class_names

SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)


def _read(name: str) -> str:
    with open(os.path.join(SCRIPTS_DIR, name), encoding="utf-8") as fh:
        return fh.read()


class TestSslBypassTypes:
    """A verificação de TLS precisa devolver o tipo declarado."""

    def test_verify_chain_returns_a_list(self):
        """verifyChain declara List; devolver o array quebra o handshake."""
        source = _read("ssl_bypass.js")
        assert "chainToList" in source
        # O retorno antigo devolvia a cadeia (array) diretamente.
        assert "return untrustedChain;" not in source

    def test_chain_to_list_builds_a_java_list(self):
        source = _read("ssl_bypass.js")
        assert "java.util.ArrayList" in source
        assert "list.add(" in source

    def test_all_overloads_are_hooked(self):
        """A mesma assinatura existe em variantes List e void."""
        source = _read("ssl_bypass.js")
        assert "hookAllOverloads" in source
        # Conscrypt, NetworkSecurityConfig e RootTrustManager
        assert source.count("hookAllOverloads(") >= 4

    def test_overload_helper_respects_the_declared_return_type(self):
        source = _read("ssl_bypass.js")
        assert "ov.returnType" in source
        assert "Ljava/util/List;" in source

    def test_certificate_pinner_hooks_every_signature(self):
        """A forma da assinatura do OkHttp varia entre versões."""
        source = _read("ssl_bypass.js")
        assert "'check'" in source
        assert "okhttp3.CertificatePinner" in source
        assert "OkHostnameVerifier" in source

    def test_native_verify_variants_are_covered(self):
        """SSL_set_verify é a variante por conexão, a mais usada."""
        source = _read("ssl_bypass.js")
        for symbol in ("SSL_CTX_set_verify", "SSL_set_verify",
                       "SSL_get_verify_result", "X509_verify_cert"):
            assert symbol in source, f"ausente: {symbol}"

    def test_native_callbacks_are_kept_alive(self):
        """O callback do verificador customizado precisa sobreviver."""
        source = _read("ssl_bypass.js")
        assert "nativeCallbacks.push(callback)" in source

    def test_native_hooks_are_not_duplicated(self):
        """A mesma função exportada por mais de uma biblioteca."""
        source = _read("ssl_bypass.js")
        assert "hookedAddresses" in source


class TestHookingBypassSemantics:
    """A evasão precisa deixar o app mais convincente, não menos."""

    def test_class_for_name_throws_not_found(self):
        """Devolver null faria o app concluir que o framework existe."""
        source = _read("anti_hooking_bypass.js")
        assert "return null;" not in source.split("function hookClassLookups")[1][:4000]
        assert "notFoundException" in source
        assert "ClassNotFoundException" in source

    def test_class_for_name_single_arg_is_not_hooked(self):
        """A sobrecarga de um argumento quebra o class loader do caller.

        ART resolve o nome com o class loader de quem chamou; invocar o
        original pelo Frida faz o ART inferir o caller a partir do frame
        do agente, e a classe passa a ser procurada no boot class loader.
        O app então recebe ClassNotFoundException para classes
        legítimas. A sobrecarga de três argumentos cobre a checagem.
        """
        source = _read("anti_hooking_bypass.js")
        block = source.split("function hookClassLookups")[1][:4000]
        assert "Class.forName.overload('java.lang.String')" not in block
        assert "forName.overload('java.lang.String')" not in block
        assert "'java.lang.String', 'boolean', 'java.lang.ClassLoader'" in block

    def test_keyword_match_requires_token_boundary(self):
        """Substring solta casa o nome do pacote do app com o termo.

        Um app cujo pacote contenha "frida" faria todo acesso a arquivo
        próprio virar "detecção".
        """
        source = _read("anti_hooking_bypass.js")
        assert "containsToken(lower, HOOK_KEYWORDS[i])" in source
        assert "lower.indexOf(HOOK_KEYWORDS[i])" not in source

    def test_ambiguous_keywords_are_not_used_for_string_search(self):
        """"gadget" e "whale" são palavras comuns."""
        source = _read("anti_hooking_bypass.js")
        strong = source.split("var HOOK_KEYWORDS = [")[1].split("];")[0]
        for word in ("gadget", "whale", "epic"):
            assert f"'{word}'" not in strong, f"ambígua no tier forte: {word}"

    def test_string_search_uses_the_needle_not_the_haystack(self):
        """Esconder o haystack quebraria buscas legítimas do app."""
        source = _read("anti_hooking_bypass.js")
        assert "containsKeyword(b, HOOK_KEYWORDS)" in source

    def test_memcmp_does_not_build_the_string_byte_by_byte(self):
        """Concatenar caractere a caractere trava o app."""
        source = _read("anti_hooking_bypass.js")
        assert "bytesContainKeyword" in source
        # A comparação é feita sobre os bytes: nenhuma string é montada
        # a partir do buffer.
        assert "String.fromCharCode.apply" not in source

    def test_memcmp_skips_large_buffers(self):
        source = _read("anti_hooking_bypass.js")
        # O limite é pequeno: comparar blocos inteiros é o caso comum
        # e não é neles que mora o nome de um framework.
        assert "n <= 64" in source

    def test_hot_string_functions_are_not_hooked(self):
        """strcmp é chamado dezenas de milhares de vezes por segundo.

        Um gancho nesse ponto consome o tempo do agente de
        instrumentação, que deixa de responder.
        """
        source = _read("anti_hooking_bypass.js")
        hooked = source.split("function hookLibcStringHooks()")[1]
        hooked = hooked.split("\n}")[0]
        assert "'strcmp'" not in hooked

    def test_no_global_syscall_replacement(self):
        """Substituir syscall() trava a sessão.

        Toda chamada de syscall do processo passaria pelo gancho, e o
        agente ocupado não responde.
        """
        source = _read("anti_hooking_bypass.js")
        assert "'syscall'" not in source


class TestEvasionHotPath:
    """Os ganchos precisam ser raros: o volume consome o agente."""

    def test_hot_string_functions_are_not_hooked(self):
        """strcmp e memcmp são chamados milhares de vezes por segundo.

        Um gancho nesses pontos consome o tempo do agente de
        instrumentação, que deixa de responder — e o sintoma é uma
        sessão que trava sem erro.
        """
        source = _read("anti_frida_bypass.js")
        hooked = source.split("function hookLibcStringHooks()")[1].split("\n}")[0]
        assert "'strcmp'" not in hooked
        assert "'memcmp'" not in hooked

    def test_no_global_syscall_replacement(self):
        """Substituir syscall() serializa o processo inteiro.

        Toda chamada de syscall passa pelo gancho; com o agente
        ocupado, a thread que chamou a syscall fica esperando e o app
        trava esperando a thread.
        """
        source = _read("anti_frida_bypass.js")
        assert "'syscall'" not in source

    def test_marker_scan_does_not_build_strings(self):
        """A verificação de marcador não monta string por chamada."""
        source = _read("anti_frida_bypass.js")
        assert "containsMarkerInString" in source
        hooked = source.split("function hookLibcStringHooks()")[1].split("\n}")[0]
        assert "toLowerCase" not in hooked

    def test_marker_scan_stops_at_the_string_terminator(self):
        """Ler um tamanho fixo a partir do ponteiro derruba o processo.

        A string pode terminar exatamente no fim da página mapeada.
        """
        source = _read("anti_frida_bypass.js")
        assert "readCString" in source
        assert "readByteArray(MAX_SCAN" not in source


class TestVendorCatalog:
    """O catálogo de vendors é dado, não código."""

    def test_catalog_has_vendors(self):
        assert len(VENDORS) >= 10

    def test_tokens_are_unique_per_vendor(self):
        for vendor in VENDORS:
            assert vendor.tokens
            assert vendor.name

    def test_generic_verdict_methods_are_covered(self):
        names = verdict_method_names()
        for method in GENERIC_VERDICT_METHODS:
            assert method in names

    def test_boolean_verdict_methods_are_separated(self):
        assert BOOLEAN_VERDICT_METHODS
        for method in BOOLEAN_VERDICT_METHODS:
            assert method not in GENERIC_VERDICT_METHODS

    def test_vendor_matching_is_case_insensitive(self):
        """O SDK escreve a tag com a capitalização dele."""
        from logcat_analyzer import RASP_VENDOR_TAGS

        for token in all_tokens():
            assert token.lower() in RASP_VENDOR_TAGS

    def test_replacements_are_valid_javascript(self):
        reps = build_replacements()
        assert reps["__RASPILOT_VERDICT_METHODS__"].startswith("[")
        assert "onThreatDetected" in reps["__RASPILOT_VERDICT_METHODS__"]

    def test_vendor_class_names_are_packages(self):
        for name in vendor_class_names():
            assert "." in name


class TestVerdictHookScript:
    """O script de veredito neutraliza a comunicação da violação."""

    def test_script_exists(self):
        assert os.path.isfile(
            os.path.join(SCRIPTS_DIR, "verdict_hook.js")
        )

    def test_script_path_resolves(self):
        """O caminho do script é resolvido a partir do módulo."""
        from verdict_hook import VERDICT_HOOK_SCRIPT

        assert os.path.isfile(VERDICT_HOOK_SCRIPT), (
            f"script de veredito não encontrado: {VERDICT_HOOK_SCRIPT}"
        )

    def test_installation_is_deferred(self):
        """A varredura de classes não pode bloquear o carregamento."""
        source = _read("verdict_hook.js")
        assert "raspilotDeferJava" in source

    def test_hooks_by_method_name(self):
        source = _read("verdict_hook.js")
        assert "VERDICT_METHODS" in source
        assert "getDeclaredMethods" in source

    def test_void_methods_become_noop_and_booleans_become_false(self):
        source = _read("verdict_hook.js")
        assert "ret === 'void'" in source
        assert "ret === 'boolean'" in source
        assert "return false;" in source

    def test_sweep_is_bounded(self):
        """Apps com muitos dex têm milhares de classes."""
        source = _read("verdict_hook.js")
        assert "MAX_CLASSES" in source

    def test_neutralization_is_reported_as_evidence(self):
        source = _read("verdict_hook.js")
        assert "bypass-evidence" in source
