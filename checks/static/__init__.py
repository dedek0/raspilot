"""RASPilot — camada de análise estática do APK.

A camada combina duas fontes:

- varredura de assinaturas no ZIP do APK (sempre disponível, sem
  dependências externas);
- consultas ao Droid ASC (``droidasc``), quando instalado, para obter
  manifesto decodificado, lista de classes e referências de
  string/tipo/método com o método que contém a referência.

O resultado é um ``StaticProfile`` serializável em JSON, consumido pelos
checks. A análise estática é evidência de *existência* da proteção; ela
não prova que a checagem foi executada em runtime.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

from checks.static.profile import (
    build_static_profile,
    merge_pinning_detection,
    merge_signature_detection,
    vector_view,
)

__all__ = [
    "build_static_profile",
    "merge_pinning_detection",
    "merge_signature_detection",
    "vector_view",
]
