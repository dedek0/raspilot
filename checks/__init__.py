"""RASPilot — pacote de verificações (checks) de proteções RASP.

Cada módulo expõe uma classe de check com sub-verificações independentes
e um método ``run_all()`` que consolida o veredito com evidências.
Todos os checks são chamáveis isoladamente (sem estado global), prontos
para serem expostos como ferramentas MCP na próxima fase.

Marca: RASPilot — Piloto Automático de Auditoria RASP para Android.
"""

from __future__ import annotations

__all__ = ["anti_root", "anti_frida", "anti_emulator", "anti_hooking", "ssl_pinning"]
