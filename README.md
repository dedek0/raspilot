# ✈ RASPilot

> 🇺🇸 [English version](README.en.md)

**RASPilot — Piloto Automático de Auditoria RASP para Android.**

Orquestra verificações Anti-Root, Anti-Frida, Anti-Emulador, Anti-Hooking e
SSL Pinning em apps Android, gerando relatórios estruturados e prontos para
consumo por LLMs via MCP.

O RASPilot conecta-se a um dispositivo Android (USB ou Wi-Fi ADB), instala e
valida o `frida-server` automaticamente, executa um pipeline de verificações
RASP contra o app alvo e produz relatórios **JSON** e **HTML** com o status de
cada proteção (`OK` / `FALHOU` / `N/A` / `SKIP` / `ERROR`) e as evidências
coletadas.

---

## Requisitos

### No host

- Python 3.9+
- `adb` (Android Platform Tools) no `PATH`
- Frida — o `frida-server` compatível é baixado automaticamente na versão
  do pacote `frida` instalado localmente

### No dispositivo Android

O RASPilot roda em **dispositivo físico ou emulador**, com os requisitos
abaixo. Quanto mais próximo do ambiente real de produção, mais útil é o
resultado: emulador não reproduz as proteções de hardware.

| Item | Requisito | Por quê |
|---|---|---|
| Versão do Android | API 24+ (Android 7.0) | o `frida-server` usado pela auditoria não suporta versões mais antigas |
| Arquitetura | `arm64-v8a`, `armeabi-v7a`, `x86_64` ou `x86` | o `frida-server` é baixado para a ABI do aparelho; `riscv64` **não** é suportado |
| Depuração USB | ativada nas Opções do desenvolvedor | o `adb` precisa conversar com o aparelho |
| Autorização de depuração | o popup "Permitir depuração USB" precisa ser aceito | sem isso o aparelho aparece como `unauthorized` e não há conexão |
| Root | **recomendado** (Magisk, KernelSU, APatch) | sem root o `frida-server` roda com o uid do `shell` e alguns vetores de detecção (TracerPid, portas, leitura de `/proc/<pid>/maps` de outros processos) ficam incompletos |
| SELinux | `permissive` facilita; `enforcing` funciona | em modo enforcing o `frida-server` precisa de root para injetar em processos de apps |
| Espaço livre | ~200 MB | `frida-server` (~60 MB) e o cache de APKs |
| Bateria | o processo de auditoria consome CPU | uma janela de 20–30 s de observação já é suficiente |

Preparação usual (todas opcionais, mas alteram o resultado):

```bash
# 1) depuração USB + aceitar o popup de autorização
# 2) root (Magisk/KernelSU), se disponível
# 3) ADB over Wi-Fi, para não depender do cabo
adb tcpip 5555
```

**Cuidados com o ambiente de auditoria.** O RASPilot detecta o que está
instalado no aparelho, e uma ferramenta de hooking ativa **contamina o
resultado**: o log de um framework de hooking instalado é do operador, não
da proteção do app auditado. O relatório separa essas duas coisas — mas
para uma leitura limpa, audite em um aparelho sem frameworks de hooking
instalados.

### Permissões e artefatos usados

O RASPilot é **não destrutivo**, mas usa o aparelho de forma observável:

- `/data/local/tmp` — recebe o `frida-server` (com nome opaco) durante a
  execução e é **removido ao final**
- `adb forward` — um túnel local para o servidor do Frida, desfeito ao final
- `logcat` — leitura contínua do buffer do sistema
- O app alvo é **forçado a parar** (force-stop) ao final de cada execução

O `frida-server` e o túnel são encerrados mesmo quando a auditoria falha
no meio.

## Instalação

```bash
git clone <repo> raspilot && cd raspilot
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# dependências de teste (opcional)
pip install -r requirements-dev.txt
```

Verificação rápida:

```bash
python main.py --version
adb devices   # deve listar seu dispositivo como "device"
```

## Uso

```bash
# USB — primeiro dispositivo disponível
python main.py --package com.example.app

# Wi-Fi ADB
python main.py --package com.example.app --wifi 192.168.0.10:5555

# Dispositivo específico + verbose + saída customizada
python main.py --package com.example.app \
    --device-id emulator-5554 \
    --output-dir ./meus_relatorios \
    --verbose

# Janela de observação maior (segundos) nos checks dinâmicos
python main.py --package com.example.app --window 20

# Pular verificações
python main.py --package com.example.app --skip anti_emulator ssl_pinning
```

### Argumentos

| Argumento | Obrigatório | Descrição |
|---|---|---|
| `--package` | sim | Package name do app alvo (ex: `com.example.app`) |
| `--device-id` | não | Serial ADB (ex: `emulator-5554`) |
| `--wifi IP:PORTA` | não | Endereço para `adb connect` |
| `--output-dir` | não | Diretório dos relatórios (default `reports/`) |
| `--window SEG` | não | Janela de observação em segundos nos checks dinâmicos (default `15`) |
| `--baseline-window SEG` | não | Janela do baseline sem instrumentação (default `5`) |
| `--no-baseline` | não | Não executa o baseline antes dos checks dinâmicos |
| `--mode MODE` | não | Modo: `detect` (só observação), `bypass` (observação+bypass) ou `stealth` (bootstrap nativo antes do resume) |
| `--no-java` | não | Não carrega hooks Java; útil em apps com RASP que bloqueia a bridge |
| `--java-timeout SEG` | não | Tempo máximo de carga dos scripts Java (default `30`). A carga da bridge é dominada pela inicialização do runtime Java no alvo e pela varredura de classloaders |
| `--js-runtime RUNTIME` | não | Runtime JavaScript do Frida: `qjs` (default) ou `v8` |
| `--verbose` | não | Logging em nível DEBUG |
| `--skip CHECK...` | não | Checks a pular (`anti_root`, `anti_frida`, `anti_emulator`, `anti_hooking`, `ssl_pinning`) |

### Saída

- Terminal: tabela colorida **"RASPilot — Relatório de Auditoria RASP"**
- `reports/<package>_<timestamp>.json` — documento estruturado (metadata,
  summary, details) para consumo por LLMs/MCP
- `reports/<package>_<timestamp>.html` — relatório visual com badges de status
  e evidências

Durante os checks dinâmicos o RASPilot também captura o **logcat** do
dispositivo. O logcat é usado como fonte independente de evidência para
correlacionar mortes (`SIGKILL`, `SIGSEGV`, `am_kill`, `am_crash`, ANR),
mensagens de SDKs de segurança e erros de TLS/pinning. Antes de qualquer
spawn com Frida, um **baseline sem instrumentação** verifica se o app já
morre sozinho; assim um crash da instrumentação ou o ciclo de vida normal
do app não é confundido com uma reação do RASP.
A observação anti-Frida + anti-hooking roda em uma **sessão única**, e os bypasses de anti-hooking/SSL compartilham outro spawn. O cache de APK fica em `~/.raspilot/cache/apk` (desative com `RASPILOT_APK_CACHE=0`).

Semântica de status:

| Status | Significado |
|---|---|
| `OK` | Ambiente/proteção OK (ex: dispositivo físico, SSL pinning resistiu ao bypass, app detectou e bloqueou o Frida/hooking) |
| `FALHOU` | Ameaça presente ou bypass venceu (ex: root/emulador no ambiente, pinning contornado, app não detectou o Frida nem checagens anti-hook) |
| `N/A` | Não aplicável: não existe a proteção que se mediria (ex: sem SSL pinning) |
| `SKIP` | Etapa que não rodou: pulada via `--skip`, ou bypass não avaliado apesar de a proteção existir (o motivo vai em `skip_reason`) |
| `ERROR` | A verificação não pôde concluir (o pipeline continua) — inclui observação inconclusiva |

> **Regra de ouro:** o RASPilot só afirma que uma proteção resistiu quando
> houve evidência de confiança alta. Termos genéricos de logcat (`root`,
> `hook`, `detected`, `checksum`), logs de frameworks de hooking
> instalados no device e o crash do próprio agente de instrumentação são
> contexto — nunca sustentam um veredito.
>
> **App que bloqueia a auditoria é app protegido.** Quando o app sobrevive
> ao baseline (sem instrumentação) e encerra quando instrumentado, a
> instrumentação é o gatilho da morte: o app bloqueou a auditoria e a
> proteção é creditada como eficaz. Sem um baseline que prove que o app é
> estável sozinho, a morte continua inconclusiva (`ERROR`) — não há como
> atribuir a causa.
>
> A atribuição usa o **backtrace do crash** (buffer `crash` do logcat,
> que não exige root): uma queda dentro do agente do Frida, ou no glue
> JNI do ART que ele aciona, é falha da **instrumentação** — e aí o
> veredito é inconclusivo, porque o app não demonstrou reação. Queda no
> código do próprio app é reação do app.
>
> O mesmo vale para o bypass: um bypass **instalado** mas nunca
> **exercitado** (nenhuma requisição TLS observada, por exemplo) não
> prova que a proteção resistiu — a etapa fica `SKIP`, com o motivo em
> `skip_reason`. E um bypass em que o app encerrou **não** é um bypass
> vencido: o app bloqueou a auditoria.

> **Importante:** o RASPilot **não modifica permanentemente** o dispositivo.
> Ao final de cada execução ele encerra o `frida-server`, remove
> `/data/local/tmp/frida-server` e force-stop no app alvo.

---

## Verificações

### 1. Anti-Root (`checks/anti_root.py`)

Múltiplos vetores independentes consolidados em `is_rooted` + `confidence`:

- Binários `su` em 7 paths canônicos
- Magisk (package, `/data/adb/magisk`, `/sbin/.magisk`, `which magisk`)
- APatch e KernelSU (`me.bmax.apatch`, `me.weishu.kernelsu`, `/data/adb/ap`,
  `/data/adb/ksu`, `apd`, `ksud`)
- Propriedades de build (`ro.debuggable`, `ro.secure`, `service.adb.root`,
  `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`)
- Apps gerenciadores de root (Magisk, SuperSU, KingRoot, APatch, KernelSU...)
- `/system` montado `rw`
- Busybox

Confiança: `high` (≥2 vetores), `medium` (1), `low` (0).

### 2. Anti-Frida (`checks/anti_frida.py`)

- Processos (`ps -A | grep frida`)
- Portas Frida clássicas (27042/27043) **e a porta stealth real** do
  `frida-server` (`netstat`/`ss`/`/proc/net/tcp`)
- Módulos Frida carregados no processo alvo (via Frida)
- Threads `gum-js-loop`, `gmain`, `pool-frida` (`/proc/<pid>/task`)
- Observação de detecção de Frida **pelo app** (hooks de observação em
  `File.exists`, `Runtime.exec`, `ProcessBuilder`, `strstr`/`strcmp`,
  `connect` nas portas Frida, `open`/`access`/`stat`/`faccessat` em paths
  Frida e no `kill_trace`)
- Correlação com o **logcat** e com o **baseline sem instrumentação**: uma
  morte só vira evidência de detecção quando há sinal de segurança, kill
  rastreado ou o app não morria no baseline; sem baseline que isole a
  causa, o crash fica `ERROR`/inconclusivo, não `OK`
- Se a observação não puder executar (script/attach), o resultado é
  `ERROR`, não `vulnerable=True`

`vulnerable=True` ⇒ o app **não** detectou o Frida (falha de RASP).
O bypass correspondente vive em `scripts/anti_frida_bypass.js`.

### 3. Anti-Emulador (`checks/anti_emulator.py`)

Combina propriedades QEMU, arquivos de kernel, arquitetura de CPU
(x86 sem Chromebook), contagem de sensores, MAC de Bluetooth placeholder e
detecção específica de Genymotion/LDPlayer/BlueStacks/Nox/Waydroid.
Classifica `emulator_type` (`qemu_avd`, `genymotion`, `ldplayer`,
`bluestacks`, `nox`, `waydroid`) com confiança.

### 4. Anti-Hooking (`checks/anti_hooking.py`)

Verifica se o app detecta frameworks de hooking (Xposed, LSPosed,
EdXposed, Substrate e hooks inline: SandHook, YAHFA, LSPlant, Whale,
Dobby) e se essa proteção resiste a um bypass real. Quatro fases
independentes consolidadas em `protection_detected` + `bypass_successful`:

- **Vetores de dispositivo**: packages instalados (`xposed`, `lsposed`,
  `riru`, `substrate`...), módulos em `/data/adb` (`/data/adb/modules`,
  `/data/adb/lspd`) e libs de hook mapeadas no processo (sessão Frida com
  fallback para `/proc/<pid>/maps`). Libs do Frida ficam de fora — a
  detecção delas é papel do Anti-Frida.
- **Detecção estática**: baixa o APK e procura assinaturas que SDKs
  anti-RASP usam para checar hooks (classes Xposed, LSPosed/lspd/LSPlant,
  EdXposed, Substrate, SandHook/YAHFA/Whale/Dobby e strings Frida).
- **Observação dinâmica**: spawn suspenso com script que registra (sem
  bloquear) `Class.forName`/`ClassLoader.loadClass` de classes de
  frameworks, `File.exists` e `open`/`fopen`/`access`/`stat` em paths de
  frameworks e em `/proc/*/maps`/`status`, `Runtime.exec`/`ProcessBuilder`,
  buscas nativas (`strstr`/`strcmp`/`memcmp`) e stack traces com frames de
  frameworks. Leitura de `maps`/`status` isolada é sinal **fraco** (também
  tem uso legítimo); morte do app na janela é sinal **forte**.
- **Bypass** (`scripts/anti_hooking_bypass.js`): novo spawn com hooks que
  fazem `Class.forName` de classes Xposed retornar `null`, escondem
  paths/entradas de frameworks (`File.exists`/`File.list`/`File.listFiles`),
  bloqueiam `Runtime.exec`, removem frames Xposed dos stack traces, ocultam strings
  em `strstr`/`strcmp`/`memcmp`, devolvem `ENOENT` em `open`/`access`/
  `stat` de paths de frameworks, **filtram as linhas de libs de hook em
  `/proc/self/maps`** (read/fgets) e zeram `TracerPid`. O bypass só é
  considerado vencedor com **evidência real** de checagem neutralizada
  **e** o app vivo (morte = o RASP reagiu por outro vetor).

`protection_detected=False` ⇒ o app não possui checagens anti-hook
observáveis (falha de RASP). `bypass_successful=True` ⇒ a proteção existe,
mas o bypass venceu.

### 5. SSL Pinning (`checks/ssl_pinning.py`)

- **Detecção estática**: baixa o APK (`pm path` + `adb pull`) e procura
  assinaturas de OkHttp `CertificatePinner`, TrustKit,
  NetworkSecurityConfig, Flutter e Conscrypt/nativo (Manifest binário,
  DEX, libs nativas).
- **Bypass dinâmico**: injeta `scripts/ssl_bypass.js` (universal) cobrindo
  TrustManager, HostnameVerifier, OkHttp 3/4, NSC, Conscrypt, Apache
  HttpClient, WebView, BoringSSL/OpenSSL e Flutter. Bypass só é considerado
  bem-sucedido com **host real interceptado e app vivo**; logs de instalação
  de hooks ou de configuração nativa são apenas diagnóstico. O logcat é
  anexado ao resultado para corroborar erros de TLS/pinning.

  Detalhes que fazem a diferença na prática:

  - **Tipo de retorno**: os métodos de validação declaram tipos
    diferentes entre si — a mesma assinatura existe numa variante que
    devolve a cadeia (`List`) e numa que não devolve nada. Devolver o
    tipo errado faz a ponte lançar uma exceção, o que entrega um `null`
    ao app e **quebra o handshake** em vez de remover a validação. Todos
    os overloads são hookados e o valor devolvido acompanha o tipo
    declarado.
  - **Classe temporária**: a bridge grava as classes que cria em um
    diretório fora do sandbox do app, o que impede `registerClass` de
    funcionar. O bootstrap redireciona esse cache para o diretório
    gravável do próprio app.
  - **Verificação de nome**: é um passo separado da verificação da
    cadeia. O verificador padrão da plataforma é substituído de fato
    (não só quando o app chama o setter) e os verificadores da plataforma
    e do OkHttp são hookados.
  - **Nativo**: `SSL_set_verify` (a variante por conexão, a mais usada),
    `SSL_CTX_set_verify`, `X509_verify_cert` e o verificador customizado
    do BoringSSL.

  O comportamento é verificado ponta a ponta por
  `tests/device_smoke.py`, que exige que a requisição **falhe** sem o
  bypass e **passe** com ele.

### 6. Hook de veredito (`scripts/verdict_hook.js`)

Enganar as primitivas de detecção não é o bastante: o SDK ainda
comunica a decisão ao app — por um callback de ameaça ou por um método
que devolve um veredito — e o app reage a partir dali.

O hook de veredito neutraliza essa comunicação. A varredura é feita pelo
**nome do método** (`onThreatDetected`, `terminateApp`, `isCompromised`,
…), que descreve a ação e se mantém estável mesmo quando o SDK muda de
pacote ou de classe. Métodos sem retorno deixam de reportar; métodos
booleanos devolvem "nada errado".

O catálogo de SDKs conhecidos fica em `rasp_vendors.py` — é dado, não
código: tokens de logcat, pacotes e classes de cada SDK. O mesmo
catálogo alimenta a detecção estática no APK e a correlação de logcat.

---

## Estrutura do repositório

```
raspilot/
├── main.py                     # CLI + pipeline de auditoria
├── device_manager.py           # ADB (USB/Wi-Fi) + frida-server + logcat/baseline
├── logcat_analyzer.py          # Correlação de mortes/segurança/TLS no logcat
├── reporter.py                 # Relatórios JSON/HTML (Jinja2)
├── checks/
│   ├── anti_root.py            # Detecção de root multi-vetor
│   ├── anti_frida.py           # Presença/detecção de Frida
│   ├── anti_emulator.py        # Classificação de emuladores
│   ├── anti_hooking.py         # Detecção + bypass de anti-hooking
│   ├── combined.py             # Observação/bypass em sessão única
│   ├── stealth.py              # Bootstrap nativo antes do resume
│   ├── apk_utils.py            # Helpers compartilhados + cache de APK
│   └── ssl_pinning.py          # Detecção + bypass de SSL pinning
├── scripts/
│   ├── ssl_bypass.js           # Bypass universal de SSL pinning (Frida)
│   ├── anti_frida_bypass.js    # Bypass de detecção de Frida (Frida)
│   ├── anti_hooking_bypass.js  # Bypass de detecção de hooking (Frida)
│   ├── verdict_hook.js         # Neutraliza o callback de ameaça do RASP
│   └── anti_root_bypass.js     # Bypass de detecção de root (Frida)
├── rasp_vendors.py             # Catálogo de SDKs de RASP conhecidos
├── templates/report.html.j2    # Template do relatório HTML
├── reports/                    # Saída dos relatórios
└── tests/                      # Suíte pytest (100% mockada, sem dispositivo)
```

## Testes

```bash
pip install -r requirements-dev.txt
pytest -v
```

A suíte cobre: parsing de output do ADB (mock de `subprocess.run`),
consolidação (`run_all`) de cada check com dados mockados, geração do
relatório JSON contra um snapshot de schema, detecção de pinning e
anti-hooking em APKs sintéticos, o modelo de evidência (confiança alta
vs contexto), a camada de bypass e o pipeline completo de ponta a ponta
(com `DeviceManager` mockado). Nenhum dispositivo físico é necessário
para os testes.

Cada teste tem um teto de tempo: um teste que trava vira falha com o
stack de todas as threads, em vez de segurar a máquina indefinidamente.

Há também um **teste de device** para o bypass de SSL pinning, que exige
aparelho conectado e um app instalado:

```bash
python tests/device_smoke.py --package <package>
```

Ele sobe um servidor HTTPS com certificado auto-assinado no host e faz
uma requisição pelo JVM do app. O teste exige que a requisição **falhe**
sem o bypass e **passe** com ele — o controle negativo é o que prova que
o bypass é o motivo.

---

## Integração MCP (próxima fase — planejada)

Os `run_all()` de cada check são funções puras: recebem o `DeviceManager`
injetado e retornam `dict`, sem efeitos colaterais globais — prontos para
serem envolvidos como ferramentas MCP com `FastMCP`:

| Ferramenta MCP planejada | Mapeamento interno |
|---|---|
| `raspilot_iniciar_avaliacao(package_name, device_id=None) -> dict` | `DeviceManager.connect_adb()` + `setup_frida_server()` + pipeline |
| `raspilot_verificar_anti_root(device_id) -> dict` | `AntiRootCheck(dm).run_all()` |
| `raspilot_verificar_anti_frida(device_id) -> dict` | `AntiFridaCheck(dm).run_all(session, pid)` |
| `raspilot_verificar_anti_emulator(device_id) -> dict` | `AntiEmulatorCheck(dm).run_all()` |
| `raspilot_verificar_anti_hooking(device_id, package_name) -> dict` | `AntiHookingCheck(dm).run_all(package)` |
| `raspilot_bypass_ssl_pinning(device_id, package_name) -> dict` | `SSLPinningCheck(dm).run_all(package)` |
| `raspilot_obter_relatorio() -> dict` | `Reporter.generate_json()` |

O JSON emitido pelo RASPilot já segue um schema estável
(`metadata` / `summary` / `details`) pensado para leitura direta por LLMs.
`metadata.schema_version` permite detectar mudanças incompatíveis e
`metadata.run` registra o contexto da execução (argumentos da CLI, versão
do Frida, porta, hashes sha256 dos scripts de injeção, pid alvo e
resultado do baseline) para que a execução possa ser reproduzida.

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| `adb` não encontrado | Platform Tools fora do PATH | Instale e adicione `adb` ao PATH |
| `Dispositivo AUNAUTHORIZED` | Depuração USB não confirmada | Aceite o prompt no aparelho |
| `frida-server não respondeu` | Versão local ≠ servidor | `pip install -U frida frida-tools` e rode de novo |
| `Dispositivo não ficou pronto em 15s` | Offline/USB com problema | Confira cabo/`adb kill-server` |
| App spawnado mas checks vazios | App protegido contra debugger | Use `--verbose` e inspecione `details` no JSON |
| Verificação curta demais para apps lentos | Splash longa ou RASP tardio | Aumente com `--window 20` (ou mais) |
| `SKIP` com `skip_reason` no bypass | A camada Java não ficou ativa a tempo | Aumente `--java-timeout`; veja *Limitações conhecidas* |
| App morre logo após o resume | Auto-destruição do app ao detectar a instrumentação | A camada nativa neutraliza `abort`/sinais; as ações neutralizadas aparecem em `neutralized_actions` |

---

## Limitações conhecidas

**A camada Java depende da anexação do agente à máquina virtual do app.**
A bridge Java obtém o `JNIEnv` da thread do agente de instrumentação.
Quando uma proteção aborta ou bloqueia essa anexação, a camada Java
simplesmente não sobe: os checks que dependem dela ficam `SKIP` com o
motivo em `skip_reason`, e a camada nativa continua valendo. Isso é
comportamento por app e precisa de um contorno específico do SDK.

**A neutralização de auto-destruição é ativa por padrão.** Vasos de RASP
que abortam o processo ou o param com um sinal de parada são
interceptados na camada nativa, para que a janela de observação não
termine antes do fim. As ações neutralizadas ficam em
`details.<check>.<fase>.neutralized_actions` — são evidência do que o app
tentou fazer, e não uma detecção do app.

**O logcat é evidência de apoio, não de veredito.** Termos genéricos
(`root`, `hook`, `detected`) e logs de ferramentas do operador não
sustentam nenhuma conclusão. Ver *Semântica de status*.

**A evasão nativa só cobre pontos de baixo volume.** As funções de
string da libc (`strcmp`, `memcmp`) são chamadas dezenas de milhares de
vezes por segundo pelo runtime do app e pelo motor JavaScript do agente
de instrumentação. Um gancho nesses pontos consome o tempo do agente,
que deixa de responder — e o sintoma é uma sessão que trava sem erro.
Por isso a camada nativa se concentra nas funções de baixo volume
(`strstr`, `raise`, `kill`, `abort`, `exit`); a comparação exata de
nomes continua coberta pela camada Java e pelo filtro de `/proc`.

**As classes geradas pela camada Java dependem do diretório de cache.**
A bridge grava a classe temporária em um diretório próprio; o padrão
dela não é gravável pelo processo do app, e o registro falha. O
diretório do app é aplicado no momento do uso — a bridge redefine o
valor quando se inicializa, e isso pode acontecer depois do
carregamento do script.

## Licença e uso

Ferramenta de auditoria de segurança para uso **autorizado** apenas
(aplicativos e dispositivos sob seu controle ou com escopo de teste
contratado).
