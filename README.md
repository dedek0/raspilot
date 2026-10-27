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
- Android SDK (`build-tools` + `platform`) e um JDK — **apenas** para compilar
  o módulo de instrumentação descrito abaixo. Sem eles, o RASPilot continua
  funcionando com o método `frida` (veja *Módulo de instrumentação*).
- **Opcional:** Droid ASC (`pip install -r requirements-static.txt`,
  Python 3.10+) para a análise estática semântica do APK. Sem ele, o
  RASPilot usa a varredura de assinaturas embutida.

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
# análise estática semântica (opcional, requer Python 3.10+)
pip install -r requirements-static.txt
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
| `--hook-method MÉTODO` | não | Bypass anti-hook: `frida` (agente injetado), `module` (APK de hooking no dispositivo, limitado ao pacote alvo) ou `auto` (default: usa o módulo quando há framework disponível) |
| `--emulator-method MÉTODO` | não | Probe/bypass anti-emulador: `frida`, `module` ou `auto` (default) |
| `--module-apk PATH` | não | APK pré-construído do módulo de instrumentação (dispensa o build, que exige o SDK do Android) |
| `--static-engine MOTOR` | não | Análise estática do APK: `auto` (default; ASC se instalado, senão varredura de bytes), `asc` (exige Droid ASC), `builtin` (só varredura de bytes) ou `off` |
| `--static-timeout SEG` | não | Timeout por consulta ao Droid ASC (default `60`) |
| `--js-runtime RUNTIME` | não | Runtime JavaScript do Frida: `qjs` (default) ou `v8` |
| `--verbose` | não | Logging em nível DEBUG |
| `--skip CHECK...` | não | Checks a pular (`anti_root`, `anti_frida`, `anti_emulator`, `anti_hooking`, `ssl_pinning`) |
| `--avd` | não | Audita contra o AVD configurado em vez do device físico (sobe o emulador, espera o boot e o encerra no final) |
| `--avd-config PATH` | não | Configuração JSON do ambiente emulado (default `~/.raspilot/avd.json` ou `$RASPILOT_AVD_CONFIG`) |
| `--avd-name NOME` | não | Nome do AVD, sobrescrevendo a configuração |
| `--avd-check` | não | Valida o ambiente emulado e mostra o que falta (sem auditar) |

### Saída

- Terminal: tabela colorida **"RASPilot — Relatório de Auditoria RASP"** e,
  em seguida, o **log de execução** com o que cada check tentou, o que
  encontrou e o status reportado
- `reports/<package>_<timestamp>.json` — documento estruturado
  (`metadata`, `summary`, `execution_log`, `details`) para consumo por
  LLMs/MCP
- `reports/<package>_<timestamp>.html` — relatório visual com badges de
  status, evidências e a mesma trilha de execução

O `execution_log` é uma lista de etapas no formato
`{check, phase, action, outcome, details, evidence, reported_status}`.
As fases são `context` (ambiente da auditoria), `static` (análise do APK),
`detection` (observação em runtime), `bypass` e `verdict`. Os resultados
possíveis são `detected`, `not_detected`, `success`, `blocked`, `resisted`,
`inconclusive`, `skipped`, `not_applicable` e `error`; o
`reported_status` repete o veredito final (`OK`/`FALHOU`/`SKIP`/`N/A`/`ERROR`).

Durante os checks dinâmicos o RASPilot também captura o **logcat** do
dispositivo. O logcat é usado como fonte independente de evidência para
correlacionar mortes (`SIGKILL`, `SIGSEGV`, `am_kill`, `am_crash`, ANR),
mensagens de SDKs de segurança e erros de TLS/pinning. Antes de qualquer
spawn com Frida, um **baseline sem instrumentação** verifica se o app já
morre sozinho; assim um crash da instrumentação ou o ciclo de vida normal
do app não é confundido com uma reação do RASP.
Antes de qualquer spawn, um **perfil estático** do APK é construído uma única vez e compartilhado pelos checks: varredura de assinaturas (sempre) + manifesto, classes e referências de método via Droid ASC (quando instalado). O perfil fica em cache por hash dos APKs e serve para separar "o app não tem proteção" de "o bypass venceu a proteção" e para apontar lacunas de cobertura dos hooks. Ele **não** substitui a observação dinâmica: presença no APK não prova execução.

A observação anti-Frida + anti-hooking roda em uma **sessão única**, e os bypasses de anti-hooking/SSL compartilham outro spawn. A detecção e o bypass anti-Frida usam spawns separados: primeiro mede-se a reação do app; depois a evasão nativa é carregada antes do resume. O anti-emulador roda **por último**, com spawns próprios: o probe faz o app enxergar um emulador, e um spawn compartilhado contaminaria os demais checks. O cache de APK fica em `~/.raspilot/cache/apk` (desative com `RASPILOT_APK_CACHE=0`); o cache do perfil estático fica em `~/.raspilot/cache/static` (desative com `RASPILOT_STATIC_CACHE=0`).

Semântica de status:

| Status | Significado |
|---|---|
| `OK` | Ambiente/proteção OK (ex: SSL pinning resistiu ao bypass, app detectou e bloqueou o Frida/hooking/emulador) |
| `FALHOU` | Ameaça presente ou bypass venceu (ex: root no ambiente, pinning contornado, proteção anti-hook/anti-emulador existe mas o bypass passou) |
| `N/A` | Não aplicável: não existe a proteção que se mediria (ex: sem SSL pinning, ou anti-Frida sem referência de alta confiança no APK e sem detecção em runtime) |
| `SKIP` | Etapa que não rodou: pulada via `--skip`, ou bypass não avaliado apesar de a proteção existir (o motivo vai em `skip_reason`) |
| `ERROR` | A verificação não pôde concluir (o pipeline continua) — inclui observação inconclusiva |

> **Anti-Frida:** quando o perfil estático está disponível e **não** encontra
> nenhuma referência de alta confiança a Frida, e o app também não reage em
> runtime, o status passa a ser `N/A` (não havia proteção a ser vencida).
> Se o APK referencia a checagem mas o app não reage, o status continua
> `FALHOU`: a proteção existe no código, mas não foi observada na janela.
> O motivo fica em `verdict_reason`. Quando a evasão é executada, o status
> final considera `bypass_successful`: `True` ⇒ `FALHOU` (RASP
> contornado), `False` ⇒ `OK` (proteção resistiu à evasão).

> **Anti-Root:** `is_rooted` continua sendo o veredito do **dispositivo**
> e aparece no resumo. Quando a fase no app roda, `protection_detected` e
> `bypass_successful` determinam o status da proteção do app; se a bridge
> Java não subir, o bypass fica `SKIP` com o motivo, sem afirmar que o app
> não detecta root.

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

### 0. Análise estática do APK (`checks/static/`)

O perfil estático é construído uma vez por execução e compartilhado pelos
cinco checks. Ele tem duas camadas:

1. **Varredura de bytes (sempre disponível)** — lê `AndroidManifest.xml`,
   `*.dex`, `lib/**/*.so`, `assets/flutter_assets*` e `res/xml/*` e procura
   assinaturas ASCII/UTF-16LE. É a mesma base já usada pelos checks, agora
   consolidada em uma passada.
2. **Droid ASC (opcional)** — executa `getmanifest`, `listclass` e um
   conjunto curado de `findrefs` para descobrir **em qual classe/método**
   a API ou string aparece. É isso que permite dizer "o app referencia
   `X509TrustManager` na classe `X`" em vez de apenas "o APK contém a
   string".

Para cada vetor (`frida`, `hooking`, `root`, `emulator`, `pinning`) o
perfil registra `present`, `confidence`, `findings` (fonte, classe, método,
evidência) e `possible_gaps` — técnicas que os scripts de bypass atuais
não cobrem, como pinning nativo em BoringSSL ou leitura nativa de
`/proc/self/maps`. A presença estática **não** é tratada como prova de
execução.

A confiança é calibrada para evitar falso positivo: `okhttp`/Flutter/
Conscrypt empacotados não contam como pinning; um `X509TrustManager`
customizado só conta com indício de pinning; `getStackTrace` isolado não
conta como anti-hook; e uma string `frida` genérica não conta como
anti-Frida.

Cada achado também recebe um **dono**: `app`, `rasp_sdk`,
`third_party_sdk`, `framework`, `library` ou `unknown` (código
ofuscado). O relatório expõe `static_owners` e `app_evidence`, para
distinguir uma checagem do app de uma classe empacotada de biblioteca
ou de um SDK terceiro.

O ASC é executado como subprocesso, com timeout e cache por hash do APK.
Sem ele (ou com `--static-engine builtin`), o RASPilot continua
funcionando com a varredura de bytes e registra a limitação no relatório.
O cache fica em `~/.raspilot/cache/static` e pode ser desligado com
`RASPILOT_STATIC_CACHE=0`.

Limitações: o ASC lê o APK instalado; código nativo, DEX empacotado ou
carregado em runtime não são cobertos. Uma string referenciada pode estar
em código morto. Por isso o perfil é evidência de superfície, não de
comportamento.

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

Além do veredito do dispositivo, o check mede a **detecção de root do
app** e tenta o bypass:

- **Módulo (Xposed/LSPosed)**: quando disponível, observa RootBeer,
  `File`, `Runtime.exec`, `SystemProperties` e `PackageManager` sem Frida
  externo; o bypass neutraliza essas APIs pelo módulo.
- **Observação Frida**: carrega `root_detection.js` nativo antes do
  resume e Java depois; cobre o caso em que o app bloqueia a bridge.
- **Bypass Frida**: `anti_root_bypass.js` tem camada nativa (paths,
  `strstr`/`strcmp`, `__system_property_get`) antes do resume e camada
  Java (RootBeer/File/exec/SystemProperties) depois.
  `bypass_successful=True` ⇒ RASP contornado (`FALHOU`);
  `False` ⇒ proteção resistiu (`OK`); `None` ⇒ não exercitado (`SKIP`).

`is_rooted` continua sendo o veredito do **dispositivo**. O relatório
mostra `protection_detected`, `bypass_successful` e
`app_root_detection.dynamic_detected` separadamente, para não confundir
“device rooteado” com “app detecta root”.

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
- **Análise estática**: assinaturas no APK (`frida` como palavra
  isolada, `gum-js-loop`, `libfrida`, `linjector`, `frida-gadget`) e, via
  ASC, referências com classe/método. Referências genéricas (texto de UI,
  nome do app) ficam em baixa/média confiança e não entram no veredito;
  só evidência de alta confiança (contexto de detecção, `gum-js-loop`,
  `linjector`, `libfrida`) conta como proteção anti-Frida.
- **Bypass (evasão)**: depois da detecção, um novo spawn carrega
  `proc_filter.js` + `anti_frida_bypass.js` antes do resume. Os hooks
  cobrem `strstr`, `strcmp`, `strncmp` e `memcmp` (com fast-path por
  tamanho/primeiro byte), paths e portas do Frida, nomes de threads,
  auto-destruição (`raise`/`abort`/`kill`/`exit`) e `syscall` direta de
  `exit_group`/`kill`/`tkill`/`tgkill`. O resultado separa detecção de
  evasão: `bypass_successful=True` ⇒ o app sobreviveu sem reagir (RASP
  contornado); `False` ⇒ a proteção resistiu à evasão.

`vulnerable=True` ⇒ o app **não** detectou o Frida (falha de RASP).
Quando o perfil estático está disponível e não encontra nenhuma proteção
anti-Frida de alta confiança, e o app também não reage, o check retorna
`N/A` em vez de `FALHOU` — não havia proteção a ser vencida. Se o APK
referencia a checagem mas o app não reage, o veredito continua `FALHOU` e
o motivo fica em `verdict_reason`.
O bypass correspondente vive em `scripts/anti_frida_bypass.js`.

### 3. Anti-Emulador (`checks/anti_emulator.py`)

Responde duas perguntas sobre o **app alvo** — e não sobre a máquina da
auditoria:

1. o app implementa proteção anti-emulador?
2. essa proteção pode ser contornada?

Fases:

- **Contexto do dispositivo**: propriedades QEMU, arquivos de kernel,
  arquitetura de CPU (x86 sem Chromebook), contagem de sensores, MAC de
  Bluetooth placeholder e detecção de Genymotion/LDPlayer/BlueStacks/Nox/
  Waydroid. É **informativo**: diz em que tipo de máquina a auditoria
  rodou, e não se o app é protegido.
- **Detecção estática**: assinaturas anti-emulador (métodos/classes de
  detecção de SDKs de RASP e strings de fingerprint como
  `ro.kernel.qemu`, `goldfish`, `sdk_gphone`), enriquecidas pelo perfil
  ASC (referências a `SystemProperties.get`, classes de SDK etc.).
- **Detecção dinâmica (probe)**: spawn suspenso com
  `scripts/emulator_spoof.js` no modo `probe` — o app passa a **enxergar
  um emulador** (`Build.*`, `SystemProperties`, `/dev/qemu_pipe`, IMEI,
  `ANDROID_ID`). Toda consulta do app a uma primitiva sensível é
  registrada, e o veredito se apoia na reação do app (veredito de
  detecção, morte do processo, log de ameaça).
- **Bypass (mask)**: novo spawn no modo `mask` — os artefatos **decisivos**
  (Build, `ro.kernel.qemu`, `/dev/qemu_pipe`) ficam ocultos, enquanto os
  artefatos **secundários** que um emulador real deixa expostos (IMEI
  zerado, `ANDROID_ID` de emulador, telco "Android") continuam visíveis.
  É o cenário realista de "emulador com camada de stealth": se o app
  ainda reage, é porque consulta um canal que não foi ocultado — e o
  relatório diz qual.

`protection_detected=False` ⇒ o app não possui checagens anti-emulador
observáveis (falha de RASP). `bypass_successful=True` ⇒ a proteção existe,
mas o bypass venceu.

Quando o app encerra o **agente de instrumentação** (anti‑Frida), a
observação é declarada **inconclusiva**: a morte não é atribuída à
detecção de emulador, e o bypass fica como `SKIP` com o motivo
registrado.

Com `--emulator-method module` (default quando há framework de hooking no
dispositivo), o probe e a máscara são executados **sem** instrumentação
externa: o app é executado normalmente enquanto o módulo faz o spoof. Isso
elimina a morte do agente como fator de confusão — o veredito passa a
refletir a reação do app ao ambiente emulado, e não à ferramenta.

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
- **Detecção estática**: procura assinaturas que SDKs anti-RASP usam
  para checar hooks (classes Xposed, LSPosed/lspd/LSPlant, EdXposed,
  Substrate, SandHook/YAHFA/Whale/Dobby e strings Frida), enriquecidas
  pelo perfil ASC (`findrefs` de `XposedBridge`, `org.lsposed`,
  `getStackTrace` e classes de frameworks).
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

A detecção anti-hook usa apenas artefatos de hooking (Xposed, LSPosed,
Substrate, SandHook/YAHFA/LSPlant/Whale/Dobby, Riru/Zygisk). Artefatos do
Frida são do vetor anti-Frida: a morte do app durante a instrumentação
**não** é creditada ao anti-hook sem um sinal anti-hook específico.

Com `--hook-method module` (default quando há framework de hooking no
dispositivo), a observação e o bypass rodam **sem** instrumentação externa:
o módulo é limitado ao pacote alvo, registra as consultas anti-hook do app
e as neutraliza. O veredito passa a se apoiar na reação do app ao
framework de hooking do próprio dispositivo — que é o vetor que a
proteção de fato fiscaliza.

### 5. SSL Pinning (`checks/ssl_pinning.py`)

- **Detecção estática**: varre o APK (`pm path` + `adb pull`) por
  assinaturas de OkHttp `CertificatePinner`, TrustKit,
  NetworkSecurityConfig, Flutter e Conscrypt/nativo (Manifest binário,
  DEX, libs nativas). Com ASC, o manifesto é decodificado
  (`networkSecurityConfig`, `debuggable`) e `findrefs impl
  X509TrustManager` localiza TrustManagers customizados. Referências
  empacotadas da própria biblioteca (okhttp/TrustKit) não contam como
  uso pelo app.
- **Evidência fraca**: se só houver indícios fracos (TrustManager
  customizado, `networkSecurityConfig` sem `pin-set`, BoringSSL) e uma
  lacuna nativa plausível, o bypass é executado como **probe** com janela
  mínima de 20s e navegação direcionada: `uiautomator` toca nós clicáveis
  do app e, se não houver dump, cai para `monkey`. Sem tráfego TLS, o
  resultado é `SKIP`; com tráfego interceptado, o relatório registra
  `tls_observed=true` e mantém `pinning_detected=false` (o pinning não
  foi confirmado no APK).
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

## Módulo de instrumentação (APK de hooking) — opcional

Tudo nesta seção é **opcional**: sem um framework de hooking no dispositivo
o RASPilot usa o método `frida` e o comportamento é o de sempre.

### Por que

O bypass via Frida injeta um **agente** no processo do app. Para um app com
proteção anti-hook, esse agente é o que mata a auditoria: o app encontra o
`frida-agent` no mapa de memória ou no stack trace antes de qualquer
checagem anti-hook acontecer.

Um **módulo (APK) de hooking** troca o Instrumento: em vez de um agente
injetado, o próprio dispositivo carrega o framework de hooking no processo
do app — exatamente o ambiente que a proteção anti-hook procura detectar.
O módulo neutraliza as consultas do app e o auditor observa o resultado
**sem** deixar rastro de injeção externa. É também o que permite medir o
anti-emulador sem depender da instrumentação: o app enxerga um emulador
enquanto roda normalmente.

### Como funciona

1. **Build** — `instrumentation/build.sh` compila o módulo com `aapt2`/`d8`/
   `apksigner` do SDK do Android (sem Gradle e sem rede). Os fontes ficam em
   `instrumentation/xposed/`.
2. **Instalação** — `adb install -r` do APK.
3. **Habilitação e escopo** — o módulo é habilitado e o escopo é definido
   **apenas para o pacote alvo** (`--package`), pelo cli do framework
   (`modules enable`, `scope set`).
4. **Configuração** — o modo da fase (`observe`, `bypass`, `probe`, `mask`)
   é escrito em uma propriedade do sistema, lida pelo módulo no início do
   processo: trocar de fase não exige reinstalar o APK.
5. **Execução** — o app é iniciado normalmente (sem Frida), e a evidência
   emitida pelo módulo é lida do logcat (`RASPilotModule: EVT|...`).
6. **Restauração** — o escopo original é devolvido, o módulo é desabilitado
   e o APK é removido do dispositivo.

### Requisitos

- dispositivo com **root** e um framework de hooking instalado (LSPosed,
  Vector, EdXposed) com cli de configuração disponível
- SDK do Android (`build-tools`, `platform`) e um JDK no host — ou um APK
  pronto com `--module-apk`

O toolchain de build é instalado sem privilégios de sistema:

```bash
./instrumentation/setup_toolchain.sh
```

Os requisitos detalhados estão em `instrumentation/requirements.txt`.

```bash
export ANDROID_HOME="$HOME/Android"
export JAVA_HOME="$HOME/Android/jdk"

# padrão: usa o módulo quando há framework no dispositivo
python main.py --package com.example.app

# força o módulo (falha se não houver framework)
python main.py --package com.example.app --hook-method module

# usa um APK já compilado
python main.py --package com.example.app --module-apk ./module.apk
```

### Cobertura e limitações

O módulo atua na **camada Java** do app: `Build`, `SystemProperties`,
`TelephonyManager`, `Settings.Secure` e `File.exists`. Verificações em
código nativo (leitura de `/proc/self/maps`, buscas de string) **não são
cobertas** — o relatório registra essa limitação em `coverage` e lista os
artefatos do framework que continuam visíveis no processo alvo.

---

## Ambiente emulado (AVD) — opcional

Tudo nesta seção é **opcional**: sem a flag `--avd` o RASPilot se
comporta exatamente como antes e **não depende do SDK Android**.

### Por que

O check anti-emulador mede o bypass de duas formas: o *probe* faz o app
enxergar um emulador e a *máscara* esconde os artefatos decisivos. Em um
device físico isso é uma simulação — o emulador é só o que o app enxerga.

Sobre um **AVD real**, os artefatos existem de verdade: o app recebe os
valores de um device físico enquanto a máquina é um emulador. É o ground
truth do bypass — e é o único jeito de medir de fato um app que bloqueia
a instrumentação (anti‑Frida), porque a proteção do emulador é avaliada
antes de a proteção do hook.

### Configuração do ambiente

**1. Instale o SDK Android** (cmdline-tools) e exporte a raiz:

```bash
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"
```

**2. Baixe a system image e crie o AVD:**

```bash
sdkmanager "system-images;android-33;google_apis;x86_64"
echo no | avdmanager create avd --name raspilot_avd \
    --package "system-images;android-33;google_apis;x86_64" \
    --device "pixel_6"
```

**3. Descreva o ambiente** em `~/.raspilot/avd.json` (ou aponte outro
caminho com `--avd-config` / `$RASPILOT_AVD_CONFIG`):

```json
{
  "sdk_root": "/home/user/Android/Sdk",
  "avd_name": "raspilot_avd",
  "system_image": "system-images;android-33;google_apis;x86_64",
  "device_profile": "pixel_6",
  "port": 5554,
  "headless": true,
  "wipe_data": false,
  "boot_timeout": 300,
  "extra_args": ["-no-snapshot-save", "-gpu", "swiftshader_indirect"]
}
```

| Chave | Padrão | Para quê |
|---|---|---|
| `sdk_root` | (`$ANDROID_SDK_ROOT`) | raiz do SDK Android |
| `avd_name` | — (obrigatório) | nome do AVD a subir |
| `system_image` | `system-images;android-33;google_apis;x86_64` | system image (apenas nas instruções) |
| `device_profile` | `pixel_6` | perfil de hardware (apenas nas instruções) |
| `port` | `5554` | porta do console/adb do emulador |
| `headless` | `true` | sobe sem janela e sem áudio |
| `wipe_data` | `false` | reinicia o AVD com dados limpos |
| `boot_timeout` | `300` | tempo máximo de espera pelo boot (s) |
| `extra_args` | `[]` | argumentos extras do `emulator` |

**4. Valide e rode:**

```bash
# mostra o que falta, sem auditar
python main.py --package com.example.app --avd-check

# sobe o AVD, audita nele e encerra o emulador no fim
python main.py --package com.example.app --avd
```

`--avd` sobe o emulador (ou reaproveita um que já esteja rodando),
espera `sys.boot_completed`, entrega o serial (`emulator-5554`) ao
`DeviceManager` e encerra **apenas** o emulador que ele mesmo subiu.

| Flag | Efeito |
|---|---|
| `--avd` | audita contra o AVD configurado |
| `--avd-config PATH` | caminho da configuração (default `~/.raspilot/avd.json`) |
| `--avd-name NOME` | sobrescreve o `avd_name` da configuração |
| `--avd-check` | valida o ambiente e mostra o que falta |

> **Limitações.** O AVD não reproduz proteções de hardware (TEE, attested
> provisioning, keystore por hardware) nem o perfil de um aparelho real.
> Uma execução em AVD complementa a auditoria em device físico — não a
> substitui. O `frida-server` é baixado para a ABI do emulador
> (`x86_64`), e apps que exigem Play Integrity podem não instalar.

> **Root no emulador.** As imagens `google_apis` são `userdebug`: o shell
> do `adb` já é root, e é isso que permite ao `frida-server` fazer
> spawn de apps que não são debuggable. Imagens `default`/`aosp` sem root
> limitam a auditoria a apps debuggable.

---

## Estrutura do repositório

```
raspilot/
├── main.py                     # CLI + pipeline de auditoria
├── requirements-static.txt     # Dependência opcional: Droid ASC (Python 3.10+)
├── avd_manager.py              # Ambiente emulado (AVD) opcional
├── device_manager.py           # ADB (USB/Wi-Fi) + frida-server + logcat/baseline
├── logcat_analyzer.py          # Correlação de mortes/segurança/TLS no logcat
├── reporter.py                 # Relatórios JSON/HTML (Jinja2)
├── execution_log.py            # Trilha: tentativa, achado e veredito por check
├── instrumentation/            # Módulo de instrumentação (APK de hooking)
│   ├── manager.py              # Preparação, escopo no framework e evidência
│   ├── build.sh                # Build do APK (aapt2/d8/apksigner, sem Gradle)
│   ├── setup_toolchain.sh      # Instala SDK do Android + JDK em ~/Android
│   ├── requirements.txt        # Requisitos do toolchain de build
│   └── xposed/                 # Fontes do módulo (anti-hook + root + emulador)
├── checks/
│   ├── anti_root.py            # Detecção de root multi-vetor
│   ├── anti_frida.py           # Presença/detecção/bypass de Frida
│   ├── anti_emulator.py        # Detecção + bypass de anti-emulador
│   ├── anti_hooking.py         # Detecção + bypass de anti-hooking
│   ├── combined.py             # Observação/bypass em sessão única
│   ├── stealth.py              # Bootstrap nativo antes do resume
│   ├── apk_utils.py            # Helpers compartilhados + cache de APK
│   ├── taxonomy.py             # Artefatos por vetor + dono do achado
│   ├── static/                 # Perfil estático (assinaturas + Droid ASC)
│   │   ├── engine.py           # Subprocesso, timeout e cache do ASC
│   │   ├── queries.py          # Assinaturas e consultas de alto sinal
│   │   └── profile.py          # Perfil, confiança e cobertura do bypass
│   └── ssl_pinning.py          # Detecção + bypass de SSL pinning
├── scripts/
│   ├── ssl_bypass.js           # Bypass universal de SSL pinning (Frida)
│   ├── anti_frida_bypass.js    # Bypass de detecção de Frida (Frida)
│   ├── anti_hooking_bypass.js  # Bypass de detecção de hooking (Frida)
│   ├── root_detection.js       # Observação de checagens de root do app
│   ├── emulator_spoof.js       # Spoof de emulador: probe e máscara (Frida)
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

O módulo de instrumentação tem testes próprios
(`tests/test_instrumentation.py` para o gerenciador e
`tests/test_instrumentation_checks.py` para a integração com os checks):
configuração, leitura da evidência no logcat, aplicação e
restauração do escopo no framework, e as fases de bypass/probe por
módulo nos checks de hooking e de emulador.

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
| `raspilot_verificar_anti_emulator(device_id, package_name) -> dict` | `AntiEmulatorCheck(dm).run_all(package)` |
| `raspilot_verificar_anti_hooking(device_id, package_name) -> dict` | `AntiHookingCheck(dm).run_all(package)` |
| `raspilot_bypass_ssl_pinning(device_id, package_name) -> dict` | `SSLPinningCheck(dm).run_all(package)` |
| `raspilot_obter_relatorio() -> dict` | `Reporter.generate_json()` |

O JSON emitido pelo RASPilot já segue um schema estável
(`metadata` / `summary` / `execution_log` / `details`) pensado para leitura
direta por LLMs. `metadata.schema_version` permite detectar mudanças
incompatíveis e `metadata.run` registra o contexto da execução (argumentos
da CLI, versão do Frida, porta, hashes sha256 dos scripts de injeção, pid
alvo e resultado do baseline) para que a execução possa ser reproduzida.

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
| `framework de hooking indisponível` | Nenhum framework com cli de configuração no aparelho | Use `--hook-method frida --emulator-method frida` |
| `Estático: droidasc não instalado` | Análise semântica opcional indisponível | `pip install -r requirements-static.txt` (Python 3.10+) ou use `--static-engine builtin` |
| `Estático: timeout após Ns` | APK grande ou máquina lenta | Aumente `--static-timeout`; o check continua com o resultado parcial |
| `build do módulo falhou` | SDK do Android ou JDK ausentes no host | Instale `build-tools` + `platform` em `$ANDROID_HOME` e um JDK, ou use `--module-apk` |

---

## Limitações conhecidas

**A análise estática é superfície, não comportamento.** O perfil do APK
encontra referências a checagens e aponta lacunas de cobertura, mas não
prova que o método foi executado. Código nativo, DEX empacotado/criptografado
e DEX carregado em runtime não são vistos pelo ASC; quando isso acontece,
o relatório registra a limitação e o veredito dinâmico continua sendo a
fonte de prova. No `anti_root`, o módulo cobre a camada Java e o Frida
cobre paths/strings nativos; se nenhuma checagem for exercitada, o
resultado fica `SKIP`, não `OK` nem `FALHOU`.

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

**O módulo de instrumentação atua na camada Java do app.**
Quando o bypass (ou o probe) roda pelo módulo, as consultas nativas do app
(leitura de `/proc/self/maps`, buscas de string em código nativo) não são
cobertas: o módulo não tem componente nativo. A limitação fica registrada
em `coverage.not_covered`, e os artefatos do framework que continuam
visíveis no processo alvo são listados em `framework_artifacts`.

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
