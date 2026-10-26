# Módulo de instrumentação

Módulo compatível com a API Xposed (`IXposedHookLoadPackage`) usado pelo
RASPilot para medir as proteções anti-hook e anti-emulador **sem**
instrumentação externa: o app é executado com o framework de hooking do
próprio dispositivo, que é o ambiente que a proteção de fato fiscaliza.

## Layout

```
instrumentation/
├── __init__.py             # API pública (XposedManager, ModuleConfig)
├── manager.py              # Preparação, escopo, execução e evidência
├── build.sh                # Compila o APK (aapt2/d8/apksigner, sem Gradle)
├── setup_toolchain.sh      # Instala SDK do Android + JDK em ~/Android
├── requirements.txt        # Requisitos do toolchain de build
└── xposed/                 # Fontes do módulo Android
    ├── AndroidManifest.xml
    ├── assets/xposed_init  # Classe de entrada do módulo
    ├── api/                # Stubs da API Xposed (só tempo de compilação)
    └── src/com/raspilot/module/
        ├── RaspilotModule.java   # Ponto de entrada
        ├── RaspilotConfig.java   # Configuração da execução
        ├── RaspilotBaked.java    # Gerado no build (configuração padrão)
        ├── HookShield.java       # Camada anti-hook
        ├── EmulatorShield.java   # Camada de emulador
        ├── Evidence.java         # Emissor de evidência (logcat)
        ├── SilentProcess.java    # Processo sem efeito
        └── SilentOutputStream.java
```

## Requisitos

O módulo é um APK Android e **não tem dependências pip**. O build exige,
no host:

| Requisito | Versão | Origem |
|---|---|---|
| Android SDK — `build-tools` | >= 34 | `sdkmanager` |
| Android SDK — `platform` | android-33 ou superior | `sdkmanager` |
| JDK | 17+ (`javac`, `jar`, `keytool`) | Temurin/OpenJDK |

Instalação automatizada, sem privilégios de sistema:

```bash
./instrumentation/setup_toolchain.sh
```

Depois, exporte o ambiente:

```bash
export ANDROID_HOME="$HOME/Android"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME="$ANDROID_HOME/jdk"
export PATH="$ANDROID_HOME/platform-tools:$JAVA_HOME/bin:$PATH"
```

Sem o toolchain o RASPilot continua funcionando: os checks usam o método
`frida` (veja `--hook-method` / `--emulator-method`).

## Build

```bash
export ANDROID_HOME="$HOME/Android"
export JAVA_HOME="$ANDROID_HOME/jdk"

./instrumentation/build.sh --hook bypass --emu off --target com.example.app --label bypass
```

Opções: `--hook off|observe|bypass`, `--emu off|observe|probe|mask`,
`--target PACOTE`, `--label NOME`, `--out CAMINHO_APK`.

O build usa apenas o SDK do Android (`build-tools` + `platform`) e um JDK.
As classes da API Xposed em `xposed/api/` servem **apenas** à compilação:
em tempo de execução elas são fornecidas pelo framework do dispositivo e
não são empacotadas no APK.

## Configuração em execução

O modo da fase é lido de uma propriedade do sistema:

```
persist.raspilot.module.config = hook=<modo>;emu=<modo>;target=<pacote>;label=<rótulo>
```

Ela é lida no início do processo, o que permite trocar de fase sem
reinstalar o APK. Sem a propriedade, valem os valores compilados no APK.

## Evidência

Cada evento é escrito no logcat com a tag `RASPilotModule`:

```
RASPilotModule: EVT|<tipo>|<canal>|<método>|<detalhe>
```

Tipos: `observe` (consulta do app), `neutralize` (consulta neutralizada),
`spoof` (valor aplicado pelo módulo), `ready` (módulo carregado), `context`
(registro sem sustentação de veredito — leitura de `/proc` tem uso legítimo)
e `error`.

## Cobertura

A camada anti-hook neutraliza `Class.forName`,
`ClassLoader.loadClass`, `File.exists` (e variantes `canRead`,
`canWrite`, `length`, `isDirectory`), `Runtime.exec`,
`ProcessBuilder.start`, `System.getProperty`, `System.getenv`,
`SystemProperties.get`, `PackageManager.getPackageInfo` e
`queryIntentActivities` de framework. As listagens
`getInstalledPackages`, `getInstalledApplications` e
`getRunningAppProcesses` são observadas quando contêm artefatos de
framework (e, no bypass, as entradas correspondentes saem da lista).
Leituras de artefatos do próprio processo — `/proc/self/*` — via
`FileInputStream`/`RandomAccessFile` são registradas como `context` e,
no bypass, devolvidas vazias (stream de `/dev/null`).

A camada de emulador atua sobre `Build`, `SystemProperties.get`,
`TelephonyManager`, `Settings.Secure` e `File.exists`.

Durante a janela de observação os checks de `anti_hooking` simulam
interação do usuário (eventos `monkey` no app alvo): proteções que só
exercitam checagens na navegação deixam de ficar fora da janela.

Verificações escritas em código nativo (consultas diretas via
`open()`/`read()` sem passar por Java) **não** são cobertas: o módulo
não tem componente nativo. O relatório registra a limitação em
`coverage.not_covered` e lista em `framework_artifacts` os artefatos do
framework que continuam visíveis no processo alvo.
