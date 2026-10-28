package com.raspilot.module;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Camada de anti-hook.
 *
 * Observa as consultas que o app faz a artefatos de frameworks de hooking
 * e, no modo de bypass, faz com que essas consultas voltem "nada".
 */
public final class HookShield {

    /** Termos que identificam frameworks de hooking. */
    private static final String[] TOKENS = {
            "xposed", "lsposed", "edxposed", "substrate", "sandhook", "yahfa",
            "lsplant", "dobby", "andhook", "shadowhook", "bytehook", "xhook",
            "whale", "epic", "riru", "frida", "gadget", "zygisk",
    };

    /** Pacotes de gerenciadores e modulos de frameworks conhecidos. */
    private static final String[] FRAMEWORK_PACKAGES = {
            "org.lsposed.manager",
            "org.lsposed",
            "de.robv.android.xposed",
            "org.lsposed.disableflagsecure",
            "com.topjohnwu.magisk.module",
    };

    /**
     * Marcador de sonda interna: enquanto verdadeiro, a leitura de
     * /proc feita pelo próprio módulo é emitida como ``probe`` e não
     * como consulta/neutralização do app.
     */
    private static volatile boolean probing = false;

    private HookShield() {
    }

    /**
     * Instala os hooks da camada de anti-hook.
     *
     * @param config Configuracao efetiva do modulo.
     * @param classLoader Class loader do processo alvo.
     */
    public static void install(RaspilotConfig config, ClassLoader classLoader) {
        boolean bypass = config.hookBypass();

        hookClassForName(bypass);
        hookLoadClass(bypass);
        hookFileExists(bypass);
        hookFileAttributes(bypass);
        hookProcStreams(bypass);
        hookRuntimeExec(bypass);
        hookProcessBuilder(bypass);
        hookSystemProperty(bypass);
        hookSystemEnv(bypass);
        hookSystemProperties(bypass);
        hookPackageManager(bypass, classLoader);
        hookPackageManagerListing(bypass, classLoader);
        hookRunningProcesses(bypass);
        hookAppTargets(config.hookTargets, classLoader);

        // Sonda ativa de instalação: prova que a tentativa de hooking
        // chegou ao processo do app (não apenas que o módulo carregou).
        Evidence.emit("probe", "hook", "probe-installed",
                "camada anti-hook instalada (mode="
                        + (bypass ? "bypass" : "observe") + ")");
        runVisibilityProbe(bypass);
    }

    /**
     * Observa métodos do próprio app achados pela análise estática.
     *
     * Diferente das demais camadas (que hookam APIs genéricas do
     * Android), aqui o alvo é código do app sob auditoria — a lista
     * compilada no APK a partir do perfil estático (ASC) daquele app
     * especificamente (ver {@link RaspilotConfig#hookTargets}).
     *
     * O hook é **só observação**: nunca invoca o método por reflexão
     * (poderia crashar o app com argumentos incorretos) nem altera seu
     * retorno. A evidência só conta quando o próprio app chama o
     * método durante a janela — é a prova mais direta de que o app
     * exercitou uma checagem de hooking em código seu, não apenas em
     * uma API de framework genérica.
     *
     * @param targets Alvos ``{classe_dalvik, método}`` do app atual.
     * @param classLoader Class loader do processo alvo.
     */
    private static void hookAppTargets(String[][] targets, ClassLoader classLoader) {
        if (targets == null || targets.length == 0) {
            return;
        }
        for (String[] target : targets) {
            if (target == null || target.length != 2) {
                continue;
            }
            final String className = dottedName(target[0]);
            final String methodName = target[1];
            if (className == null || className.length() == 0
                    || methodName == null || methodName.length() == 0) {
                continue;
            }
            try {
                Class<?> clazz = XposedHelpers.findClassIfExists(className, classLoader);
                if (clazz == null) {
                    continue;
                }
                boolean hookedAny = false;
                XC_MethodHook callback = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Evidence.emit("observe", "hook-app-target",
                                className + "->" + methodName,
                                "método do app achado pela análise estática foi chamado");
                    }
                };
                if ("<init>".equals(methodName)) {
                    // Construtor: nao aparece em getDeclaredMethods().
                    for (java.lang.reflect.Constructor<?> ctor
                            : clazz.getDeclaredConstructors()) {
                        try {
                            XposedBridge.hookMethod(ctor, callback);
                            hookedAny = true;
                        } catch (Throwable error) {
                            Evidence.error("hookAppTargets.<init>", error);
                        }
                    }
                } else {
                    for (Method candidate : clazz.getDeclaredMethods()) {
                        if (!methodName.equals(candidate.getName())) {
                            continue;
                        }
                        try {
                            XposedBridge.hookMethod(candidate, callback);
                            hookedAny = true;
                        } catch (Throwable error) {
                            Evidence.error("hookAppTargets." + methodName, error);
                        }
                    }
                }
                if (hookedAny) {
                    Evidence.emit("probe", "hook-app-target", "target-hooked",
                            className + "->" + methodName);
                }
            } catch (Throwable error) {
                Evidence.error("hookAppTargets", error);
            }
        }
    }

    /**
     * Converte um descritor Dalvik (``Lcom/app/Foo;``) em nome pontilhado.
     *
     * @param dalvikName Descritor no formato Dalvik ou já pontilhado.
     * @return Nome de classe pontilhado, ou null se vazio.
     */
    private static String dottedName(String dalvikName) {
        if (dalvikName == null) {
            return null;
        }
        String text = dalvikName.trim();
        if (text.startsWith("L")) {
            text = text.substring(1);
        }
        if (text.endsWith(";")) {
            text = text.substring(0, text.length() - 1);
        }
        return text.replace('/', '.');
    }

    /**
     * Mede se os artefatos do framework continuam visíveis para o app.
     *
     * A sonda lê ``/proc/self/maps`` com o marcador ``probing`` ativo
     * (para não virar consulta do app). No bypass, a camada de proc
     * substitui o conteúdo por ``/dev/null``; se o mapa ainda contiver
     * artefatos do framework, o relatório registra
     * ``bypass-incomplete`` em vez de declarar vitória.
     *
     * @param bypass True no modo bypass.
     */
    private static void runVisibilityProbe(final boolean bypass) {
        boolean mapsVisible = false;
        probing = true;
        try {
            mapsVisible = mapsContainsFramework();
        } catch (Throwable ignored) {
            mapsVisible = false;
        } finally {
            probing = false;
        }
        String detail = "maps=" + (mapsVisible ? "visible" : "hidden");
        Evidence.emit("probe", "hook", "visibility", detail);
        if (bypass) {
            if (!mapsVisible) {
                Evidence.emit("probe", "hook", "bypass-verified", detail);
            } else {
                Evidence.emit("probe", "hook", "bypass-incomplete", detail);
            }
        }
    }

    private static boolean mapsContainsFramework() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream("/proc/self/maps")));
            String line;
            while ((line = reader.readLine()) != null) {
                if (isFrameworkName(line)) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Throwable ignored) {
                }
            }
        }
        return false;
    }

    private static void hookClassForName(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.Class", XposedBridge.BOOTCLASSLOADER, "forName",
                    String.class, boolean.class, ClassLoader.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String name = raw == null ? null : raw.toString();
                            if (!isFrameworkName(name)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "Class.forName", String.valueOf(name));
                            if (bypass) {
                                throw new ClassNotFoundException(name);
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("Class.forName", error);
        }
    }

    private static void hookLoadClass(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.ClassLoader", XposedBridge.BOOTCLASSLOADER, "loadClass",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String name = raw == null ? null : raw.toString();
                            if (!isFrameworkName(name)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "ClassLoader.loadClass", String.valueOf(name));
                            if (bypass) {
                                throw new ClassNotFoundException(name);
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("ClassLoader.loadClass", error);
        }
    }

    private static void hookFileExists(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.io.File", XposedBridge.BOOTCLASSLOADER, "exists",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object target = param.thisObject;
                            if (!(target instanceof File)) {
                                return;
                            }
                            String path;
                            try {
                                path = ((File) target).getAbsolutePath();
                            } catch (Throwable error) {
                                return;
                            }
                            if (!isFrameworkPath(path)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "File.exists", path);
                            if (bypass) {
                                param.setResult(Boolean.FALSE);
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("File.exists", error);
        }
    }

    /**
     * Instala hooks nas variantes de atributos de arquivo.
     *
     * Protecoes usam metodos diferentes de ``exists`` para constatar a
     * presenca de artefatos: ``canRead``, ``length``, ``isDirectory`` e
     * ``canWrite``. Sem esses hooks, a drede em ``File.exists`` deixa
     * consultas comuns sem observacao nem neutralizacao.
     *
     * @param bypass True para neutralizar as consultas.
     */
    private static void hookFileAttributes(final boolean bypass) {
        String[] booleanMethods = {"canRead", "canWrite", "isDirectory"};
        for (String method : booleanMethods) {
            try {
                XposedHelpers.findAndHookMethod(
                        "java.io.File", XposedBridge.BOOTCLASSLOADER, method,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param)
                                    throws Throwable {
                                String path = fileOf(param);
                                if (path == null || !isFrameworkPath(path)) {
                                    return;
                                }
                                Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                        "File." + method, path);
                                if (bypass) {
                                    param.setResult(Boolean.FALSE);
                                    param.returnEarly = true;
                                }
                            }
                        });
            } catch (Throwable error) {
                Evidence.error("File." + method, error);
            }
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "java.io.File", XposedBridge.BOOTCLASSLOADER, "length",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            String path = fileOf(param);
                            if (path == null || !isFrameworkPath(path)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "File.length", path);
                            if (bypass) {
                                param.setResult(0L);
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("File.length", error);
        }
    }

    /**
     * Observa leituras de artefatos do processo via streams Java.
     *
     * As checagens anti-hook e anti-debug leem arquivos do proprio
     * processo: ``/proc/self/maps``, ``/proc/self/status``,
     * ``/proc/self/cmdline`` — normalmente atraves de
     * ``FileInputStream`` e ``RandomAccessFile``. Consultas a caminhos
     * de framework (que ja passam nas drede de caminho) continuam nos
     * canais habituais; este hook cobre o restante.
     *
     * A leitura de ``/proc`` tem uso legitimo (SDKs de relatorio de
     * crash analisam o mapa de memoria); por isso o evento sai como
     * contexto em observacao e precisa de outro canal para sustentar
     * veredito. No bypass, a leitura volta vazia: sem conteudo, a
     * checagem nao constata nada.
     *
     * @param bypass True para neutralizar as leituras.
     */
    private static void hookProcStreams(final boolean bypass) {
        try {
            XposedHelpers.findAndHookConstructor(
                    "java.io.FileInputStream", XposedBridge.BOOTCLASSLOADER,
                    String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String path = raw == null ? null : raw.toString();
                            handleProcPath(param, bypass, "FileInputStream"
                                    + (path == null ? "" : "(" + path + ")"), path);
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("FileInputStream(String)", error);
        }
        try {
            XposedHelpers.findAndHookConstructor(
                    "java.io.FileInputStream", XposedBridge.BOOTCLASSLOADER,
                    File.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String path = raw instanceof File
                                    ? ((File) raw).getAbsolutePath() : null;
                            handleProcPath(param, bypass, "FileInputStream(File)", path);
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("FileInputStream(File)", error);
        }
        try {
            XposedHelpers.findAndHookConstructor(
                    "java.io.RandomAccessFile", XposedBridge.BOOTCLASSLOADER,
                    String.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String path = raw == null ? null : raw.toString();
                            handleProcPath(param, bypass, "RandomAccessFile"
                                    + (path == null ? "" : "(" + path + ")"), path);
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("RandomAccessFile(String,String)", error);
        }
        try {
            XposedHelpers.findAndHookConstructor(
                    "java.io.RandomAccessFile", XposedBridge.BOOTCLASSLOADER,
                    File.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String path = raw instanceof File
                                    ? ((File) raw).getAbsolutePath() : null;
                            handleProcPath(param, bypass, "RandomAccessFile(File)", path);
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("RandomAccessFile(File,String)", error);
        }
    }

    /**
     * Trata uma consulta a caminho de processo pelo stream aberto.
     *
     * @param param .Parametros do hook.
     * @param bypass True no modo bypass.
     * @param method Nome legivel do metodo/constructor.
     * @param path   Caminho consultado (pode ser null).
     * @throws Throwable Ao abrir o stream de substituicao no bypass.
     */
    private static void handleProcPath(XC_MethodHook.MethodHookParam param,
                                       boolean bypass, String method,
                                       String path) throws Throwable {
        if (path == null || !isProcessArtifactPath(path)) {
            return;
        }
        if (probing) {
            Evidence.emit("probe", "hook", method, path);
        } else {
            Evidence.emit(bypass ? "neutralize" : "context", "hook",
                    method, path);
        }
        if (bypass) {
            String empty = "/dev/null";
            if (method.startsWith("FileInputStream")) {
                param.setResult(new FileInputStream(empty));
            } else {
                param.setResult(new RandomAccessFile(empty, "r"));
            }
            param.returnEarly = true;
        }
    }

    /**
     * Observa consultas a propriedades do sistema Android.
     *
     * SDKs de protecao consultam propriedades de artefatos (servicos
     * de framework em init.svc, chaves de ambientes instrumentados)
     * pelas APIs escondidas de propriedades, que nao passam em
     * ``System.getProperty``.
     *
     * @param bypass True para neutralizar as consultas.
     */
    private static void hookSystemProperties(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.os.SystemProperties", XposedBridge.BOOTCLASSLOADER,
                    "get", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String key = raw == null ? null : raw.toString();
                            if (!isFrameworkName(key)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "SystemProperties.get", String.valueOf(key));
                            if (bypass) {
                                param.setResult("");
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("SystemProperties.get", error);
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "android.os.SystemProperties", XposedBridge.BOOTCLASSLOADER,
                    "get", String.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String key = raw == null ? null : raw.toString();
                            if (!isFrameworkName(key)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "SystemProperties.get2", String.valueOf(key));
                            if (bypass) {
                                Object fallback = param.args.length > 1
                                        ? param.args[1] : "";
                                param.setResult(fallback);
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("SystemProperties.get(def)", error);
        }
    }

    /**
     * Observa consultas a listagens do PackageManager.
     *
     * Checagens de varredura procuram artefatos na lista de apps
     * instalados e em intents de integracao de framework. Emissao
     * somente com correspondencia: listagem legtima de apps (UI e
     * compartilhamento) nao vira evidencia.
     *
     * @param bypass      True para neutralizar as consultas.
     * @param classLoader Class loader do processo alvo.
     */
    private static void hookPackageManagerListing(final boolean bypass,
                                                   ClassLoader classLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.app.ApplicationPackageManager",
                    XposedBridge.BOOTCLASSLOADER, "queryIntentActivities",
                    android.content.Intent.class, int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            if (!(raw instanceof android.content.Intent)) {
                                return;
                            }
                            android.content.Intent intent =
                                    (android.content.Intent) raw;
                            String action = intent.getAction() == null
                                    ? "" : intent.getAction();
                            String pkg = intent.getPackage() == null
                                    ? "" : intent.getPackage();
                            if (!isFrameworkName(action)
                                    && !isFrameworkPackage(pkg)
                                    && !isFrameworkName(pkg)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "PackageManager.queryIntentActivities",
                                    "action=" + action + " pkg=" + pkg);
                            if (bypass) {
                                param.setResult(new ArrayList<Object>());
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("PackageManager.queryIntentActivities", error);
        }
        String[] listing = {"getInstalledPackages", "getInstalledApplications"};
        for (String method : listing) {
            try {
                XposedHelpers.findAndHookMethod(
                        "android.app.ApplicationPackageManager",
                        XposedBridge.BOOTCLASSLOADER, method, int.class,
                        new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param)
                                    throws Throwable {
                                String found = firstFrameworkEntry(param.getResult());
                                if (found == null) {
                                    return;
                                }
                                Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                        "PackageManager." + method, "frameworkPackages:" + found);
                                if (bypass) {
                                    param.setResult(stripFrameworkEntries(param.getResult()));
                                }
                            }
                        });
            } catch (Throwable error) {
                Evidence.error("PackageManager." + method, error);
            }
        }
    }

    /**
     * Observa a lista de processos vivos consultada pelo app.
     *
     * Procura por nomes de processos de ferramentas de instrumentacao
     * na lista devolvida ao app. Em observacao, emite somente com
     * correspondencia; no bypass, as entradas correspondentes saem da
     * lista antes de ser devolvidas.
     *
     * @param bypass True para neutralizar a consulta.
     */
    private static void hookRunningProcesses(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.app.ActivityManager",
                    XposedBridge.BOOTCLASSLOADER, "getRunningAppProcesses",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object raw = param.getResult();
                            if (!(raw instanceof List)) {
                                return;
                            }
                            String found = firstFrameworkEntry(raw);
                            if (found == null) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "ActivityManager.getRunningAppProcesses",
                                    "frameworkProcess:" + found);
                            if (bypass) {
                                param.setResult(stripFrameworkEntries(raw));
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("ActivityManager.getRunningAppProcesses", error);
        }
    }

    /**
     * Extrai o caminho absoluto do arquivo consultado pelo hook.
     *
     * @param param Parametros do hook (thisObject e um File).
     * @return Caminho ou null quando indisponivel.
     */
    private static String fileOf(XC_MethodHook.MethodHookParam param) {
        Object target = param.thisObject;
        if (!(target instanceof File)) {
            return null;
        }
        try {
            return ((File) target).getAbsolutePath();
        } catch (Throwable error) {
            return null;
        }
    }

    /**
     * Procura entradas de framework em uma colecao devolvida ao app.
     *
     * @param raw Resultado de metodo (List de PackageInfo,
     *            ApplicationInfo ou RunningAppProcessInfo).
     * @return Nome da primeira entrada corresponde ou null.
     */
    private static String firstFrameworkEntry(Object raw) {
        if (!(raw instanceof List)) {
            return null;
        }
        for (Object item : (List<?>) raw) {
            String name = packageNameOf(item);
            if (name != null && matchesFramework(name)) {
                return name;
            }
        }
        return null;
    }

    /**
     * Remove entradas de framework de uma copia da colecao.
     *
     * @param raw Resultado original do metodo.
     * @return Colecao sem as entradas correspondes.
     */
    private static List<Object> stripFrameworkEntries(Object raw) {
        List<Object> kept = new ArrayList<>();
        if (raw instanceof List) {
            for (Object item : (List<?>) raw) {
                String name = packageNameOf(item);
                if (name == null || !matchesFramework(name)) {
                    kept.add(item);
                }
            }
        }
        return kept;
    }

    /**
     * Extrai o nome de pacote/processo de um item de listagem.
     *
     * @param item Item de PackageManager/ActivityManager.
     * @return Nome ou null.
     */
    private static String packageNameOf(Object item) {
        if (item == null) {
            return null;
        }
        if (item instanceof android.content.pm.PackageInfo) {
            return ((android.content.pm.PackageInfo) item).packageName;
        }
        if (item instanceof android.content.pm.ApplicationInfo) {
            return ((android.content.pm.ApplicationInfo) item).packageName;
        }
        if (item instanceof android.app.ActivityManager.RunningAppProcessInfo) {
            return ((android.app.ActivityManager.RunningAppProcessInfo) item).processName;
        }
        return null;
    }

    /**
     * Informa se um nome corresponde a framework de hooking.
     *
     * @param name Nome de pacote ou processo.
     * @return True quando ha correspondencia.
     */
    public static boolean matchesFramework(String name) {
        return isFrameworkPackage(name) || isFrameworkName(name);
    }

    private static void hookRuntimeExec(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.Runtime", XposedBridge.BOOTCLASSLOADER, "exec",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String command = raw == null ? "" : raw.toString();
                            if (!isFrameworkName(command)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "Runtime.exec", command);
                            if (bypass) {
                                param.setResult(new SilentProcess());
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("Runtime.exec", error);
        }

        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.Runtime", XposedBridge.BOOTCLASSLOADER, "exec",
                    String[].class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String command = join(raw);
                            if (!isFrameworkName(command)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "Runtime.exec[]", command);
                            if (bypass) {
                                param.setResult(new SilentProcess());
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("Runtime.exec[]", error);
        }
    }

    private static void hookProcessBuilder(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.ProcessBuilder", XposedBridge.BOOTCLASSLOADER, "start",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object target = param.thisObject;
                            if (!(target instanceof ProcessBuilder)) {
                                return;
                            }
                            String command;
                            try {
                                command = join(((ProcessBuilder) target).command());
                            } catch (Throwable error) {
                                return;
                            }
                            if (!isFrameworkName(command)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "ProcessBuilder.start", command);
                            if (bypass) {
                                param.setResult(new SilentProcess());
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("ProcessBuilder.start", error);
        }
    }

    private static void hookSystemProperty(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.System", XposedBridge.BOOTCLASSLOADER, "getProperty",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String key = raw == null ? null : raw.toString();
                            if (!isFrameworkName(key)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "System.getProperty", String.valueOf(key));
                            if (bypass) {
                                param.setResult(null);
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("System.getProperty", error);
        }
    }

    private static void hookSystemEnv(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.System", XposedBridge.BOOTCLASSLOADER, "getenv",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String key = raw == null ? null : raw.toString();
                            if (!isFrameworkName(key)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                    "System.getenv", String.valueOf(key));
                            if (bypass) {
                                param.setResult(null);
                                param.returnEarly = true;
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("System.getenv", error);
        }
    }

    private static void hookPackageManager(final boolean bypass, ClassLoader classLoader) {
        // A classe concreta e necessaria: getPackageInfo em PackageManager
        // e abstrato e nao aceita hook.
        String[] owners = {
                "android.app.ApplicationPackageManager",
        };
        for (String owner : owners) {
            try {
                XposedHelpers.findAndHookMethod(
                        owner, XposedBridge.BOOTCLASSLOADER, "getPackageInfo",
                        String.class, int.class,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param)
                                    throws Throwable {
                                Object raw = param.args == null ? null : param.args[0];
                                String name = raw == null ? null : raw.toString();
                                if (!isFrameworkPackage(name)) {
                                    return;
                                }
                                Evidence.emit(bypass ? "neutralize" : "observe", "hook",
                                        "PackageManager.getPackageInfo", String.valueOf(name));
                                if (bypass) {
                                    throw new android.content.pm.PackageManager
                                            .NameNotFoundException(name);
                                }
                            }
                        });
            } catch (Throwable error) {
                Evidence.error("PackageManager.getPackageInfo", error);
            }
        }
    }

    /**
     * Verifica se um nome (classe, comando, propriedade) referencia um
     * framework de hooking.
     *
     * @param value Valor consultado.
     * @return True quando ha referencia a framework de hooking.
     */
    public static boolean isFrameworkName(String value) {
        if (value == null || value.length() < 4) {
            return false;
        }
        String lower = value.toLowerCase();
        for (String token : TOKENS) {
            if (containsToken(lower, token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verifica se um caminho referencia um framework de hooking.
     *
     * @param path Caminho consultado.
     * @return True quando ha referencia a framework de hooking.
     */
    public static boolean isFrameworkPath(String path) {
        if (path == null || path.length() < 4) {
            return false;
        }
        String lower = path.toLowerCase();
        if (lower.contains("/data/adb/lspd") || lower.contains("/data/adb/xposed")
                || lower.contains("/data/adb/modules") || lower.contains("/data/adb/riru")) {
            return true;
        }
        if (lower.startsWith("/data/local/tmp/frida")
                || lower.contains("/frida-server")
                || lower.contains("frida-gadget")) {
            return true;
        }
        return isFrameworkName(path);
    }

    /**
     * Informa se um caminho e um artefato do proprio processo.
     *
     * Protecoes anti-debug leem o mapa de memoria e o estado do
     * proprio processo antes de qualquer outro artefato; caminhos de
     * outros processos ficam fora do escopo.
     *
     * @param path Caminho consultado.
     * @return True quando o caminho referencia o processo atual.
     */
    public static boolean isProcessArtifactPath(String path) {
        if (path == null || path.length() < 10) {
            return false;
        }
        String lower = path.toLowerCase();
        if (lower.contains("/proc/self/")) {
            return true;
        }
        try {
            int pid = android.os.Process.myPid();
            if (lower.startsWith("/proc/" + Integer.toString(pid) + "/")) {
                return true;
            }
        } catch (Throwable ignored) {
            // O caminho por pid e dispensavel quando o pid falha.
        }
        return false;
    }

    /**
     * Verifica se um pacote pertence a um framework de hooking.
     *
     * @param name Nome do pacote.
     * @return True quando o pacote pertence a um framework conhecido.
     */
    public static boolean isFrameworkPackage(String name) {
        if (name == null || name.length() < 4) {
            return false;
        }
        for (String pkg : FRAMEWORK_PACKAGES) {
            if (pkg.equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Casa um termo como token isolado.
     *
     * @param lower Texto em minusculas.
     * @param token Termo procurado.
     * @return True quando o termo aparece isolado.
     */
    private static boolean containsToken(String lower, String token) {
        int index = lower.indexOf(token);
        while (index != -1) {
            boolean beforeOk = index == 0 || !isAlnum(lower.charAt(index - 1));
            int end = index + token.length();
            boolean afterOk = end >= lower.length() || !isAlnum(lower.charAt(end));
            if (beforeOk && afterOk) {
                return true;
            }
            index = lower.indexOf(token, index + 1);
        }
        return false;
    }

    private static boolean isAlnum(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    /**
     * Converte um array de argumentos em texto legivel.
     *
     * @param raw Valor bruto (array ou objeto).
     * @return Texto resultante.
     */
    private static String join(Object raw) {
        if (raw == null) {
            return "";
        }
        if (raw instanceof String[]) {
            List<String> parts = new ArrayList<>();
            for (String item : (String[]) raw) {
                parts.add(String.valueOf(item));
            }
            return join(parts.toArray());
        }
        if (raw instanceof Object[]) {
            Object[] items = (Object[]) raw;
            StringBuilder builder = new StringBuilder();
            for (Object item : items) {
                if (builder.length() > 0) {
                    builder.append(' ');
                }
                builder.append(String.valueOf(item));
            }
            return builder.toString();
        }
        return String.valueOf(raw);
    }
}
