package com.raspilot.module;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import java.io.File;
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
            "whale", "epic", "riru", "frida", "gadget",
    };

    /** Pacotes de gerenciadores e modulos de frameworks conhecidos. */
    private static final String[] FRAMEWORK_PACKAGES = {
            "org.lsposed.manager",
            "org.lsposed",
            "de.robv.android.xposed",
            "org.lsposed.disableflagsecure",
            "com.topjohnwu.magisk.module",
    };

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
        hookRuntimeExec(bypass);
        hookProcessBuilder(bypass);
        hookSystemProperty(bypass);
        hookSystemEnv(bypass);
        hookPackageManager(bypass, classLoader);
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
