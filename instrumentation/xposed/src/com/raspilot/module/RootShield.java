package com.raspilot.module;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Camada de deteccao de root.
 *
 * Observa as consultas que o app faz a paths, comandos, propriedades,
 * packages e APIs do RootBeer e, no modo bypass, faz com que elas voltem
 * "nada". A camada nativa do Frida cobre os checks que nao passam pelo
 * Java.
 */
public final class RootShield {

    private static final String[] ROOT_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/system/app/Superuser.apk", "/system/xbin/daemonsu",
            "/data/adb/magisk", "/sbin/.magisk", "/system/bin/magisk",
            "/system/bin/busybox", "/system/xbin/busybox",
    };

    private static final String[] ROOT_PROPS = {
            "ro.debuggable", "ro.secure", "service.adb.root", "ro.build.tags",
            "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
    };

    private static final String[] ROOT_PACKAGES = {
            "com.topjohnwu.magisk", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su",
            "com.kingroot.kinguser", "me.bmax.apatch", "me.weishu.kernelsu",
            "com.rifsxd.ksunext",
    };

    private static final String[] ROOT_TOKENS = {
            "magisk", "superuser", "busybox", "rootbeer", "test-keys",
            "daemonsu", "rootcloak",
    };

    private RootShield() {
    }

    /**
     * Instala os hooks da camada de root.
     *
     * @param config Configuracao efetiva do modulo.
     * @param classLoader Class loader do processo alvo.
     */
    public static void install(RaspilotConfig config, ClassLoader classLoader) {
        boolean bypass = config.rootBypass();
        hookFileApis(bypass);
        hookRuntimeExec(bypass);
        hookProcessBuilder(bypass);
        hookSystemProperties(bypass);
        hookPackageManager(bypass);
        hookRootBeer(bypass, classLoader);
        hookDeveloperSettings(bypass);
        hookInstallSource(bypass);
        hookBuildFields(bypass);
    }

    private static boolean isRootPath(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase();
        for (String candidate : ROOT_PATHS) {
            if (lower.contains(candidate)) {
                return true;
            }
        }
        return lower.endsWith("/su") || lower.equals("su");
    }

    private static boolean isRootCommand(String command) {
        if (command == null) {
            return false;
        }
        String lower = command.toLowerCase();
        if (lower.contains("magisk") || lower.contains("busybox")
                || lower.contains("which su") || lower.contains("/su")) {
            return true;
        }
        return lower.matches(".*(^|[\\s;|&])su($|[\\s;|&]).*");
    }

    private static boolean isRootProp(String key) {
        if (key == null) {
            return false;
        }
        for (String candidate : ROOT_PROPS) {
            if (candidate.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isRootPackage(String pkg) {
        if (pkg == null) {
            return false;
        }
        for (String candidate : ROOT_PACKAGES) {
            if (candidate.equals(pkg)) {
                return true;
            }
        }
        return false;
    }

    private static String filePath(Object target) {
        if (!(target instanceof File)) {
            return null;
        }
        try {
            return ((File) target).getAbsolutePath();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void hookFileApis(final boolean bypass) {
        String[] methods = {"exists", "canRead", "canWrite", "isDirectory"};
        for (String method : methods) {
            try {
                XposedHelpers.findAndHookMethod(
                        "java.io.File", XposedBridge.BOOTCLASSLOADER, method,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                String path = filePath(param.thisObject);
                                if (!isRootPath(path)) {
                                    return;
                                }
                                Evidence.emit(bypass ? "neutralize" : "observe",
                                        "root", "File." + method, path);
                                if (bypass) {
                                    param.setResult(Boolean.FALSE);
                                }
                            }
                        });
            } catch (Throwable error) {
                Evidence.error("root.File." + method, error);
            }
        }
    }

    private static void hookRuntimeExec(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.Runtime", XposedBridge.BOOTCLASSLOADER, "exec",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            String command = String.valueOf(param.args[0]);
                            if (!isRootCommand(command)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe",
                                    "root", "Runtime.exec", command);
                            if (bypass) {
                                throw new IOException("su not found");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("root.Runtime.exec", error);
        }
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.Runtime", XposedBridge.BOOTCLASSLOADER, "exec",
                    String[].class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            String[] args = (String[]) param.args[0];
                            StringBuilder joined = new StringBuilder();
                            if (args != null) {
                                for (String arg : args) {
                                    joined.append(arg).append(' ');
                                }
                            }
                            if (!isRootCommand(joined.toString())) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe",
                                    "root", "Runtime.exec[]", joined.toString());
                            if (bypass) {
                                throw new IOException("su not found");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("root.Runtime.exec[]", error);
        }
    }

    private static void hookProcessBuilder(final boolean bypass) {
        try {
            XposedHelpers.findAndHookMethod(
                    "java.lang.ProcessBuilder", XposedBridge.BOOTCLASSLOADER,
                    "start",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            Object target = param.thisObject;
                            String joined = "";
                            try {
                                Method command = target.getClass()
                                        .getMethod("command");
                                Object value = command.invoke(target);
                                joined = String.valueOf(value);
                            } catch (Throwable ignored) {
                            }
                            if (!isRootCommand(joined)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe",
                                    "root", "ProcessBuilder.start", joined);
                            if (bypass) {
                                throw new IOException("su not found");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("root.ProcessBuilder.start", error);
        }
    }

    private static void hookSystemProperties(final boolean bypass) {
        try {
            Class<?> clazz = XposedHelpers.findClass(
                    "android.os.SystemProperties", XposedBridge.BOOTCLASSLOADER);
            XposedBridge.hookAllMethods(clazz, "get", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.args == null || param.args.length == 0) {
                        return;
                    }
                    String key = String.valueOf(param.args[0]);
                    if (!isRootProp(key)) {
                        return;
                    }
                    Evidence.emit(bypass ? "neutralize" : "observe",
                            "root", "SystemProperties.get", key);
                    if (bypass) {
                        param.setResult(safePropValue(key));
                    }
                }
            });
        } catch (Throwable error) {
            Evidence.error("root.SystemProperties", error);
        }
    }

    private static String safePropValue(String key) {
        if ("ro.debuggable".equals(key) || "service.adb.root".equals(key)) {
            return "0";
        }
        if ("ro.secure".equals(key)) {
            return "1";
        }
        if ("ro.build.tags".equals(key)) {
            return "release-keys";
        }
        return "";
    }

    private static void hookPackageManager(final boolean bypass) {
        try {
            Class<?> clazz = XposedHelpers.findClass(
                    "android.app.ApplicationPackageManager",
                    XposedBridge.BOOTCLASSLOADER);
            XposedBridge.hookAllMethods(clazz, "getPackageInfo",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            if (param.args == null || param.args.length == 0) {
                                return;
                            }
                            String pkg = String.valueOf(param.args[0]);
                            if (!isRootPackage(pkg)) {
                                return;
                            }
                            Evidence.emit(bypass ? "neutralize" : "observe",
                                    "root", "PackageManager.getPackageInfo", pkg);
                            if (bypass) {
                                param.setResult(null);
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("root.PackageManager", error);
        }
    }

    private static void hookRootBeer(final boolean bypass,
                                     ClassLoader classLoader) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(
                    "com.scottyab.rootbeer.RootBeer", classLoader);
            if (clazz == null) {
                return;
            }
            XposedBridge.hookAllMethods(clazz, "checkForRoot",
                    rootBeerHook(bypass, "checkForRoot"));
            XposedBridge.hookAllMethods(clazz, "isRooted",
                    rootBeerHook(bypass, "isRooted"));
            XposedBridge.hookAllMethods(clazz, "checkSuExists",
                    rootBeerHook(bypass, "checkSuExists"));
            XposedBridge.hookAllMethods(clazz, "checkForBinary",
                    rootBeerHook(bypass, "checkForBinary"));
            XposedBridge.hookAllMethods(clazz, "checkForDangerousProps",
                    rootBeerHook(bypass, "checkForDangerousProps"));
            XposedBridge.hookAllMethods(clazz, "checkForRWPaths",
                    rootBeerHook(bypass, "checkForRWPaths"));
            XposedBridge.hookAllMethods(clazz, "detectTestKeys",
                    rootBeerHook(bypass, "detectTestKeys"));
            XposedBridge.hookAllMethods(clazz, "checkForMagiskBinary",
                    rootBeerHook(bypass, "checkForMagiskBinary"));
            XposedBridge.hookAllMethods(clazz, "checkForRootNative",
                    rootBeerHook(bypass, "checkForRootNative"));
        } catch (Throwable error) {
            Evidence.error("root.RootBeer", error);
        }
    }

    private static XC_MethodHook rootBeerHook(final boolean bypass,
                                              final String name) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                Evidence.emit(bypass ? "neutralize" : "observe",
                        "root", "RootBeer." + name, "chamado");
                if (!bypass) {
                    return;
                }
                Method method = (Method) param.method;
                Class<?> type = method.getReturnType();
                if (type == boolean.class || type == Boolean.class) {
                    param.setResult(Boolean.FALSE);
                } else if (List.class.isAssignableFrom(type)) {
                    param.setResult(new ArrayList<Object>());
                } else if (type == int.class || type == Integer.class) {
                    param.setResult(0);
                } else if (type == String.class) {
                    param.setResult("");
                } else {
                    param.setResult(null);
                }
            }
        };
    }

    /** Chaves de desenvolvedor/ADB usadas por checagens de integridade. */
    private static final String[] DEVELOPER_KEYS = {
            "adb_enabled",
            "development_settings_enabled",
            "install_non_market_apps",
            "verifier_verify_adb_installs",
            "package_verifier_user_consent",
            "package_verifier_enable",
    };

    private static boolean isDeveloperKey(String key) {
        if (key == null) {
            return false;
        }
        for (String candidate : DEVELOPER_KEYS) {
            if (candidate.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private static void hookDeveloperSettings(final boolean bypass) {
        if (!bypass) {
            return;
        }
        for (String className : new String[]{
                "android.provider.Settings$Global",
                "android.provider.Settings$Secure",
        }) {
            try {
                XposedHelpers.findAndHookMethod(
                        className, XposedBridge.BOOTCLASSLOADER,
                        "getString",
                        android.content.ContentResolver.class, String.class,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                String key = String.valueOf(param.args[1]);
                                if (!isDeveloperKey(key)) {
                                    return;
                                }
                                param.setResult("0");
                                Evidence.emit("neutralize", "root",
                                        className + ".getString", key);
                            }
                        });
            } catch (Throwable error) {
                Evidence.error("root.developer.getString", error);
            }
            for (Class<?>[] types : new Class<?>[][]{
                    {android.content.ContentResolver.class, String.class, int.class},
                    {android.content.ContentResolver.class, String.class},
            }) {
                try {
                    XC_MethodHook getIntHook = new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String key = String.valueOf(param.args[1]);
                            if (!isDeveloperKey(key)) {
                                return;
                            }
                            param.setResult(0);
                            Evidence.emit("neutralize", "root",
                                    className + ".getInt", key);
                        }
                    };
                    if (types.length == 3) {
                        XposedHelpers.findAndHookMethod(
                                className, XposedBridge.BOOTCLASSLOADER,
                                "getInt", types[0], types[1], types[2],
                                getIntHook);
                    } else {
                        XposedHelpers.findAndHookMethod(
                                className, XposedBridge.BOOTCLASSLOADER,
                                "getInt", types[0], types[1], getIntHook);
                    }
                } catch (Throwable ignored) {
                    // Overload pode não existir na versão do Android.
                }
            }
        }
        try {
            XposedHelpers.findAndHookMethod(
                    android.os.Debug.class, "isDebuggerConnected",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(false);
                            Evidence.emit("neutralize", "root",
                                    "Debug.isDebuggerConnected", "false");
                        }
                    });
        } catch (Throwable ignored) {
            // Sem efeito em versões que não expõem o método.
        }
    }

    private static void hookInstallSource(final boolean bypass) {
        if (!bypass) {
            return;
        }
        try {
            Class<?> clazz = XposedHelpers.findClass(
                    "android.app.ApplicationPackageManager",
                    XposedBridge.BOOTCLASSLOADER);
            XposedBridge.hookAllMethods(clazz, "getInstallerPackageName",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult("com.android.vending");
                            Evidence.emit("neutralize", "root",
                                    "getInstallerPackageName", "loja oficial");
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("root.installSource", error);
        }
        try {
            Class<?> clazz = XposedHelpers.findClass(
                    "android.content.pm.InstallSourceInfo",
                    XposedBridge.BOOTCLASSLOADER);
            for (String method : new String[]{
                    "getInstallingPackageName",
                    "getInitiatingPackageName",
                    "getUpdateOwnerPackageName",
            }) {
                XposedBridge.hookAllMethods(clazz, method,
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                param.setResult("com.android.vending");
                                Evidence.emit("neutralize", "root",
                                        "InstallSourceInfo." + method,
                                        "loja oficial");
                            }
                        });
            }
            XposedBridge.hookAllMethods(clazz, "getOriginatingPackageName",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(null);
                        }
                    });
            XposedBridge.hookAllMethods(clazz, "getPackageSource",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(2);
                            Evidence.emit("neutralize", "root",
                                    "InstallSourceInfo.getPackageSource", "store");
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("root.installSourceInfo", error);
        }
    }

    private static void hookBuildFields(final boolean bypass) {
        if (!bypass) {
            return;
        }
        try {
            XposedHelpers.setStaticObjectField(
                    android.os.Build.class, "TAGS", "release-keys");
            XposedHelpers.setStaticObjectField(
                    android.os.Build.class, "TYPE", "user");
            String fingerprint = android.os.Build.FINGERPRINT;
            if (fingerprint != null && fingerprint.contains("test-keys")) {
                XposedHelpers.setStaticObjectField(
                        android.os.Build.class, "FINGERPRINT",
                        fingerprint.replace("test-keys", "release-keys"));
            }
            Evidence.emit("neutralize", "root", "Build", "release-keys/user");
        } catch (Throwable error) {
            Evidence.error("root.Build", error);
        }
    }
}
