package com.raspilot.module;

import android.os.Build;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Camada de emulador.
 *
 * No modo probe o app enxerga um ambiente emulado; no modo mask os
 * artefatos decisivos ficam ocultos e os secundarios seguem expostos,
 * reproduzindo o cenario de um emulador com camada de stealth.
 */
public final class EmulatorShield {

    /** Canais decisivos: assinatura que nenhum device real apresenta. */
    private static final String[] DECISIVE_BUILD = {
            "FINGERPRINT", "MODEL", "MANUFACTURER", "BRAND", "DEVICE",
            "PRODUCT", "HARDWARE", "BOARD", "TAGS",
    };

    /** Canais secundarios: artefatos que um emulador real deixa expostos. */
    private static final String[] SECONDARY_BUILD = {
            "ID", "HOST", "TYPE", "USER", "SERIAL", "BOOTLOADER", "DISPLAY",
    };

    /** Valores de emulador usados no modo probe. */
    private static final Map<String, String> EMU_BUILD = new LinkedHashMap<>();

    /** Valores limpos usados no modo mask (canais decisivos). */
    private static final Map<String, String> CLEAN_BUILD = new LinkedHashMap<>();

    /** Valores de emulador usados no modo probe (propriedades). */
    private static final Map<String, String> EMU_PROPS = new LinkedHashMap<>();

    /** Valores limpos usados no modo mask (propriedades). */
    private static final Map<String, String> CLEAN_PROPS = new LinkedHashMap<>();

    /** Termes que identificam ambiente emulado. */
    private static final String[] EMU_TOKENS = {
            "goldfish", "ranchu", "vbox", "qemu", "sdk_gphone", "sdk_phone",
            "generic_x86", "genymotion", "bluestacks", "windroye", "droid4x",
            "emulator", "android sdk built for", "ttvm",
    };

    /** Arquivos que so existem em ambiente emulado. */
    private static final String[] EMU_FILES = {
            "/dev/qemu_pipe",
            "/dev/socket/qemud",
            "/dev/goldfish_pipe",
            "/sys/qemu_trace",
            "/init.goldfish.rc",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/lib64/libc_malloc_debug_qemu.so",
    };

    /** Identidade de telefonia de um ambiente emulado. */
    private static final Map<String, String> EMU_TELEPHONY = new LinkedHashMap<>();

    static {
        EMU_BUILD.put("FINGERPRINT",
                "google/sdk_gphone64_x86_64/emu64a:13/TQ3A.230901.001/10750268:user/release-keys");
        EMU_BUILD.put("MODEL", "sdk_gphone64_x86_64");
        EMU_BUILD.put("MANUFACTURER", "Google");
        EMU_BUILD.put("BRAND", "google");
        EMU_BUILD.put("DEVICE", "emu64a");
        EMU_BUILD.put("PRODUCT", "sdk_gphone64_x86_64");
        EMU_BUILD.put("HARDWARE", "goldfish");
        EMU_BUILD.put("BOARD", "goldfish_x86");
        EMU_BUILD.put("ID", "TQ3A.230901.001");
        EMU_BUILD.put("HOST", "Build-Temporary");
        EMU_BUILD.put("TAGS", "test-keys");
        EMU_BUILD.put("TYPE", "userdebug");
        EMU_BUILD.put("USER", "android");
        EMU_BUILD.put("SERIAL", "unknown");
        EMU_BUILD.put("BOOTLOADER", "unknown");
        EMU_BUILD.put("DISPLAY", "EMU");

        CLEAN_BUILD.put("FINGERPRINT",
                "samsung/o1sxeea/o1s:13/TP1A.220624.014/G991BXXU5AWCL:user/release-keys");
        CLEAN_BUILD.put("MODEL", "SM-G991B");
        CLEAN_BUILD.put("MANUFACTURER", "samsung");
        CLEAN_BUILD.put("BRAND", "samsung");
        CLEAN_BUILD.put("DEVICE", "o1s");
        CLEAN_BUILD.put("PRODUCT", "o1sxeea");
        CLEAN_BUILD.put("HARDWARE", "sm8150");
        CLEAN_BUILD.put("BOARD", "o1s");
        CLEAN_BUILD.put("TAGS", "release-keys");

        EMU_PROPS.put("ro.kernel.qemu", "1");
        EMU_PROPS.put("ro.boot.qemu", "1");
        EMU_PROPS.put("ro.kernel.qemu.gles", "1");
        EMU_PROPS.put("ro.qemu.sf", "1");
        EMU_PROPS.put("qemu.sf", "1");
        EMU_PROPS.put("ro.hardware", "goldfish");
        EMU_PROPS.put("ro.boot.hardware", "ranchu");
        EMU_PROPS.put("ro.hardware.egl", "emulation");
        EMU_PROPS.put("ro.product.model", "sdk_gphone64_x86_64");
        EMU_PROPS.put("ro.product.name", "sdk_gphone64_x86_64");
        EMU_PROPS.put("ro.product.device", "emu64a");
        EMU_PROPS.put("ro.product.brand", "google");
        EMU_PROPS.put("ro.product.manufacturer", "Google");
        EMU_PROPS.put("ro.build.fingerprint", EMU_BUILD.get("FINGERPRINT"));
        EMU_PROPS.put("ro.build.tags", "test-keys");
        EMU_PROPS.put("ro.build.characteristics", "emulator,phone");
        EMU_PROPS.put("ro.build.id", EMU_BUILD.get("ID"));
        EMU_PROPS.put("ro.build.host", EMU_BUILD.get("HOST"));
        EMU_PROPS.put("ro.build.user", EMU_BUILD.get("USER"));
        EMU_PROPS.put("ro.build.type", EMU_BUILD.get("TYPE"));
        EMU_PROPS.put("ro.build.display.id", EMU_BUILD.get("ID"));
        EMU_PROPS.put("ro.serialno", EMU_BUILD.get("SERIAL"));
        EMU_PROPS.put("ro.boot.serialno", EMU_BUILD.get("SERIAL"));
        EMU_PROPS.put("ro.bootloader", EMU_BUILD.get("BOOTLOADER"));
        EMU_PROPS.put("ro.product.cpu.abi", "x86_64");

        CLEAN_PROPS.put("ro.kernel.qemu", "");
        CLEAN_PROPS.put("ro.boot.qemu", "");
        CLEAN_PROPS.put("ro.kernel.qemu.gles", "");
        CLEAN_PROPS.put("ro.qemu.sf", "");
        CLEAN_PROPS.put("qemu.sf", "");
        CLEAN_PROPS.put("ro.hardware", "sm8150");
        CLEAN_PROPS.put("ro.boot.hardware", "qcom");
        CLEAN_PROPS.put("ro.hardware.egl", "adreno");
        CLEAN_PROPS.put("ro.product.model", "SM-G991B");
        CLEAN_PROPS.put("ro.product.name", "o1sxeea");
        CLEAN_PROPS.put("ro.product.device", "o1s");
        CLEAN_PROPS.put("ro.product.brand", "samsung");
        CLEAN_PROPS.put("ro.product.manufacturer", "samsung");
        CLEAN_PROPS.put("ro.build.fingerprint",
                "samsung/o1sxeea/o1s:13/TP1A.220624.014/G991BXXU5AWCL:user/release-keys");
        CLEAN_PROPS.put("ro.build.tags", "release-keys");
        CLEAN_PROPS.put("ro.build.characteristics", "default");
        CLEAN_PROPS.put("ro.build.id", "TP1A.220624.014");
        CLEAN_PROPS.put("ro.build.host", "localhost");
        CLEAN_PROPS.put("ro.build.user", "user");
        CLEAN_PROPS.put("ro.build.type", "user");
        CLEAN_PROPS.put("ro.build.display.id", "TP1A.220624.014");
        CLEAN_PROPS.put("ro.serialno", "R5CT30ABCDE");
        CLEAN_PROPS.put("ro.boot.serialno", "R5CT30ABCDE");
        CLEAN_PROPS.put("ro.bootloader", "SM-G991B");
        CLEAN_PROPS.put("ro.product.cpu.abi", "arm64-v8a");

        EMU_TELEPHONY.put("getDeviceId", "000000000000000");
        EMU_TELEPHONY.put("getImei", "000000000000000");
        EMU_TELEPHONY.put("getMeid", "000000000000000");
        EMU_TELEPHONY.put("getSubscriberId", "310260000000000");
        EMU_TELEPHONY.put("getSimSerialNumber", "89012600000000000000");
        EMU_TELEPHONY.put("getNetworkOperatorName", "Android");
        EMU_TELEPHONY.put("getNetworkOperator", "310260");
        EMU_TELEPHONY.put("getSimOperator", "310260");
        EMU_TELEPHONY.put("getLine1Number", "15555215554");
    }

    private EmulatorShield() {
    }

    /**
     * Instala os hooks da camada de emulador.
     *
     * @param config Configuracao efetiva do modulo.
     */
    public static void install(RaspilotConfig config) {
        String mode = config.emulatorMode;
        boolean probe = config.emulatorProbe();
        boolean mask = RaspilotConfig.EMU_MASK.equals(mode);
        boolean observe = RaspilotConfig.EMU_OBSERVE.equals(mode);

        if (probe || mask) {
            applyBuildValues(probe, mask);
        }
        hookSystemProperties(probe, mask, observe);
        hookEmulatorFiles(probe, mask, observe);
        if (probe || observe) {
            hookTelephony(probe);
        }
        if (probe || observe) {
            hookAndroidId(probe);
        }
    }

    /**
     * Aplica valores de Build conforme o modo.
     *
     * @param probe True para valores de emulador.
     * @param mask True para sanitizar apenas valores emulados.
     */
    private static void applyBuildValues(boolean probe, boolean mask) {
        for (String name : DECISIVE_BUILD) {
            if (probe) {
                applyBuildField(name, EMU_BUILD.get(name));
            } else if (mask) {
                String current = readBuildField(name);
                if (current != null && looksEmulated(current)) {
                    applyBuildField(name, CLEAN_BUILD.get(name));
                }
            }
        }
        if (!probe) {
            return;
        }
        for (String name : SECONDARY_BUILD) {
            applyBuildField(name, EMU_BUILD.get(name));
        }
    }

    /**
     * Le um campo estatico de Build.
     *
     * @param name Nome do campo.
     * @return Valor atual ou null.
     */
    private static String readBuildField(String name) {
        try {
            Field field = Build.class.getField(name);
            Object value = field.get(null);
            return value == null ? null : value.toString();
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Sobrescreve um campo estatico de Build.
     *
     * @param name Nome do campo.
     * @param value Valor a aplicar (null mantem o valor original).
     */
    private static void applyBuildField(String name, String value) {
        if (value == null) {
            return;
        }
        try {
            Field field = Build.class.getField(name);
            setStaticFinal(field, value);
            Evidence.emit("spoof", "emulator:spoof", "Build." + name, value);
        } catch (Throwable error) {
            Evidence.error("Build." + name, error);
        }
    }

    /**
     * Escreve em um campo estatico final.
     *
     * @param field Campo alvo.
     * @param value Valor a aplicar.
     * @throws Exception Quando a escrita nao e possivel.
     */
    private static void setStaticFinal(Field field, Object value) throws Exception {
        field.setAccessible(true);
        Field modifiers = null;
        try {
            modifiers = Field.class.getDeclaredField("modifiers");
            modifiers.setAccessible(true);
            modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        } catch (Throwable ignored) {
            // Sem o acesso ao campo "modifiers" ainda resta a tentativa direta.
        }
        try {
            field.set(null, value);
        } finally {
            if (modifiers != null) {
                try {
                    modifiers.setInt(field, field.getModifiers() | Modifier.FINAL);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static void hookSystemProperties(final boolean probe, final boolean mask,
                                             final boolean observe) {
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            XposedBridge.hookMethod(clazz.getMethod("get", String.class),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[0];
                            String key = raw == null ? null : raw.toString();
                            String channel = propChannel(key);
                            if (channel == null) {
                                return;
                            }
                            if (observe) {
                                Evidence.emit("observe", "emulator:" + channel,
                                        "SystemProperties.get", String.valueOf(key));
                            }
                            if (mask && "decisive".equals(channel)) {
                                String current = readProperty(key);
                                if (current != null && looksEmulated(current)) {
                                    param.setResult(CLEAN_PROPS.get(key));
                                    Evidence.emit("neutralize", "emulator:decisive",
                                            "SystemProperties.get", key + " (mask)");
                                }
                                return;
                            }
                            if (probe) {
                                String spoofed = EMU_PROPS.get(key);
                                if (spoofed != null) {
                                    param.setResult(spoofed);
                                    Evidence.emit("neutralize", "emulator:" + channel,
                                            "SystemProperties.get", key + "=" + spoofed);
                                }
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("SystemProperties.get", error);
        }
    }

    private static void hookEmulatorFiles(final boolean probe, final boolean mask,
                                          final boolean observe) {
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
                            if (!isEmulatorFile(path)) {
                                return;
                            }
                            if (observe) {
                                Evidence.emit("observe", "emulator:decisive",
                                        "File.exists", path);
                            }
                            if (probe) {
                                param.setResult(Boolean.TRUE);
                                param.returnEarly = true;
                                Evidence.emit("neutralize", "emulator:decisive",
                                        "File.exists", path + " (presente)");
                            } else if (mask) {
                                param.setResult(Boolean.FALSE);
                                param.returnEarly = true;
                                Evidence.emit("neutralize", "emulator:decisive",
                                        "File.exists", path + " (oculto)");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("File.exists (emulador)", error);
        }
    }

    private static void hookTelephony(final boolean probe) {
        for (final String name : EMU_TELEPHONY.keySet()) {
            try {
                XposedHelpers.findAndHookMethod(
                        "android.telephony.TelephonyManager", XposedBridge.BOOTCLASSLOADER,
                        name, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                if (probe) {
                                    param.setResult(EMU_TELEPHONY.get(name));
                                    param.returnEarly = true;
                                    Evidence.emit("neutralize", "emulator:secondary",
                                            "TelephonyManager." + name,
                                            EMU_TELEPHONY.get(name));
                                } else {
                                    Evidence.emit("observe", "emulator:secondary",
                                            "TelephonyManager." + name, "consulta");
                                }
                            }
                        });
            } catch (Throwable error) {
                Evidence.error("TelephonyManager." + name, error);
            }
        }
    }

    private static void hookAndroidId(final boolean probe) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.provider.Settings$Secure", XposedBridge.BOOTCLASSLOADER,
                    "getString",
                    android.content.ContentResolver.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object raw = param.args == null ? null : param.args[1];
                            String key = raw == null ? null : raw.toString();
                            if (!"android_id".equalsIgnoreCase(key)) {
                                return;
                            }
                            if (probe) {
                                param.setResult("9774d56d682e549c");
                                param.returnEarly = true;
                                Evidence.emit("neutralize", "emulator:secondary",
                                        "Settings.Secure.getString", "android_id");
                            } else {
                                Evidence.emit("observe", "emulator:secondary",
                                        "Settings.Secure.getString", "android_id");
                            }
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("Settings.Secure.getString", error);
        }
    }

    /**
     * Le uma propriedade do sistema sem hook.
     *
     * @param key Nome da propriedade.
     * @return Valor atual ou null.
     */
    private static String readProperty(String key) {
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            Method get = clazz.getMethod("get", String.class);
            Object result = get.invoke(null, key);
            return result instanceof String ? (String) result : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Indica o canal de uma propriedade.
     *
     * @param key Nome da propriedade.
     * @return "decisive", "secondary" ou null.
     */
    private static String propChannel(String key) {
        if (key == null) {
            return null;
        }
        if (!EMU_PROPS.containsKey(key)) {
            return null;
        }
        for (String decisive : DECISIVE_PROPS) {
            if (decisive.equals(key)) {
                return "decisive";
            }
        }
        return "secondary";
    }

    /** Propriedades decisivas (nenhum device real apresenta). */
    private static final String[] DECISIVE_PROPS = {
            "ro.kernel.qemu", "ro.boot.qemu", "ro.kernel.qemu.gles", "ro.qemu.sf",
            "qemu.sf", "ro.hardware", "ro.boot.hardware", "ro.hardware.egl",
            "ro.product.model", "ro.product.name", "ro.product.device",
            "ro.product.brand", "ro.product.manufacturer", "ro.build.fingerprint",
            "ro.build.tags", "ro.build.characteristics",
    };

    /**
     * Verifica se um valor tem assinatura de ambiente emulado.
     *
     * @param value Valor consultado.
     * @return True quando o valor denota emulador.
     */
    private static boolean looksEmulated(String value) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase();
        for (String token : EMU_TOKENS) {
            if (lower.contains(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verifica se um caminho pertence a um ambiente emulado.
     *
     * @param path Caminho consultado.
     * @return True quando o caminho e exclusivo de emulador.
     */
    public static boolean isEmulatorFile(String path) {
        if (path == null) {
            return false;
        }
        for (String file : EMU_FILES) {
            if (file.equals(path)) {
                return true;
            }
        }
        return false;
    }
}
