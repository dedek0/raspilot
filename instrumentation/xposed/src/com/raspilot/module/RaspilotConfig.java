package com.raspilot.module;

/**
 * Configuracao efetiva do modulo.
 *
 * A configuracao nasce de valores compilados no APK e pode ser
 * substituida em tempo de execucao por uma propriedade do sistema, o que
 * permite trocar o comportamento entre fases sem reinstalar o modulo.
 */
public final class RaspilotConfig {

    /** Propriedade do sistema com a configuracao de execucao. */
    public static final String RUNTIME_PROPERTY = "persist.raspilot.module.config";

    /** Modo da camada de anti-hook. */
    public static final String HOOK_OFF = "off";
    public static final String HOOK_OBSERVE = "observe";
    public static final String HOOK_BYPASS = "bypass";

    /** Modo da camada de root. */
    public static final String ROOT_OFF = "off";
    public static final String ROOT_OBSERVE = "observe";
    public static final String ROOT_BYPASS = "bypass";

    /** Modo da camada de anti-tampering. */
    public static final String TAMPER_OFF = "off";
    public static final String TAMPER_OBSERVE = "observe";
    public static final String TAMPER_BYPASS = "bypass";

    /** Modo da camada de emulador. */
    public static final String EMU_OFF = "off";
    public static final String EMU_OBSERVE = "observe";
    public static final String EMU_PROBE = "probe";
    public static final String EMU_MASK = "mask";

    private static RaspilotConfig instance;

    public final String hookMode;
    public final String rootMode;
    public final String tamperMode;
    public final String emulatorMode;
    public final String targetPackage;
    public final String label;
    public final boolean runtimeOverride;
    /**
     * Metodos do proprio app (classe_dalvik, metodo) achados pela
     * analise estatica do APK sob auditoria. Compilados no APK do
     * modulo — nao ha override em runtime, pois a lista e especifica
     * do build atual (ver build.sh --hook-targets).
     */
    public final String[][] hookTargets;

    private RaspilotConfig(String hookMode, String rootMode, String tamperMode,
                            String emulatorMode, String targetPackage, String label,
                            boolean runtimeOverride, String[][] hookTargets) {
        this.hookMode = hookMode;
        this.rootMode = rootMode;
        this.tamperMode = tamperMode;
        this.emulatorMode = emulatorMode;
        this.targetPackage = targetPackage;
        this.label = label;
        this.runtimeOverride = runtimeOverride;
        this.hookTargets = hookTargets;
    }

    /**
     * Resolve a configuracao efetiva do modulo.
     *
     * @return Configuracao resolvida (valores compilados + override).
     */
    public static synchronized RaspilotConfig resolve() {
        if (instance != null) {
            return instance;
        }
        String hook = RaspilotBaked.HOOK_MODE;
        String root = RaspilotBaked.ROOT_MODE;
        String tamper = RaspilotBaked.TAMPER_MODE;
        String emu = RaspilotBaked.EMULATOR_MODE;
        String target = RaspilotBaked.TARGET_PACKAGE;
        String label = RaspilotBaked.LABEL;
        boolean overridden = false;

        String raw = readProperty(RUNTIME_PROPERTY);
        if (raw != null && raw.length() > 0) {
            String[] parts = raw.split(";");
            for (String part : parts) {
                int eq = part.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String key = part.substring(0, eq).trim();
                String value = part.substring(eq + 1).trim();
                if ("hook".equals(key)) {
                    hook = value;
                    overridden = true;
                } else if ("root".equals(key)) {
                    root = value;
                    overridden = true;
                } else if ("tamper".equals(key)) {
                    tamper = value;
                    overridden = true;
                } else if ("emu".equals(key)) {
                    emu = value;
                    overridden = true;
                } else if ("target".equals(key)) {
                    target = value;
                    overridden = true;
                } else if ("label".equals(key)) {
                    label = value;
                    overridden = true;
                }
            }
        }

        instance = new RaspilotConfig(
                hook, root, tamper, emu, target, label, overridden,
                RaspilotBaked.HOOK_TARGETS);
        return instance;
    }

    /**
     * Le uma propriedade do sistema tolerando falhas de SELinux.
     *
     * @param key Nome da propriedade.
     * @return Valor da propriedade ou null.
     */
    private static String readProperty(String key) {
        try {
            String value = System.getProperty(key);
            if (value != null && value.length() > 0) {
                return value;
            }
        } catch (Throwable ignored) {
        }
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            java.lang.reflect.Method get = clazz.getMethod("get", String.class);
            Object result = get.invoke(null, key);
            if (result instanceof String) {
                String value = (String) result;
                return value.length() > 0 ? value : null;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /**
     * Informa se a camada de anti-hook deve ser aplicada.
     *
     * @return True quando o modo nao e "off".
     */
    public boolean hookEnabled() {
        return !HOOK_OFF.equals(hookMode);
    }

    /**
     * Informa se a neutralizacao de anti-hook esta ativa.
     *
     * @return True no modo bypass.
     */
    public boolean hookBypass() {
        return HOOK_BYPASS.equals(hookMode);
    }

    /**
     * Informa se a camada de root deve ser aplicada.
     *
     * @return True quando o modo nao e "off".
     */
    public boolean rootEnabled() {
        return !ROOT_OFF.equals(rootMode);
    }

    /**
     * Informa se a neutralizacao de root esta ativa.
     *
     * @return True no modo bypass.
     */
    public boolean rootBypass() {
        return ROOT_BYPASS.equals(rootMode);
    }

    /**
     * Informa se a camada de anti-tampering deve ser aplicada.
     *
     * @return True quando o modo nao e "off".
     */
    public boolean tamperEnabled() {
        return !TAMPER_OFF.equals(tamperMode);
    }

    /**
     * Informa se a alteracao de assinatura esta ativa.
     *
     * @return True no modo bypass.
     */
    public boolean tamperBypass() {
        return TAMPER_BYPASS.equals(tamperMode);
    }

    /**
     * Informa se a camada de emulador deve ser aplicada.
     *
     * @return True quando o modo nao e "off".
     */
    public boolean emulatorEnabled() {
        return !EMU_OFF.equals(emulatorMode);
    }

    /**
     * Informa se o app alvo deve ser tratado como emulador.
     *
     * @return True no modo probe.
     */
    public boolean emulatorProbe() {
        return EMU_PROBE.equals(emulatorMode);
    }
}
