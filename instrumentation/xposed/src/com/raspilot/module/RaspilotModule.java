package com.raspilot.module;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Ponto de entrada do modulo.
 *
 * O modulo e carregado pelo framework de hooking do dispositivo dentro do
 * processo do app alvo e aplica as camadas configuradas para o pacote.
 */
public class RaspilotModule implements IXposedHookLoadPackage, IXposedHookZygoteInit {

    @Override
    public void initZygote(StartupParam startupParam) {
        // Nada a fazer no zygote: as camadas sao instaladas por processo.
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            RaspilotConfig config = RaspilotConfig.resolve();
            String pkg = lpparam.packageName;
            String target = config.targetPackage;
            if (target != null && target.length() > 0 && !target.equals(pkg)) {
                return;
            }
            if (!config.hookEnabled() && !config.rootEnabled()
                    && !config.tamperEnabled() && !config.emulatorEnabled()
                    && !config.proxyEnabled()) {
                Evidence.emit("ready", "module", "handleLoadPackage",
                        "nenhuma camada ativa para " + pkg);
                return;
            }
            ClassLoader classLoader = lpparam.classLoader;
            if (classLoader == null) {
                classLoader = de.robv.android.xposed.XposedBridge.BOOTCLASSLOADER;
            }
            if (config.hookEnabled()) {
                HookShield.install(config, classLoader);
            }
            if (config.rootEnabled()) {
                RootShield.install(config, classLoader);
            }
            if (config.tamperEnabled()) {
                TamperShield.install(config, classLoader);
            }
            if (config.emulatorEnabled()) {
                EmulatorShield.install(config);
            }
            if (config.proxyEnabled()) {
                ProxyShield.install(config, classLoader);
            }
            Evidence.emit("ready", "module", "handleLoadPackage",
                    "pkg=" + pkg + " hook=" + config.hookMode
                            + " root=" + config.rootMode
                            + " tamper=" + config.tamperMode
                            + " emu=" + config.emulatorMode
                            + " proxy=" + config.proxyMode
                            + " label=" + config.label);
        } catch (Throwable error) {
            Evidence.error("handleLoadPackage", error);
        }
    }
}
