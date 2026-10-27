package com.raspilot.module;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * Camada de anti-tampering.
 *
 * No modo observe, apenas registra quando o app consulta a assinatura do
 * proprio pacote. No modo bypass, devolve uma assinatura diferente e faz
 * {@code checkSignatures} falhar, sem reinstalar o APK. O app que checa a
 * integridade e reage a essa divergencia derruba o processo; o app que
 * continua vivo e utilizavel nao bloqueia a alteracao.
 */
public final class TamperShield {

    /** Assinatura sintetica; o conteudo so precisa ser estavel e diferente. */
    private static final byte[] FAKE_SIGNATURE = {
            0x52, 0x41, 0x53, 0x50, 0x69, 0x6c, 0x6f, 0x74,
    };

    /** Codigo de SIGNATURE_MISMATCH do PackageManager. */
    private static final int SIGNATURE_MISMATCH = -3;

    private TamperShield() {
    }

    /**
     * Instala os hooks da camada de integridade.
     *
     * @param config Configuracao efetiva do modulo.
     * @param classLoader Class loader do processo alvo.
     */
    public static void install(RaspilotConfig config, ClassLoader classLoader) {
        final boolean bypass = config.tamperBypass();
        final String target = config.targetPackage;
        hookGetPackageInfo(bypass, target);
        hookCheckSignatures(bypass, target);
    }

    private static boolean isTarget(String pkg, String target) {
        if (pkg == null) {
            return false;
        }
        if (target == null || target.length() == 0) {
            return true;
        }
        return target.equals(pkg);
    }

    private static Signature fakeSignature() {
        try {
            return new Signature(FAKE_SIGNATURE);
        } catch (Throwable error) {
            Evidence.error("tamper.Signature", error);
            return null;
        }
    }

    private static void replaceSignatures(PackageInfo info, String pkg,
                                          boolean bypass, String target) {
        if (!isTarget(pkg, target)) {
            return;
        }
        Evidence.emit(bypass ? "neutralize" : "observe", "tamper",
                "getPackageInfo", pkg);
        if (!bypass) {
            return;
        }
        Signature fake = fakeSignature();
        if (fake == null) {
            return;
        }
        try {
            info.signatures = new Signature[]{fake};
        } catch (Throwable error) {
            Evidence.error("tamper.PackageInfo.signatures", error);
        }
    }

    private static void hookGetPackageInfo(final boolean bypass, final String target) {
        Class<?> clazz;
        try {
            clazz = Class.forName("android.app.ApplicationPackageManager");
        } catch (Throwable ignored) {
            clazz = PackageManager.class;
        }
        XC_MethodHook callback = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (!(result instanceof PackageInfo)) {
                    return;
                }
                String pkg = param.args.length > 0
                        ? String.valueOf(param.args[0]) : null;
                replaceSignatures((PackageInfo) result, pkg, bypass, target);
            }
        };
        // Overloads mais usados; a lista cobre as assinaturas estaveis
        // entre API 21 e API 34.
        try {
            XposedHelpers.findAndHookMethod(clazz, "getPackageInfo",
                    String.class, int.class, callback);
        } catch (Throwable error) {
            Evidence.error("tamper.getPackageInfo", error);
        }
        try {
            XposedHelpers.findAndHookMethod(clazz, "getPackageInfo",
                    String.class, int.class, int.class, callback);
        } catch (Throwable error) {
            Evidence.error("tamper.getPackageInfo", error);
        }
    }

    private static void hookCheckSignatures(final boolean bypass,
                                            final String target) {
        Class<?> clazz;
        try {
            clazz = Class.forName("android.app.ApplicationPackageManager");
        } catch (Throwable ignored) {
            clazz = PackageManager.class;
        }
        try {
            XposedHelpers.findAndHookMethod(clazz, "checkSignatures",
                    String.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (!bypass) {
                                return;
                            }
                            String pkg1 = param.args.length > 0
                                    ? String.valueOf(param.args[0]) : null;
                            String pkg2 = param.args.length > 1
                                    ? String.valueOf(param.args[1]) : null;
                            if (!isTarget(pkg1, target) && !isTarget(pkg2, target)) {
                                return;
                            }
                            Evidence.emit("neutralize", "tamper",
                                    "checkSignatures", pkg1 + " / " + pkg2);
                            param.setResult(SIGNATURE_MISMATCH);
                        }
                    });
        } catch (Throwable error) {
            Evidence.error("tamper.checkSignatures", error);
        }
    }
}
