package com.raspilot.module;

import android.util.Log;

/**
 * Emissor de evidencia do modulo.
 *
 * Cada evento e escrito no logcat com um formato estavel, allowing que a
 * ferramenta leia a evidencia sem depender do framework de hooking:
 *
 *     RASPilotModule: EVT|<tipo>|<canal>|<metodo>|<detalhe>
 */
public final class Evidence {

    public static final String TAG = "RASPilotModule";

    /** Prefixo das linhas de evidencia no logcat. */
    public static final String PREFIX = "EVT|";

    private Evidence() {
    }

    /**
     * Registra um evento de evidencia.
     *
     * @param kind Tipo do evento (observe, neutralize, ready, error).
     * @param channel Canal consultado (hook, emulator, build...).
     * @param method Metodo ou API interceptada.
     * @param detail Detalhe textual do evento.
     */
    public static void emit(String kind, String channel, String method, String detail) {
        try {
            String line = PREFIX + safe(kind) + "|" + safe(channel) + "|"
                    + safe(method) + "|" + safe(detail);
            Log.i(TAG, line);
        } catch (Throwable ignored) {
            // A evidencia nunca pode derrubar o processo do app.
        }
    }

    /**
     * Registra um erro interno do modulo.
     *
     * @param stage Etapa que falhou.
     * @param error Erro observado.
     */
    public static void error(String stage, Object error) {
        try {
            Log.w(TAG, PREFIX + "error|" + safe(stage) + "|-|"
                    + safe(error == null ? "null" : error.toString()));
        } catch (Throwable ignored) {
        }
    }

    private static String safe(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('|', '/').replace('\n', ' ').trim();
    }
}
