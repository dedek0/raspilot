package de.robv.android.xposed;

import java.lang.reflect.Member;

/**
 * Assinatura minima da API de hooking usada pelo modulo.
 *
 * As classes deste pacote existem apenas em tempo de compilacao: em
 * tempo de execucao elas sao fornecidas pelo framework de hooking do
 * dispositivo. Nao devem ser empacotadas no APK do modulo.
 */
public class XC_MethodHook {

    public XC_MethodHook() {
    }

    public XC_MethodHook(int priority) {
    }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
    }

    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    }
    public static class MethodHookParam {

        public Object thisObject;
        public Object[] args;
        public Member method;
        public Object result;
        public Throwable throwable;
        public boolean returnEarly;

        public MethodHookParam() {
        }

        public Object getResult() {
            return null;
        }

        public Object getResultOrThrowable() {
            return null;
        }

        public Throwable getThrowable() {
            return null;
        }

        public boolean hasThrowable() {
            return false;
        }

        public void setResult(Object result) {
        }

        public void setThrowable(Throwable throwable) {
        }
    }

    public static class Unhook {

        public Unhook(XC_MethodHook callback, Member hookMethod) {
        }

        public XC_MethodHook getCallback() {
            return null;
        }

        public Member getHookedMethod() {
            return null;
        }

        public void unhook() {
        }
    }
}
