package de.robv.android.xposed;

import java.lang.reflect.Member;
import java.util.Set;

public final class XposedBridge {

    public static final ClassLoader BOOTCLASSLOADER = null;
    public static final String TAG = "Xposed";

    private XposedBridge() {
    }

    public static void log(String text) {
    }

    public static void log(Throwable t) {
    }

    public static int getXposedVersion() {
        return 0;
    }

    public static XC_MethodHook.Unhook hookMethod(Member hookMethod, XC_MethodHook callback) {
        return null;
    }

    public static void unhookMethod(Member hookMethod, XC_MethodHook callback) {
    }

    public static Object invokeOriginalMethod(
            Member method, Object thisObject, Object[] args) {
        return null;
    }

    public static void hookLoadPackage(de.robv.android.xposed.callbacks.XC_LoadPackage callback) {
    }

    public static Set<Object> hookAllMethods(
            Class<?> hookClass, String methodName, XC_MethodHook callback) {
        return null;
    }

    public static Set<Object> hookAllConstructors(
            Class<?> hookClass, XC_MethodHook callback) {
        return null;
    }
}
