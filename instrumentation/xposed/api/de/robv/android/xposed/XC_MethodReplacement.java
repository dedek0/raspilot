package de.robv.android.xposed;

public class XC_MethodReplacement extends XC_MethodHook {

    public static final XC_MethodReplacement DO_NOTHING = null;

    public XC_MethodReplacement() {
    }

    public XC_MethodReplacement(int priority) {
    }

    public static XC_MethodReplacement returnConstant(int priority, Object value) {
        return null;
    }

    public static XC_MethodReplacement returnConstant(Object value) {
        return null;
    }

    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
        return null;
    }
}
