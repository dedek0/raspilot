package de.robv.android.xposed.callbacks;

import android.content.pm.ApplicationInfo;

public class XC_LoadPackage extends XCallback {

    public static class LoadPackageParam extends XCallback.Param {

        public String packageName;
        public String processName;
        public ApplicationInfo appInfo;
        public boolean isFirstApplication;
        public ClassLoader classLoader;

        public LoadPackageParam() {
            super();
        }
    }
}
