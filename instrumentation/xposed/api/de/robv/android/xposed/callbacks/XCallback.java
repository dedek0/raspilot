package de.robv.android.xposed.callbacks;

import android.os.Bundle;

public abstract class XCallback {

    public static final int PRIORITY_DEFAULT = 50;
    public static final int PRIORITY_HIGHEST = 10000;
    public static final int PRIORITY_LOWEST = -10000;

    protected int priority = PRIORITY_DEFAULT;

    public XCallback() {
    }

    public XCallback(int priority) {
        this.priority = priority;
    }

    public static void callAll(XCallback.Param param) {
    }

    protected void call(XCallback.Param param) {
    }

    public static class Param {

        public final XCallback[] callbacks;

        public Param() {
            this.callbacks = null;
        }

        public Param(XCallback[] callbacks) {
            this.callbacks = callbacks;
        }

        public Bundle getExtra() {
            return null;
        }

        public Object getObjectExtra(String key) {
            return null;
        }

        public void setObjectExtra(String key, Object value) {
        }
    }
}
