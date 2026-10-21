package com.raspilot.module;

import java.io.OutputStream;

/**
 * Fluxo de saida que descarta tudo o que e escrito.
 */
public final class SilentOutputStream extends OutputStream {

    @Override
    public void write(int b) {
    }

    @Override
    public void write(byte[] buffer, int offset, int length) {
    }
}
