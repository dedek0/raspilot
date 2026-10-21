package com.raspilot.module;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Processo sem efeito, usado para neutralizar execucoes que o app
 * dispara para sondar frameworks de hooking.
 */
public final class SilentProcess extends Process {

    private final ByteArrayInputStream empty =
            new ByteArrayInputStream(new byte[0]);

    @Override
    public OutputStream getOutputStream() {
        return new SilentOutputStream();
    }

    @Override
    public InputStream getInputStream() {
        return empty;
    }

    @Override
    public InputStream getErrorStream() {
        return empty;
    }

    @Override
    public int waitFor() {
        return 0;
    }

    @Override
    public int exitValue() {
        return 0;
    }

    @Override
    public void destroy() {
    }
}
