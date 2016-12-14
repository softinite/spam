package com.softinite.spam.encrdecr;

import java.io.*;

/**
 * Responsible for hiding internal implementation of file operations.
 * It is mainly used to facilitate the testability of the application and thus enhance resilience.
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class FileProxy {

    private File internal;

    protected File getInternal() {
        return internal;
    }

    public void setInternal(File internal) {
        this.internal = internal;
    }

    public Boolean exists() {
        return getInternal().exists()
                && getInternal().isFile();
    }

    public String getName() {
        return getInternal().getName();
    }

    public Boolean touch() throws IOException {
        return getInternal().createNewFile();
    }

    public void write(byte[] text) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(getInternal(), false)) {
            fos.write(text);
        }
    }

    public Boolean isEmpty() {
        return getInternal().length() == 0;
    }

    public PrintWriter loadWriter() throws FileNotFoundException {
        return new PrintWriter(getInternal());
    }
}
