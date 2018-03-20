package com.app.learning;

public class EncryptionException extends Exception {

    public EncryptionException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public EncryptionException(final Throwable throwable) {
        super(throwable);
    }
}
