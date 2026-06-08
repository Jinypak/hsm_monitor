package com.yours.hsm.algo;

public class CryptoOpException extends Exception {

    public enum Code {
        PIN_INCORRECT, KEY_NOT_FOUND, MECH_NOT_SUPPORTED,
        SLOT_LOCKED, SESSION_CLOSED, GENERAL
    }

    private final Code code;

    public CryptoOpException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public CryptoOpException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() { return code; }
}
