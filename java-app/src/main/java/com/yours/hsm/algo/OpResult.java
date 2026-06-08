package com.yours.hsm.algo;

import java.util.Optional;

public record OpResult(
    boolean          ok,
    long             durationNs,
    Optional<byte[]> output,
    Optional<byte[]> verifyHash,
    Optional<String> errorCode,
    Optional<String> errorMsg
) {
    public double durationMs() { return durationNs / 1_000_000.0; }

    public static OpResult success(long durationNs, byte[] output) {
        return new OpResult(true, durationNs,
            Optional.of(output), Optional.empty(),
            Optional.empty(), Optional.empty());
    }

    public static OpResult successWithHash(long durationNs, byte[] output, byte[] hash) {
        return new OpResult(true, durationNs,
            Optional.of(output), Optional.of(hash),
            Optional.empty(), Optional.empty());
    }

    public static OpResult failure(long durationNs, String errorCode, String errorMsg) {
        return new OpResult(false, durationNs,
            Optional.empty(), Optional.empty(),
            Optional.of(errorCode), Optional.of(errorMsg));
    }
}
