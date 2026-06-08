package com.yours.hsm.algo;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DigestOpTest {

    private static final Provider SUN = Security.getProvider("SUN");

    @Test
    void sha256_matchesReferenceDigest() throws Exception {
        AlgoSpec spec = AlgoCatalog.findById("SHA256").orElseThrow();
        byte[] input  = "hello hsm".getBytes(StandardCharsets.UTF_8);

        OpResult r = new DigestOp(SUN, spec).execute(input);

        assertTrue(r.ok());
        byte[] expected = MessageDigest.getInstance("SHA-256", SUN).digest(input);
        assertArrayEquals(expected, r.output().orElseThrow());
    }

    @Test
    void sha512_producesCorrectLength() throws Exception {
        AlgoSpec spec = AlgoCatalog.findById("SHA512").orElseThrow();
        OpResult r = new DigestOp(SUN, spec).execute(new byte[] {1, 2, 3});
        assertTrue(r.ok());
        assertArrayEquals(
            MessageDigest.getInstance("SHA-512", SUN).digest(new byte[] {1, 2, 3}),
            r.output().orElseThrow());
    }
}
