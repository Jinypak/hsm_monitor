package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 소프트웨어(JDK) Provider 로 PQC 라운드트립 검증 — HSM 불필요.
 * JDK 25(ML-DSA JEP 497 / ML-KEM JEP 496)에서 실제 동작.
 * 런타임에 알고리즘이 없으면(구버전 JDK) 해당 테스트는 스킵.
 */
class PqcServiceTest {

    private static boolean available(String algo) {
        try { KeyPairGenerator.getInstance(algo); return true; }
        catch (Exception e) { return false; }
    }

    private final PqcService pqc = new PqcService(null); // JCA 기본(소프트웨어)

    @Test
    void mlDsa_signVerify_roundtrip() throws CryptoOpException {
        Assumptions.assumeTrue(available("ML-DSA-65"), "ML-DSA 미지원 JDK — 스킵");
        KeyPair kp = pqc.generateKeyPair("ML-DSA-65");
        assertEquals("ML-DSA", kp.getPublic().getAlgorithm());

        byte[] msg = "PQC 서명 테스트".getBytes(StandardCharsets.UTF_8);
        PqcService.SignResult r = pqc.signVerify(kp, msg);

        assertTrue(r.verified(), "ML-DSA 서명이 검증되어야 함");
        assertTrue(r.signature().length > 0);
    }

    @Test
    void mlKem_encapsulateDecapsulate_sharedSecretsMatch() throws CryptoOpException {
        Assumptions.assumeTrue(available("ML-KEM-768"), "ML-KEM 미지원 JDK — 스킵");
        KeyPair kp = pqc.generateKeyPair("ML-KEM-768");
        assertEquals("ML-KEM", kp.getPublic().getAlgorithm());

        PqcService.KemResult r = pqc.kemRoundtrip(kp);

        assertTrue(r.match(), "캡슐화/디캡슐화 공유비밀(지문)이 일치해야 함");
        assertArrayEquals(r.fingerprintA(), r.fingerprintB());
        assertTrue(r.encapsulation().length > 0);
    }

    @Test
    void generateKeyPair_unknownAlgo_throwsMechNotSupported() {
        CryptoOpException e = assertThrows(CryptoOpException.class,
            () -> pqc.generateKeyPair("ML-DSA-999"));
        assertEquals(CryptoOpException.Code.MECH_NOT_SUPPORTED, e.code());
    }
}
