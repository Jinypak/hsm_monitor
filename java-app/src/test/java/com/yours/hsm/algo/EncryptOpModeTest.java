package com.yours.hsm.algo;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 일반화된 {@link EncryptOp} 의 모드별 라운드트립 검증.
 * SunJCE 로 실제 연산 — Luna 불필요.
 */
class EncryptOpModeTest {

    private static final Provider SUNJCE = Security.getProvider("SunJCE");

    private static SecretKey aesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", SUNJCE);
        kg.init(256);
        return kg.generateKey();
    }

    private void roundtrip(String id) throws Exception {
        AlgoSpec spec = AlgoCatalog.findById(id).orElseThrow();
        SecretKey key = aesKey();
        byte[] plain  = "일반화된 EncryptOp 모드 라운드트립 검증 — PASS".getBytes(StandardCharsets.UTF_8);

        OpResult enc = new EncryptOp(SUNJCE, spec, key, Cipher.ENCRYPT_MODE, null).execute(plain);
        assertTrue(enc.ok(), id + " 암호화 성공");
        byte[] ct = enc.output().orElseThrow();
        // IV 가 앞에 붙으므로 평문보다 길어야 함
        assertTrue(ct.length > plain.length, id + " 출력에 IV 가 prepend 되어야 함");

        OpResult dec = new EncryptOp(SUNJCE, spec, key, Cipher.DECRYPT_MODE, null).execute(ct);
        assertTrue(dec.ok(), id + " 복호화 성공");
        assertArrayEquals(plain, dec.output().orElseThrow(), id + " 라운드트립 일치");
    }

    @Test void aesCtr_roundtrip()    throws Exception { roundtrip("AES_CTR"); }
    @Test void aesCfb128_roundtrip() throws Exception { roundtrip("AES_CFB128"); }
    @Test void aesOfb_roundtrip()    throws Exception { roundtrip("AES_OFB"); }
    @Test void aesCbcPkcs5_roundtrip() throws Exception { roundtrip("AES_CBC_PKCS5"); }
    @Test void aesGcm_roundtrip()    throws Exception { roundtrip("AES_GCM"); }

    @Test
    void aesEcb_noIvPrepended() throws Exception {
        AlgoSpec spec = AlgoCatalog.findById("AES_ECB").orElseThrow();
        SecretKey key = aesKey();
        byte[] plain  = new byte[32]; // 블록 정렬된 평문 (NoPadding)

        OpResult enc = new EncryptOp(SUNJCE, spec, key, Cipher.ENCRYPT_MODE, null).execute(plain);
        assertTrue(enc.ok());
        // ECB 는 IV 가 없으므로 길이가 평문과 동일
        assertArrayEquals(new byte[0],
            java.util.Arrays.copyOfRange(enc.output().orElseThrow(), 32, enc.output().orElseThrow().length));
        assertFalse(enc.output().orElseThrow().length > plain.length, "ECB 는 IV prepend 없음");
    }
}
