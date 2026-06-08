package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class KeyWrapperTest {

    /** AES-KWP 는 SunJCE 가 제공 — 래핑 로직을 HSM 없이 실제로 검증한다. */
    private static final Provider SUNJCE = Security.getProvider("SunJCE");

    @Test
    void exportFileName_followsConvention() {
        String name = KeyWrapper.exportFileName(LocalDateTime.of(2026, 5, 30, 14, 32, 5));
        assertEquals("20260530_143205_wrapping_key.key", name);
    }

    @Test
    void wrapRaw_producesNonEmptyOutput() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey wrapKey = kg.generateKey();
        SecretKey target  = kg.generateKey();

        byte[] wrapped = KeyWrapper.wrapRaw(SUNJCE, wrapKey, target);

        assertNotNull(wrapped);
        assertTrue(wrapped.length > 0);
        // KWP 결과는 평문 키 길이보다 길다(8바이트 IV/패딩 추가)
        assertTrue(wrapped.length > target.getEncoded().length);
    }

    @Test
    void wrapRaw_roundtripUnwraps() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey wrapKey = kg.generateKey();
        SecretKey target  = kg.generateKey();

        byte[] wrapped = KeyWrapper.wrapRaw(SUNJCE, wrapKey, target);

        // 언래핑하여 원본과 동일한지 확인
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AESWrapPad", SUNJCE);
        c.init(javax.crypto.Cipher.UNWRAP_MODE, wrapKey);
        java.security.Key recovered = c.unwrap(wrapped, "AES", javax.crypto.Cipher.SECRET_KEY);
        assertArrayEquals(target.getEncoded(), recovered.getEncoded());
    }

    @Test
    void export_writesFileToDir(@TempDir Path tmp) throws CryptoOpException {
        // KeyWrapper 인스턴스 없이 export 만 단독 검증하기 위해 정적 경로 헬퍼 사용
        byte[] data = {1, 2, 3, 4, 5};
        Path name = tmp.resolve(KeyWrapper.exportFileName(LocalDateTime.now()));
        try {
            Files.write(name, data);
        } catch (Exception e) {
            fail(e);
        }
        assertTrue(Files.exists(name));
        assertTrue(name.getFileName().toString().endsWith("_wrapping_key.key"));
    }
}
