package com.yours.hsm.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yours.hsm.algo.CryptoOpException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class KeyUnwrapperTest {

    private static final Provider SUNJCE = Security.getProvider("SunJCE");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void metaPathFor_replacesExtension() {
        Path p = Path.of("C:", "x", "20260530_143205_wrapping_key.key");
        assertEquals("20260530_143205_wrapping_key.meta.json",
            KeyUnwrapper.metaPathFor(p).getFileName().toString());
    }

    @Test
    void unwrapRaw_recoversAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey unwrapKey = kg.generateKey();
        SecretKey target    = kg.generateKey();

        byte[] wrapped = KeyWrapper.wrapRaw(SUNJCE, unwrapKey, target);
        WrapMetadata meta = new WrapMetadata("AES", "SECRET_KEY", "src", 256, "wk", "AES_KWP", "now");

        Key recovered = KeyUnwrapper.unwrapRaw(SUNJCE, unwrapKey, wrapped, meta);
        assertArrayEquals(target.getEncoded(), recovered.getEncoded());
    }

    @Test
    void unwrapRaw_recoversMlDsaPrivateKey() throws Exception {
        // ML-DSA 래핑/언래핑 라운드트립 — 실제 PQC 키로 검증
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey unwrapKey = kg.generateKey();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        var pair = kpg.generateKeyPair();

        byte[] wrapped = KeyWrapper.wrapRaw(SUNJCE, unwrapKey, pair.getPrivate());
        WrapMetadata meta = new WrapMetadata("ML-DSA", "PRIVATE_KEY", "mldsa", 0, "wk", "AES_KWP", "now");

        Key recovered = KeyUnwrapper.unwrapRaw(SUNJCE, unwrapKey, wrapped, meta);
        assertArrayEquals(pair.getPrivate().getEncoded(), recovered.getEncoded());

        // 복원 키로 서명 → 원본 공개키로 검증
        byte[] msg = "pqc roundtrip".getBytes();
        var s = java.security.Signature.getInstance("ML-DSA");
        s.initSign((java.security.PrivateKey) recovered);
        s.update(msg);
        byte[] sig = s.sign();
        var v = java.security.Signature.getInstance("ML-DSA");
        v.initVerify(pair.getPublic());
        v.update(msg);
        assertTrue(v.verify(sig));
    }

    @Test
    void readMetadata_roundtripsJson(@TempDir Path tmp) throws Exception {
        WrapMetadata meta = new WrapMetadata("ML-DSA", "PRIVATE_KEY", "src", 0, "wk", "AES_KWP", "2026-05-30T14:32:05Z");
        Path keyFile  = tmp.resolve("20260530_143205_wrapping_key.key");
        Path metaFile = KeyUnwrapper.metaPathFor(keyFile);
        Files.write(keyFile, new byte[]{1, 2, 3});
        MAPPER.writeValue(metaFile.toFile(), meta);

        KeyUnwrapper unwrapper = new KeyUnwrapper(SUNJCE, null, null);
        WrapMetadata read = unwrapper.readMetadata(keyFile);
        assertEquals("ML-DSA", read.algorithm());
        assertEquals("PRIVATE_KEY", read.keyType());
        assertEquals("src", read.sourceAlias());
    }

    @Test
    void readMetadata_missingFileThrows(@TempDir Path tmp) throws Exception {
        Path keyFile = tmp.resolve("orphan_wrapping_key.key");
        Files.write(keyFile, new byte[]{1});
        KeyUnwrapper unwrapper = new KeyUnwrapper(SUNJCE, null, null);
        CryptoOpException e = assertThrows(CryptoOpException.class, () -> unwrapper.readMetadata(keyFile));
        assertTrue(e.getMessage().contains("메타데이터"));
    }
}
