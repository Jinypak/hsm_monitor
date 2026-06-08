package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.core.KeyCatalog.KeyEntry;
import com.yours.hsm.core.KeyCatalog.KeyKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ML-DSA(PQC) 개인키를 AES(KEK)로 래핑→파일 내보내기→동일 AES로 언래핑→토큰 저장까지의
 * 전체 키 이전(transfer) 라운드트립을 HSM 없이 검증한다.
 * <p>
 * {@link com.yours.hsm.tools.KeyTransferHarness}(실제 HSM 2슬롯 필요)와 동일한 경로
 * ({@link KeyWrapper#export}, {@link KeyUnwrapper#unwrapAndStore})를 그대로 타되,
 * Luna 의존 부분({@link LunaSession}/{@link KeyCatalog})만 mock 으로 격리하고
 * 실제 래핑/언래핑은 SunJCE(AES-KWP) + SUN(ML-DSA)으로 수행한다.
 */
class MlDsaAesTransferTest {

    /** AES-KWP 는 SunJCE 가, ML-DSA 는 SUN provider 가 제공 — HSM 없이 실제 연산 검증. */
    private static final Provider SUNJCE = Security.getProvider("SunJCE");

    @Test
    void mlDsaWrappedWithAes_exportThenImport_roundtrips(@TempDir Path dir) throws Exception {
        // ── given: AES-256 KEK + ML-DSA-65 키쌍 ──────────────────────────
        SecretKey kek = aes256();
        KeyPair pair = KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();

        KeyEntry kekEntry = new KeyEntry("aes_kek", KeyKind.SECRET, "AES", 256);
        KeyEntry srcEntry = new KeyEntry("transfer_mldsa_src", KeyKind.KEYPAIR, "ML-DSA", 0);

        // ── slot0 측: AES 로 래핑 후 파일로 내보내기 (실제 KeyWrapper 경로) ──
        KeyWrapper wrapper = new KeyWrapper(sessionWithProvider());
        byte[] wrapped = KeyWrapper.wrapRaw(SUNJCE, kek, pair.getPrivate());
        WrapMetadata meta = wrapper.metadataFor(kekEntry, srcEntry);
        Path keyFile = wrapper.export(wrapped, meta, dir);

        assertTrue(Files.exists(keyFile), ".key 파일이 생성되어야 한다");
        assertTrue(Files.exists(KeyUnwrapper.metaPathFor(keyFile)), ".meta.json 이 동반되어야 한다");
        assertEquals("ML-DSA", meta.algorithm());
        assertEquals("PRIVATE_KEY", meta.keyType());
        assertEquals("aes_kek", meta.wrapAlias());

        // ── slot1 측: 동일한 AES 로 언래핑 후 토큰 저장 (실제 KeyUnwrapper 경로) ──
        KeyCatalog cat = mock(KeyCatalog.class);
        when(cat.asSecretKey(kekEntry)).thenReturn(Optional.of(kek));
        RecordingAccess access = new RecordingAccess();
        KeyUnwrapper unwrapper = new KeyUnwrapper(SUNJCE, cat, access);

        Key recovered = unwrapper.unwrapAndStore(kekEntry, keyFile, "transfer_mldsa_dst");

        // 토큰에 새 라벨로 저장되었는지 확인
        assertSame(recovered, access.stored.get("transfer_mldsa_dst"),
            "복원된 키가 새 라벨로 영구 저장되어야 한다");
        assertEquals("ML-DSA", recovered.getAlgorithm());

        // 복원 개인키로 서명 → 원본 공개키로 검증되면 동일 키임이 증명된다
        byte[] msg = "mldsa wrap transfer".getBytes();
        Signature sign = Signature.getInstance("ML-DSA");
        sign.initSign((PrivateKey) recovered);
        sign.update(msg);
        byte[] sig = sign.sign();

        Signature verify = Signature.getInstance("ML-DSA");
        verify.initVerify(pair.getPublic());
        verify.update(msg);
        assertTrue(verify.verify(sig), "복원 키로 만든 서명이 원본 공개키로 검증되어야 한다");
    }

    @Test
    void unwrapWithDifferentAesKey_fails(@TempDir Path dir) throws Exception {
        SecretKey kek      = aes256();
        SecretKey wrongKek = aes256();
        KeyPair pair = KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();

        KeyEntry kekEntry = new KeyEntry("aes_kek", KeyKind.SECRET, "AES", 256);
        KeyEntry srcEntry = new KeyEntry("transfer_mldsa_src", KeyKind.KEYPAIR, "ML-DSA", 0);

        KeyWrapper wrapper = new KeyWrapper(sessionWithProvider());
        byte[] wrapped = KeyWrapper.wrapRaw(SUNJCE, kek, pair.getPrivate());
        Path keyFile = wrapper.export(wrapped, wrapper.metadataFor(kekEntry, srcEntry), dir);

        // 다른 AES 키로 언래핑 시도 — KWP 무결성 검사 실패로 예외가 나야 한다
        KeyCatalog cat = mock(KeyCatalog.class);
        when(cat.asSecretKey(kekEntry)).thenReturn(Optional.of(wrongKek));
        KeyUnwrapper unwrapper = new KeyUnwrapper(SUNJCE, cat, new RecordingAccess());

        CryptoOpException e = assertThrows(CryptoOpException.class,
            () -> unwrapper.unwrapAndStore(kekEntry, keyFile, "transfer_mldsa_dst"));
        assertTrue(e.getMessage().contains("언래핑"), "언래핑 실패 메시지를 담아야 한다");
    }

    private static SecretKey aes256() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    /** KeyWrapper 생성에 필요한 LunaSession 을 mock 으로 만들고 provider 만 SunJCE 로 노출. */
    private static LunaSession sessionWithProvider() {
        LunaSession s = mock(LunaSession.class);
        when(s.provider()).thenReturn(SUNJCE);
        return s;
    }

    /** makePersistent/exists 만 인메모리로 기록하는 TokenKeyAccess 테스트 더블. */
    private static final class RecordingAccess implements TokenKeyAccess {
        final Map<String, Key> stored = new HashMap<>();

        @Override public void makePersistent(Key key, String alias) { stored.put(alias, key); }
        @Override public boolean exists(String alias) { return stored.containsKey(alias); }
        @Override public void relabel(String oldAlias, String newAlias) { }
        @Override public Map<KeyAttribute, Boolean> readAttributes(String alias) { return Map.of(); }
        @Override public void setAttribute(String alias, KeyAttribute attr, boolean value) { }
        @Override public void destroy(String alias) { }
    }
}
