package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.mock.MockProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.Provider;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class KeyManagerTest {

    /** HSM 없이 토큰 동작을 흉내내는 인메모리 fake. */
    static final class FakeAccess implements TokenKeyAccess {
        final Map<String, Map<KeyAttribute, Boolean>> store = new HashMap<>();
        final Set<String> persisted = new HashSet<>();

        @Override public void makePersistent(Key key, String alias) {
            persisted.add(alias);
            store.computeIfAbsent(alias, a -> defaults());
        }
        @Override public boolean exists(String alias) { return store.containsKey(alias); }
        @Override public void relabel(String oldAlias, String newAlias) {
            store.put(newAlias, store.remove(oldAlias));
        }
        @Override public Map<KeyAttribute, Boolean> readAttributes(String alias) {
            return new EnumMap<>(store.get(alias));
        }
        @Override public void setAttribute(String alias, KeyAttribute attr, boolean value) {
            store.get(alias).put(attr, value);
        }
        @Override public void destroy(String alias) { store.remove(alias); }

        void seed(String alias) { store.put(alias, defaults()); }
        private static Map<KeyAttribute, Boolean> defaults() {
            Map<KeyAttribute, Boolean> m = new EnumMap<>(KeyAttribute.class);
            for (KeyAttribute a : KeyAttribute.values()) m.put(a, false);
            return m;
        }
    }

    private Provider   provider;
    private FakeAccess access;
    private KeyManager mgr;

    @BeforeEach
    void setUp() {
        provider = new MockProvider();
        access   = new FakeAccess();
        mgr      = new KeyManager(provider, access);
    }

    @Test
    void generateAes_persistsWithAlias() throws CryptoOpException {
        SecretKey key = mgr.generateAes("aes-demo", 256);
        assertNotNull(key);
        assertTrue(access.exists("aes-demo"));
        assertTrue(access.persisted.contains("aes-demo"));
    }

    @Test
    void generateAes_rejectsBadBits() {
        CryptoOpException e = assertThrows(CryptoOpException.class,
            () -> mgr.generateAes("x", 200));
        assertTrue(e.getMessage().contains("AES 키 길이"));
    }

    @Test
    void generateAes_rejectsBlankAlias() {
        assertThrows(CryptoOpException.class, () -> mgr.generateAes("   ", 128));
    }

    @Test
    void generateAes_rejectsDuplicateAlias() {
        access.seed("dup");
        assertThrows(CryptoOpException.class, () -> mgr.generateAes("dup", 128));
    }

    @Test
    void generateRsa_persistsKeyPair() throws CryptoOpException {
        KeyPair pair = mgr.generateRsa("rsa-demo", 2048);
        assertNotNull(pair.getPrivate());
        assertNotNull(pair.getPublic());
        assertTrue(access.exists("rsa-demo"));
    }

    @Test
    void generateRsa_rejectsBadBits() {
        assertThrows(CryptoOpException.class, () -> mgr.generateRsa("x", 1024));
    }

    @Test
    void generateEc_persistsKeyPair() throws CryptoOpException {
        KeyPair pair = mgr.generateEc("ec-demo", "secp256r1");
        assertNotNull(pair.getPrivate());
        assertNotNull(pair.getPublic());
        assertTrue(access.exists("ec-demo"));
        assertTrue(access.exists("ec-demo" + KeyManager.PUBLIC_SUFFIX));
    }

    @Test
    void generateSecret_desede_persists() throws CryptoOpException {
        SecretKey key = mgr.generateSecret("DESede", "des3-demo", 168);
        assertNotNull(key);
        assertTrue(access.exists("des3-demo"));
    }

    @Test
    void generateSecret_unknownAlgo_throwsMechNotSupported() {
        // MockProvider 에 ARIA 미등록 → MECH_NOT_SUPPORTED
        CryptoOpException e = assertThrows(CryptoOpException.class,
            () -> mgr.generateSecret("ARIA", "aria-demo", 256));
        assertEquals(CryptoOpException.Code.MECH_NOT_SUPPORTED, e.code());
    }

    @Test
    void relabel_movesAttributes() throws CryptoOpException {
        access.seed("old");
        access.store.get("old").put(KeyAttribute.SIGN, true);

        mgr.relabel("old", "new");

        assertFalse(access.exists("old"));
        assertTrue(access.exists("new"));
        assertTrue(mgr.attributes("new").get(KeyAttribute.SIGN));
    }

    @Test
    void relabel_rejectsDuplicateTarget() {
        access.seed("a");
        access.seed("b");
        assertThrows(CryptoOpException.class, () -> mgr.relabel("a", "b"));
    }

    @Test
    void relabel_rejectsMissingSource() {
        assertThrows(CryptoOpException.class, () -> mgr.relabel("ghost", "new"));
    }

    @Test
    void relabel_rejectsSameName() {
        access.seed("same");
        assertThrows(CryptoOpException.class, () -> mgr.relabel("same", "same"));
    }

    @Test
    void setAttribute_updatesValue() throws CryptoOpException {
        access.seed("k");
        mgr.setAttribute("k", KeyAttribute.EXTRACTABLE, true);
        assertTrue(mgr.attributes("k").get(KeyAttribute.EXTRACTABLE));
    }

    @Test
    void setAttribute_rejectsMissingKey() {
        assertThrows(CryptoOpException.class,
            () -> mgr.setAttribute("ghost", KeyAttribute.SIGN, true));
    }

    @Test
    void delete_removesKey() throws CryptoOpException {
        access.seed("victim");
        mgr.delete("victim");
        assertFalse(access.exists("victim"));
    }

    @Test
    void delete_rejectsMissingKey() {
        assertThrows(CryptoOpException.class, () -> mgr.delete("ghost"));
    }
}
