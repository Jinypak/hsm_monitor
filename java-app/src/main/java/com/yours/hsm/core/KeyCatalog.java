package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

public final class KeyCatalog {

    private static final Logger logger = LoggerFactory.getLogger(KeyCatalog.class);

    public enum KeyKind { PRIVATE, PUBLIC, SECRET, KEYPAIR }

    public record KeyEntry(
        String  alias,
        KeyKind kind,
        String  algorithm,
        int     keyBits
    ) {
        @Override public String toString() {
            return "%s [%s %s%s]".formatted(
                alias, kind, algorithm,
                keyBits > 0 ? "/" + keyBits : "");
        }
    }

    private final LunaSession session;

    public KeyCatalog(LunaSession session) {
        this.session = session;
    }

    public List<KeyEntry> list() throws CryptoOpException {
        try {
            KeyStore ks = session.keyStore();
            List<KeyEntry> result = new ArrayList<>();
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                result.add(entryFor(ks, alias));
            }
            logger.debug("키 목록 조회: {}개", result.size());
            return result;
        } catch (KeyStoreException e) {
            throw new CryptoOpException(Code.GENERAL, "키 목록 조회 실패: " + e.getMessage(), e);
        }
    }

    // CKA 상수 (PKCS#11) — 토큰 객체에서 정확한 크기/종류 조회용
    private static final long CKA_CLASS        = 0x00000000L;
    private static final long CKA_MODULUS      = 0x00000120L;
    private static final long CKA_MODULUS_BITS = 0x00000121L;
    private static final long CKA_VALUE_LEN    = 0x00000161L;
    private static final long CKO_SECRET_KEY   = 4L;

    public Optional<KeyEntry> findByAlias(String alias) throws CryptoOpException {
        return list().stream().filter(e -> e.alias().equals(alias)).findFirst();
    }

    public Optional<KeyPair> asKeyPair(KeyEntry entry) throws CryptoOpException {
        try {
            KeyStore ks = session.keyStore();
            PrivateKey priv = (PrivateKey) ks.getKey(entry.alias(), null);
            if (priv == null) return Optional.empty();
            Certificate cert = ks.getCertificate(entry.alias());
            PublicKey pub = cert != null ? cert.getPublicKey() : null;
            if (pub == null) {
                logger.warn("alias={} 인증서 없음 — 공개키 미사용 연산(서명·복호화)만 가능", entry.alias());
            }
            return Optional.of(new KeyPair(pub, priv));
        } catch (Exception e) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND,
                "키쌍 로드 실패: " + entry.alias(), e);
        }
    }

    /**
     * 선택한 키와 한 쌍을 이루는 <b>공개키를 자동으로</b> 찾는다.
     * <p>탐색 순서:
     * <ol>
     *   <li>선택 alias 자체의 공개키(인증서 또는 PUBLIC 키 객체)</li>
     *   <li>라벨 규칙으로 추정한 동반 공개키 별칭 — {@code -pub/_pub/.pub/-public} 등,
     *       {@code -priv} 접미사는 제거 후 매칭(base 명 복원)</li>
     *   <li>개인키에서 유도 — RSA 는 modulus/publicExponent 가 비밀이 아니므로 CRT 개인키로 재구성</li>
     * </ol>
     */
    public Optional<PublicKey> asPublicKey(KeyEntry entry) throws CryptoOpException {
        try {
            KeyStore ks = session.keyStore();
            // 1) 선택 alias 자체
            Optional<PublicKey> direct = publicFromAlias(ks, entry.alias());
            if (direct.isPresent()) return direct;
            // 2) 라벨 규칙으로 동반 공개키 별칭
            for (String cand : publicAliasCandidates(entry.alias())) {
                Optional<PublicKey> p = publicFromAlias(ks, cand);
                if (p.isPresent()) return p;
            }
            // 3) 개인키에서 유도 (RSA)
            Optional<PrivateKey> priv = asPrivateKey(entry);
            if (priv.isPresent()
                && priv.get() instanceof java.security.interfaces.RSAPrivateCrtKey crt
                && crt.getModulus() != null && crt.getPublicExponent() != null) {
                return Optional.of(java.security.KeyFactory.getInstance("RSA")
                    .generatePublic(new java.security.spec.RSAPublicKeySpec(
                        crt.getModulus(), crt.getPublicExponent())));
            }
            return Optional.empty();
        } catch (Exception e) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND,
                "공개키 로드 실패: " + entry.alias(), e);
        }
    }

    /**
     * 선택한 키와 한 쌍을 이루는 <b>개인키를 자동으로</b> 찾는다.
     * 선택 alias 가 개인키면 그대로, 아니면 라벨 규칙({@code -priv/_priv/.priv/-private},
     * {@code -pub} 제거 후 base 매칭)으로 동반 개인키 별칭을 탐색한다.
     */
    public Optional<PrivateKey> asPrivateKey(KeyEntry entry) throws CryptoOpException {
        try {
            KeyStore ks = session.keyStore();
            Optional<PrivateKey> direct = privateFromAlias(ks, entry.alias());
            if (direct.isPresent()) return direct;
            for (String cand : privateAliasCandidates(entry.alias())) {
                Optional<PrivateKey> p = privateFromAlias(ks, cand);
                if (p.isPresent()) return p;
            }
            return Optional.empty();
        } catch (Exception e) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND,
                "개인키 로드 실패: " + entry.alias(), e);
        }
    }

    private Optional<PublicKey> publicFromAlias(KeyStore ks, String alias) {
        try {
            if (ks.containsAlias(alias)) {
                Certificate cert = ks.getCertificate(alias);
                if (cert != null) return Optional.of(cert.getPublicKey());
                if (ks.getKey(alias, null) instanceof PublicKey pub) return Optional.of(pub);
            }
        } catch (Exception e) {
            logger.debug("공개키 KeyStore 조회 실패 alias={}", alias);
        }
        // Luna KeyStore 는 공개키 객체를 getKey 로 돌려주지 않으므로 토큰에서 직접 조회
        return lunaLocate(alias, PublicKey.class);
    }

    private Optional<PrivateKey> privateFromAlias(KeyStore ks, String alias) {
        try {
            if (ks.containsAlias(alias) && ks.getKey(alias, null) instanceof PrivateKey priv) {
                return Optional.of(priv);
            }
        } catch (Exception e) {
            logger.debug("개인키 KeyStore 조회 실패 alias={}", alias);
        }
        return lunaLocate(alias, PrivateKey.class);
    }

    /**
     * Luna 토큰에서 라벨로 키 객체를 직접 조회한다({@code LunaKey.LocateKeyByAlias}).
     * KeyStore SPI 가 노출하지 않는 공개키(PQC/RSA/EC 의 {@code -pub} 객체)도 가져올 수 있다.
     * Luna 환경이 아니거나 미존재 시 빈 값.
     */
    private <T extends java.security.Key> Optional<T> lunaLocate(String alias, Class<T> type) {
        try {
            com.safenetinc.luna.provider.key.LunaKey lk =
                com.safenetinc.luna.provider.key.LunaKey.LocateKeyByAlias(alias, session.slot());
            if (type.isInstance(lk)) return Optional.of(type.cast(lk));
        } catch (Throwable t) {
            logger.debug("Luna 키 직접 조회 실패 alias={} type={}", alias, type.getSimpleName());
        }
        return Optional.empty();
    }

    /** 키쌍 한쪽 라벨에서 공개·개인 접미사를 떼어 base 명을 복원. */
    static String baseAlias(String alias) {
        return alias.replaceAll("(?i)[-_.]?(public|private|pub|priv)$", "");
    }

    private static final String[] PUB_SUFFIXES  = {"-pub", "_pub", ".pub", "-public", "Pub", "pub"};
    private static final String[] PRIV_SUFFIXES = {"-priv", "_priv", ".priv", "-private", "Priv", "priv"};

    /** 선택 alias 기준으로 시도할 공개키 별칭 후보(중복·자기자신 제거). */
    static List<String> publicAliasCandidates(String alias) {
        String base = baseAlias(alias);
        var out = new java.util.LinkedHashSet<String>();
        for (String s : PUB_SUFFIXES) { out.add(alias + s); out.add(base + s); }
        out.add(base);
        out.remove(alias);
        return List.copyOf(out);
    }

    /** 선택 alias 기준으로 시도할 개인키 별칭 후보(중복·자기자신 제거). */
    static List<String> privateAliasCandidates(String alias) {
        String base = baseAlias(alias);
        var out = new java.util.LinkedHashSet<String>();
        for (String s : PRIV_SUFFIXES) { out.add(alias + s); out.add(base + s); }
        out.add(base);
        out.remove(alias);
        return List.copyOf(out);
    }

    public Optional<SecretKey> asSecretKey(KeyEntry entry) throws CryptoOpException {
        try {
            KeyStore ks = session.keyStore();
            return Optional.ofNullable((SecretKey) ks.getKey(entry.alias(), null));
        } catch (Exception e) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND,
                "대칭키 로드 실패: " + entry.alias(), e);
        }
    }

    private KeyEntry entryFor(KeyStore ks, String alias) throws KeyStoreException {
        boolean isKey  = ks.isKeyEntry(alias);
        boolean isCert = ks.isCertificateEntry(alias);

        if (isKey) {
            try {
                var key = ks.getKey(alias, null);
                if (key instanceof PrivateKey pk) {
                    return new KeyEntry(alias, KeyKind.KEYPAIR, pk.getAlgorithm(), keyBits(key, ks, alias));
                }
                if (key instanceof PublicKey pub) {
                    return new KeyEntry(alias, KeyKind.PUBLIC, pub.getAlgorithm(), keyBits(key, ks, alias));
                }
                if (key instanceof SecretKey sk) {
                    return new KeyEntry(alias, KeyKind.SECRET, sk.getAlgorithm(), keyBits(key, ks, alias));
                }
            } catch (Exception e) {
                logger.warn("alias={} 키 로드 실패 — 타입 미상", alias, e);
            }
        }
        return new KeyEntry(alias, isCert ? KeyKind.PUBLIC : KeyKind.PRIVATE, "Unknown", 0);
    }

    /**
     * 키 비트 길이를 구한다.
     * <p>
     * 토큰 키({@code LunaKey})는 추출 불가 시 {@code getEncoded()}가 핸들을 반환해
     * 길이가 틀어지므로, 토큰 객체의 CKA 속성(CKA_VALUE_LEN / CKA_MODULUS)을 직접 읽는다.
     * Luna 환경이 아니거나 조회 실패 시 표준 인터페이스로 폴백.
     */
    private int keyBits(java.security.Key key, KeyStore ks, String alias) {
        // 1) Luna 토큰 객체 CKA 직접 조회 (정확)
        try {
            if (key instanceof com.safenetinc.luna.provider.key.LunaKey lk) {
                var obj = com.safenetinc.luna.LunaTokenObject
                    .LocateObjectByHandle(lk.GetKeyHandle(), session.slot());
                long cls = obj.GetClassAndType()[0];
                if (cls == CKO_SECRET_KEY) {
                    long bytes = obj.GetSmallAttribute(CKA_VALUE_LEN);
                    if (bytes > 0) return (int) (bytes * 8);
                } else {
                    byte[] mod = obj.GetLargeAttribute(CKA_MODULUS);
                    if (mod != null && mod.length > 0) return mod.length * 8;
                    long bits = obj.GetSmallAttribute(CKA_MODULUS_BITS);
                    if (bits > 0) return (int) bits;
                }
            }
        } catch (Throwable t) {
            logger.debug("alias={} CKA 크기 조회 실패 — 폴백 사용", alias);
        }
        // 2) 폴백 — 인증서/표준 인터페이스/encoded
        try {
            Certificate cert = ks.getCertificate(alias);
            if (cert != null && cert.getPublicKey() instanceof java.security.interfaces.RSAKey rk) {
                return rk.getModulus().bitLength();
            }
        } catch (Exception ignored) {}
        if (key instanceof java.security.interfaces.RSAKey rsa) return rsa.getModulus().bitLength();
        byte[] enc = key.getEncoded();
        return enc != null ? enc.length * 8 : 0;
    }
}
