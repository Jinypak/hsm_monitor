package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.util.List;
import java.util.Map;

/**
 * 키 생성 / 라벨 변경 / 속성 변경 / 삭제.
 * <p>
 * 생성은 운영환경과 동일하게 JCE(KeyGenerator/KeyPairGenerator + LunaProvider)로 수행하고,
 * 토큰 영구화·속성 편집·삭제는 {@link TokenKeyAccess}에 위임한다.
 * 검증 로직은 이 클래스에 모아 두어 HSM 없이도 테스트 가능하다.
 */
public final class KeyManager {

    private static final Logger logger = LoggerFactory.getLogger(KeyManager.class);

    public static final List<Integer> AES_SIZES = List.of(128, 192, 256);
    public static final List<Integer> RSA_SIZES = List.of(2048, 3072, 4096);

    private final Provider       provider;
    private final TokenKeyAccess access;

    public KeyManager(LunaSession session) {
        this(session.provider(), new LunaTokenKeyAccess(session));
    }

    /** 테스트용 — Provider와 토큰 접근을 직접 주입. */
    KeyManager(Provider provider, TokenKeyAccess access) {
        this.provider = provider;
        this.access   = access;
    }

    // ── 생성 ─────────────────────────────────────────
    public SecretKey generateAes(String alias, int bits) throws CryptoOpException {
        validateAlias(alias);
        if (!AES_SIZES.contains(bits)) {
            throw new CryptoOpException(Code.GENERAL,
                "AES 키 길이는 " + AES_SIZES + " 중 하나여야 합니다: " + bits);
        }
        requireAbsent(alias);
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
            kg.init(bits);
            SecretKey key = kg.generateKey();
            access.makePersistent(key, alias);
            logger.info("AES 키 생성: alias={} bits={}", alias, bits);
            return key;
        } catch (CryptoOpException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "AES 키 생성 실패: " + e.getMessage(), e);
        }
    }

    /**
     * 범용 대칭키 생성 — ARIA/DESede/SM4/GenericSecret 등.
     * {@code jceAlgo} 는 {@code KeyGenerator} 알고리즘명(예: "ARIA", "DESede").
     * {@code bits<=0} 이면 길이 미지정(알고리즘 기본값) 으로 생성한다.
     */
    public SecretKey generateSecret(String jceAlgo, String alias, int bits) throws CryptoOpException {
        validateAlias(alias);
        requireAbsent(alias);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(jceAlgo, provider);
            if (bits > 0) kg.init(bits);
            SecretKey key = kg.generateKey();
            access.makePersistent(key, alias);
            logger.info("{} 키 생성: alias={} bits={}", jceAlgo, alias, bits);
            return key;
        } catch (CryptoOpException e) {
            throw e;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CryptoOpException(Code.MECH_NOT_SUPPORTED,
                jceAlgo + " 미지원 — Provider 가 노출하지 않습니다: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, jceAlgo + " 키 생성 실패: " + e.getMessage(), e);
        }
    }

    /** 지원 EC 곡선(NIST P-256/384/521). */
    public static final List<String> EC_CURVES = List.of("secp256r1", "secp384r1", "secp521r1");

    /** EC 키쌍 생성 — {@code curve} 는 {@link java.security.spec.ECGenParameterSpec} 곡선명. */
    public KeyPair generateEc(String alias, String curve) throws CryptoOpException {
        validateAlias(alias);
        String pubAlias = alias + PUBLIC_SUFFIX;
        requireAbsent(alias);
        requireAbsent(pubAlias);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
            kpg.initialize(new java.security.spec.ECGenParameterSpec(curve));
            KeyPair pair = kpg.generateKeyPair();
            access.makePersistent(pair.getPrivate(), alias);
            access.makePersistent(pair.getPublic(),  pubAlias);
            logger.info("EC 키쌍 생성: priv={} pub={} curve={}", alias, pubAlias, curve);
            return pair;
        } catch (CryptoOpException e) {
            throw e;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CryptoOpException(Code.MECH_NOT_SUPPORTED,
                "EC 미지원 — Provider 가 노출하지 않습니다: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "EC 키쌍 생성 실패: " + e.getMessage(), e);
        }
    }

    /** RSA 공개키 라벨 접미사 — 목록에서 개인키와 구분되도록. */
    public static final String PUBLIC_SUFFIX = "-pub";

    public KeyPair generateRsa(String alias, int bits) throws CryptoOpException {
        validateAlias(alias);
        if (!RSA_SIZES.contains(bits)) {
            throw new CryptoOpException(Code.GENERAL,
                "RSA 키 길이는 " + RSA_SIZES + " 중 하나여야 합니다: " + bits);
        }
        String pubAlias = alias + PUBLIC_SUFFIX;
        requireAbsent(alias);
        requireAbsent(pubAlias);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
            kpg.initialize(bits);
            KeyPair pair = kpg.generateKeyPair();
            // 개인키는 alias, 공개키는 alias-pub 로 구분되게 영구화 (CKA_CLASS 로도 구분되지만
            // 목록 가독성을 위해 라벨도 분리)
            access.makePersistent(pair.getPrivate(), alias);
            access.makePersistent(pair.getPublic(),  pubAlias);
            logger.info("RSA 키쌍 생성: priv={} pub={} bits={}", alias, pubAlias, bits);
            return pair;
        } catch (CryptoOpException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "RSA 키쌍 생성 실패: " + e.getMessage(), e);
        }
    }

    /** 지원되는 ML-KEM 파라미터셋. */
    public static final List<String> ML_KEM_SETS = List.of("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024");

    /**
     * ML-KEM 키쌍을 생성해 토큰에 저장한다. 파라미터셋 이름이 곧 JCE 알고리즘명.
     * Provider(LunaProvider 또는 JDK)가 ML-KEM 을 노출해야 한다.
     */
    public KeyPair generateMlKem(String alias, String paramSet) throws CryptoOpException {
        validateAlias(alias);
        if (!ML_KEM_SETS.contains(paramSet)) {
            throw new CryptoOpException(Code.MECH_NOT_SUPPORTED,
                "지원하지 않는 ML-KEM 파라미터셋: " + paramSet + " (가능: " + ML_KEM_SETS + ")");
        }
        String pubAlias = alias + PUBLIC_SUFFIX;
        requireAbsent(alias);
        requireAbsent(pubAlias);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(paramSet, provider);
            KeyPair pair = kpg.generateKeyPair();
            access.makePersistent(pair.getPrivate(), alias);
            access.makePersistent(pair.getPublic(),  pubAlias);
            logger.info("ML-KEM 키쌍 생성: priv={} pub={} set={}", alias, pubAlias, paramSet);
            return pair;
        } catch (CryptoOpException e) {
            throw e;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CryptoOpException(Code.MECH_NOT_SUPPORTED,
                paramSet + " 미지원 — 펌웨어/Provider 가 ML-KEM 을 노출하지 않습니다: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "ML-KEM 키쌍 생성 실패: " + e.getMessage(), e);
        }
    }

    /** 지원되는 ML-DSA 파라미터셋. */
    public static final List<String> ML_DSA_SETS = List.of("ML-DSA-44", "ML-DSA-65", "ML-DSA-87");

    /**
     * ML-DSA 키쌍을 생성해 토큰에 저장한다. 펌웨어가 ML-DSA 를 지원하면 LunaProvider 가
     * 서비스로 노출하며, 그 경우 생성된 키는 {@code LunaKey} 이므로 토큰 영구화가 가능하다.
     * <p>
     * 키 이전(다른 슬롯으로 래핑→내보내기)을 위해 개인키를 {@code extractable=true}로 생성한다.
     * {@link #generateMlDsa(String, String, boolean)} 의 추출 불가 기본값 버전.
     */
    public KeyPair generateMlDsa(String alias, String paramSet) throws CryptoOpException {
        return generateMlDsa(alias, paramSet, false);
    }

    /**
     * ML-DSA 키쌍을 생성해 토큰에 저장한다.
     *
     * @param extractable {@code true}면 개인키를 {@code CKA_EXTRACTABLE=true}로 생성한다.
     *   AES-KWP 로 토큰 밖으로 래핑(키 이전)하려면 반드시 생성 시점에 켜야 한다 —
     *   PKCS#11 규칙상 {@code CKA_EXTRACTABLE}은 생성 후 {@code false→true} 변경이 불가하다.
     *   <p>실제 래핑까지 성공하려면 파티션 정책 {@code Allow private key wrapping}(슬롯0)과
     *   {@code Allow private key unwrapping}(슬롯1)도 켜져 있어야 한다(FW 7.9.1+, Client 10.9.1+).
     */
    public KeyPair generateMlDsa(String alias, String paramSet, boolean extractable)
        throws CryptoOpException {
        validateAlias(alias);
        if (!ML_DSA_SETS.contains(paramSet)) {
            throw new CryptoOpException(Code.MECH_NOT_SUPPORTED,
                "지원하지 않는 ML-DSA 파라미터셋: " + paramSet + " (가능: " + ML_DSA_SETS + ")");
        }
        String pubAlias = alias + PUBLIC_SUFFIX;
        requireAbsent(alias);
        requireAbsent(pubAlias);
        try {
            // 파라미터셋 이름(ML-DSA-65)이 곧 JCE 알고리즘명. provider 가 미지원이면 예외.
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(paramSet, provider);
            if (extractable) {
                applyExtractablePrivateTemplate(kpg, paramSet);
            }
            KeyPair pair = kpg.generateKeyPair();
            access.makePersistent(pair.getPrivate(), alias);
            access.makePersistent(pair.getPublic(),  pubAlias);
            logger.info("ML-DSA 키쌍 생성: priv={} pub={} set={} extractable={}",
                alias, pubAlias, paramSet, extractable);
            return pair;
        } catch (CryptoOpException e) {
            throw e;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CryptoOpException(Code.MECH_NOT_SUPPORTED,
                paramSet + " 미지원 — 펌웨어/Provider 가 ML-DSA 를 노출하지 않습니다: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "ML-DSA 키쌍 생성 실패: " + e.getMessage(), e);
        }
    }

    /** LunaProvider 식별자 — 추출가능 템플릿은 Luna 키 생성에만 적용한다. */
    static final String LUNA_PROVIDER_NAME = "LunaProvider";

    /**
     * Luna 의 ML-DSA 키 생성 템플릿 CKA(벤더값). 파라미터셋을 PUBLIC 클래스의 long 속성으로 지정한다.
     * (LunaKeyPairGeneratorMLDSA 가 {@code LunaPkcs11AttributesParameterSpec} 사용 시
     *  inner spec 이 아니라 이 속성에서 파라미터셋을 읽는다 — 미설정 시 "attribute not set")
     */
    private static final long LUNA_CKA_MLDSA_PARAMETER_SET = 1565L;

    /** ML-DSA 파라미터셋 → Luna 내부 코드(44→1, 65→2, 87→3). */
    private static long mlDsaParameterSetCode(String paramSet) {
        return switch (paramSet) {
            case "ML-DSA-44" -> 1L;
            case "ML-DSA-65" -> 2L;
            case "ML-DSA-87" -> 3L;
            default -> throw new IllegalArgumentException("알 수 없는 ML-DSA 파라미터셋: " + paramSet);
        };
    }

    /**
     * KeyPairGenerator 에 개인키 {@code CKA_EXTRACTABLE=true} 생성 템플릿을 적용한다.
     * <p>
     * LunaProvider 일 때만 {@code LunaPkcs11AttributesParameterSpec} 로 템플릿을 지정한다.
     * 이 spec 을 쓰면 생성기가 파라미터셋도 attributes(PUBLIC, {@value #LUNA_CKA_MLDSA_PARAMETER_SET})
     * 에서 읽으므로 파라미터셋 long 속성을 함께 넣어야 한다.
     * 비-Luna provider(SunJCE 등, 단위 테스트)는 토큰 객체 개념이 없으므로 그대로 둔다.
     */
    private void applyExtractablePrivateTemplate(KeyPairGenerator kpg, String paramSet)
        throws java.security.InvalidAlgorithmParameterException {
        if (!LUNA_PROVIDER_NAME.equals(provider.getName())) {
            return; // 비-Luna: CKA 템플릿 비적용(표준 생성)
        }
        var attrs = new com.safenetinc.luna.attributes.LunaPkcs11Attributes();
        // (1) 생성기가 요구하는 파라미터셋 — PUBLIC 클래스 long 속성
        attrs.setLongAttribute(
            com.safenetinc.luna.attributes.LunaPkcs11Attributes.PUBLIC,
            LUNA_CKA_MLDSA_PARAMETER_SET, mlDsaParameterSetCode(paramSet));
        // (2) 실제 목적 — 개인키를 토큰 밖으로 래핑 가능하게(CKA_EXTRACTABLE=true)
        attrs.setBooleanAttribute(
            com.safenetinc.luna.attributes.LunaPkcs11Attributes.PRIVATE,
            KeyAttribute.EXTRACTABLE.cka(), true);
        kpg.initialize(
            new com.safenetinc.luna.provider.param.LunaPkcs11AttributesParameterSpec(attrs, null));
    }

    // ── 라벨 변경 ─────────────────────────────────────
    public void relabel(String oldAlias, String newAlias) throws CryptoOpException {
        validateAlias(newAlias);
        if (newAlias.equals(oldAlias)) {
            throw new CryptoOpException(Code.GENERAL, "새 라벨이 기존과 동일합니다.");
        }
        if (!access.exists(oldAlias)) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND, "키를 찾을 수 없습니다: " + oldAlias);
        }
        requireAbsent(newAlias);
        access.relabel(oldAlias, newAlias);
        logger.info("키 라벨 변경: {} → {}", oldAlias, newAlias);
    }

    // ── 속성 조회 / 변경 ──────────────────────────────
    public Map<KeyAttribute, Boolean> attributes(String alias) throws CryptoOpException {
        if (!access.exists(alias)) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND, "키를 찾을 수 없습니다: " + alias);
        }
        return access.readAttributes(alias);
    }

    public void setAttribute(String alias, KeyAttribute attr, boolean value) throws CryptoOpException {
        if (!access.exists(alias)) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND, "키를 찾을 수 없습니다: " + alias);
        }
        access.setAttribute(alias, attr, value);
        logger.info("키 속성 변경: alias={} {}={}", alias, attr.name(), value);
    }

    // ── 삭제 ─────────────────────────────────────────
    public void delete(String alias) throws CryptoOpException {
        if (!access.exists(alias)) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND, "키를 찾을 수 없습니다: " + alias);
        }
        access.destroy(alias);
        logger.warn("키 영구 삭제: alias={}", alias);
    }

    // ── 내부 검증 ─────────────────────────────────────
    private void validateAlias(String alias) throws CryptoOpException {
        if (alias == null || alias.isBlank()) {
            throw new CryptoOpException(Code.GENERAL, "alias(라벨)를 입력하세요.");
        }
    }

    private void requireAbsent(String alias) throws CryptoOpException {
        if (access.exists(alias)) {
            throw new CryptoOpException(Code.GENERAL, "이미 존재하는 라벨입니다: " + alias);
        }
    }
}
