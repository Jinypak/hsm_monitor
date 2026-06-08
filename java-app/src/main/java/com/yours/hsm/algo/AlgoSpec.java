package com.yours.hsm.algo;

/**
 * 알고리즘 스펙 — JCE 알고리즘명, PKCS#11 메커니즘 코드, 가용성 메타데이터를 한 데 묶음.
 * 카탈로그({@link AlgoCatalog})의 단일 항목 단위.
 */
public record AlgoSpec(
    String  id,
    Family  family,
    Op      op,
    String  jceName,
    String  ckmHex,
    int     keyBits,
    boolean fipsApproved,
    boolean vendorOnly,
    boolean phase1Default,
    boolean deprecated,    // ⚠ legacy/insecure — UI 경고 표시용
    boolean regional       // 🌏 지역/도메인 한정 (ARIA/SM/GBCS/DUKPT 등)
) {

    public enum Family {
        RSA, AES, EC, EDDSA, MONTGOMERY, DSA, DH,
        HMAC, DIGEST, KDF,
        ARIA, SM2, SM3, SM4, DES, DES3, RC, CAST,
        BIP32, DUKPT, MILENAGE, TUAK, SSL3, PBE,
        ML_DSA, ML_KEM, SLH_DSA
    }

    public enum Op {
        KEYGEN, KEYPAIR_GEN, PARAM_GEN,
        SIGN, VERIFY,
        ENC, DEC,
        WRAP, UNWRAP,
        MAC, DIGEST,
        DERIVE, KDF
    }

    public AlgoSpec {
        if (id == null || id.isBlank())            throw new IllegalArgumentException("id required");
        if (jceName == null || jceName.isBlank())  throw new IllegalArgumentException("jceName required");
        if (family == null)                        throw new IllegalArgumentException("family required");
        if (op == null)                            throw new IllegalArgumentException("op required");
        if (ckmHex == null)                        throw new IllegalArgumentException("ckmHex required (use \"TBD\" for missing)");
        if (keyBits < 0)                           throw new IllegalArgumentException("keyBits must be >= 0 (0 = variable/unknown)");
    }

    /**
     * 9-인자 간편 생성자 — deprecated/regional 미지정(둘 다 false).
     * 기존 Phase 1 항목 및 테스트 호환용.
     */
    public AlgoSpec(String id, Family family, Op op, String jceName, String ckmHex,
                    int keyBits, boolean fipsApproved, boolean vendorOnly, boolean phase1Default) {
        this(id, family, op, jceName, ckmHex, keyBits, fipsApproved, vendorOnly, phase1Default, false, false);
    }
}
