package com.yours.hsm.algo;

import com.yours.hsm.algo.AlgoSpec.Family;
import com.yours.hsm.algo.AlgoSpec.Op;

import java.util.List;
import java.util.Optional;

/**
 * 정적 알고리즘 카탈로그.
 * <p>
 * 데이터 출처: {@code docs/mechanism-catalog.md}.
 * Phase 1 노출 항목({@code phase1Default=true})은 §11.3 의 11개와 1:1 일치(이 11개만 true).
 * <p>
 * <b>연산 등급</b>은 데이터로 구분한다:
 * <ul>
 *   <li><b>Tier A</b> — JCE 표준 서비스로 매핑되어 실제 연산 가능(RSA/AES/EC/EdDSA/DSA/DH/
 *       ARIA/DES3/Digest/HMAC/KDF 등). 콤보 노출 여부는 런타임 {@link com.yours.hsm.core.ProviderProbe}
 *       가 결정한다.</li>
 *   <li><b>Tier B</b> — 카탈로그/가용성 표시 전용(PQC·SM·DUKPT·Milenage·BIP32·SSL3·PBE·RC/CAST 등).
 *       해당 Provider가 노출하면 자동으로 연산 탭에도 등장한다.</li>
 * </ul>
 * 펌웨어 업그레이드로 새 메커니즘이 활성화되면 {@code phase1Default} 와 무관하게
 * {@code ProviderProbe} 가 런타임에 가용성을 결정한다.
 */
public final class AlgoCatalog {

    private AlgoCatalog() {}

    // 11-인자 생성 가독성을 위한 짧은 별칭
    private static AlgoSpec spec(String id, Family f, Op op, String jce, String ckm,
                                 int bits, boolean fips, boolean vendor, boolean p1,
                                 boolean deprecated, boolean regional) {
        return new AlgoSpec(id, f, op, jce, ckm, bits, fips, vendor, p1, deprecated, regional);
    }

    private static final List<AlgoSpec> ALL = List.of(

        // ════════════════════════════════════════════════════════════════
        //  Phase 1 (mechanism-catalog.md §11.3) — 이 11개만 phase1Default=true
        // ════════════════════════════════════════════════════════════════
        new AlgoSpec("RSA_KEYPAIR",         Family.RSA,    Op.KEYPAIR_GEN,
                     "RSA",                                            "0x00000000", 0, true,  false, true),
        new AlgoSpec("RSA_SIGN_SHA256",     Family.RSA,    Op.SIGN,
                     "SHA256withRSA",                                  "0x00000040", 0, true,  false, true),
        new AlgoSpec("RSA_SIGN_SHA256_PSS", Family.RSA,    Op.SIGN,
                     "SHA256withRSA/PSS",                              "0x00000043", 0, true,  false, true),
        new AlgoSpec("RSA_OAEP_SHA256",     Family.RSA,    Op.ENC,
                     "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",          "0x00000009", 0, true,  false, true),
        new AlgoSpec("AES_KEYGEN",          Family.AES,    Op.KEYGEN,
                     "AES",                                            "0x00001080", 0, true,  false, true),
        new AlgoSpec("AES_CBC_PKCS5",       Family.AES,    Op.ENC,
                     "AES/CBC/PKCS5Padding",                           "0x00001085", 0, true,  false, true),
        new AlgoSpec("AES_GCM",             Family.AES,    Op.ENC,
                     "AES/GCM/NoPadding",                              "0x00001087", 0, true,  false, true),
        new AlgoSpec("AES_KWP",             Family.AES,    Op.WRAP,
                     "AES/KWP/NoPadding",                              "0x80000171", 0, true,  true,  true),
        new AlgoSpec("AES_CMAC",            Family.AES,    Op.MAC,
                     "AESCMAC",                                        "0x0000108a", 0, true,  false, true),
        new AlgoSpec("HMAC_SHA256",         Family.HMAC,   Op.MAC,
                     "HmacSHA256",                                     "0x00000251", 0, true,  false, true),
        new AlgoSpec("SHA256",              Family.DIGEST, Op.DIGEST,
                     "SHA-256",                                        "0x00000250", 0, true,  false, true),

        // ════════════════════════════════════════════════════════════════
        //  RSA — Tier A (서명/암복호화 전 변형)
        // ════════════════════════════════════════════════════════════════
        spec("RSA_SIGN_SHA1",      Family.RSA, Op.SIGN, "SHA1withRSA",        "0x00000006", 0, false, false, false, true,  false),
        spec("RSA_SIGN_SHA224",    Family.RSA, Op.SIGN, "SHA224withRSA",      "0x00000046", 0, true,  false, false, false, false),
        new AlgoSpec("RSA_SIGN_SHA384",     Family.RSA, Op.SIGN, "SHA384withRSA",      "0x00000041", 0, true,  false, false),
        new AlgoSpec("RSA_SIGN_SHA512",     Family.RSA, Op.SIGN, "SHA512withRSA",      "0x00000042", 0, true,  false, false),
        new AlgoSpec("RSA_SIGN_SHA3_256",   Family.RSA, Op.SIGN, "SHA3-256withRSA",    "0x00000060", 0, true,  false, false),
        new AlgoSpec("RSA_SIGN_SHA3_384",   Family.RSA, Op.SIGN, "SHA3-384withRSA",    "0x00000061", 0, true,  false, false),
        new AlgoSpec("RSA_SIGN_SHA3_512",   Family.RSA, Op.SIGN, "SHA3-512withRSA",    "0x00000062", 0, true,  false, false),
        spec("RSA_SIGN_SHA1_PSS",  Family.RSA, Op.SIGN, "SHA1withRSA/PSS",    "0x0000000e", 0, false, false, false, true,  false),
        new AlgoSpec("RSA_SIGN_SHA384_PSS", Family.RSA, Op.SIGN, "SHA384withRSA/PSS",  "0x00000044", 0, true,  false, false),
        new AlgoSpec("RSA_SIGN_SHA512_PSS", Family.RSA, Op.SIGN, "SHA512withRSA/PSS",  "0x00000045", 0, true,  false, false),
        new AlgoSpec("RSA_PKCS_ENC",        Family.RSA, Op.ENC,  "RSA/ECB/PKCS1Padding","0x00000001",0, true,  false, false),
        spec("RSA_X509_ENC",       Family.RSA, Op.ENC,  "RSA/ECB/NoPadding",  "0x00000003", 0, false, false, false, true,  false),

        // ════════════════════════════════════════════════════════════════
        //  AES — Tier A (전 모드 + MAC + 래핑)
        // ════════════════════════════════════════════════════════════════
        spec("AES_ECB",   Family.AES, Op.ENC, "AES/ECB/NoPadding",   "0x00001081", 0, false, false, false, true,  false),
        new AlgoSpec("AES_CBC",     Family.AES, Op.ENC, "AES/CBC/NoPadding",   "0x00001082", 0, true, false, false),
        new AlgoSpec("AES_CTR",     Family.AES, Op.ENC, "AES/CTR/NoPadding",   "0x00001086", 0, true, false, false),
        new AlgoSpec("AES_CFB8",    Family.AES, Op.ENC, "AES/CFB8/NoPadding",  "0x00002106", 0, true, false, false),
        new AlgoSpec("AES_CFB128",  Family.AES, Op.ENC, "AES/CFB128/NoPadding","0x00002107", 0, true, false, false),
        new AlgoSpec("AES_OFB",     Family.AES, Op.ENC, "AES/OFB/NoPadding",   "0x00002104", 0, true, false, false),
        spec("AES_XTS",   Family.AES, Op.ENC, "AES/XTS/NoPadding",   "0x00001071", 0, true,  true,  false, false, false),
        new AlgoSpec("AES_KW",      Family.AES, Op.WRAP,"AESWrap",             "0x80000170", 0, true, true,  false),
        new AlgoSpec("AES_GMAC",    Family.AES, Op.MAC, "AESGMAC",             "0x0000108e", 0, true, false, false),

        // ════════════════════════════════════════════════════════════════
        //  EC / ECDSA / ECDH — Tier A
        // ════════════════════════════════════════════════════════════════
        new AlgoSpec("EC_KEYPAIR",       Family.EC, Op.KEYPAIR_GEN, "EC",              "0x00001040", 0, true, false, false),
        spec("ECDSA_SHA1",      Family.EC, Op.SIGN, "SHA1withECDSA",   "0x00001042", 0, false, false, false, true,  false),
        new AlgoSpec("ECDSA_SHA224",     Family.EC, Op.SIGN, "SHA224withECDSA", "0x00001043", 0, true, false, false),
        new AlgoSpec("ECDSA_SHA256",     Family.EC, Op.SIGN, "SHA256withECDSA", "0x00001044", 0, true, false, false),
        new AlgoSpec("ECDSA_SHA384",     Family.EC, Op.SIGN, "SHA384withECDSA", "0x00001045", 0, true, false, false),
        new AlgoSpec("ECDSA_SHA512",     Family.EC, Op.SIGN, "SHA512withECDSA", "0x00001046", 0, true, false, false),
        new AlgoSpec("ECDSA_SHA3_256",   Family.EC, Op.SIGN, "SHA3-256withECDSA","0x00001048",0, true, false, false),
        new AlgoSpec("ECDH_DERIVE",      Family.EC, Op.DERIVE,"ECDH",            "0x00001050", 0, true, false, false),

        // ════════════════════════════════════════════════════════════════
        //  EdDSA / Montgomery — Tier A
        // ════════════════════════════════════════════════════════════════
        new AlgoSpec("ED25519_KEYPAIR",  Family.EDDSA,      Op.KEYPAIR_GEN, "Ed25519", "0x00001055", 0, true, false, false),
        new AlgoSpec("EDDSA_ED25519",    Family.EDDSA,      Op.SIGN,        "Ed25519", "0x00001057", 0, true, false, false),
        new AlgoSpec("ED448_KEYPAIR",    Family.EDDSA,      Op.KEYPAIR_GEN, "Ed448",   "0x00001055", 0, true, false, false),
        new AlgoSpec("EDDSA_ED448",      Family.EDDSA,      Op.SIGN,        "Ed448",   "0x00001057", 0, true, false, false),
        new AlgoSpec("X25519_KEYPAIR",   Family.MONTGOMERY, Op.KEYPAIR_GEN, "X25519",  "0x00001056", 0, true, false, false),
        new AlgoSpec("X25519_DERIVE",    Family.MONTGOMERY, Op.DERIVE,      "X25519",  "0x00001050", 0, true, false, false),

        // ════════════════════════════════════════════════════════════════
        //  DSA / DH — Tier A (legacy 호환)
        // ════════════════════════════════════════════════════════════════
        new AlgoSpec("DSA_KEYPAIR",      Family.DSA, Op.KEYPAIR_GEN, "DSA",          "0x00000010", 0, true, false, false),
        new AlgoSpec("DSA_SHA256",       Family.DSA, Op.SIGN,        "SHA256withDSA","0x00000014", 0, true, false, false),
        new AlgoSpec("DH_KEYPAIR",       Family.DH,  Op.KEYPAIR_GEN, "DiffieHellman","0x00000020", 0, true, false, false),
        new AlgoSpec("DH_DERIVE",        Family.DH,  Op.DERIVE,      "DiffieHellman","0x00000021", 0, true, false, false),

        // ════════════════════════════════════════════════════════════════
        //  ARIA 🌏 (KS X 1213) — Tier A (한국 표준)
        // ════════════════════════════════════════════════════════════════
        spec("ARIA_KEYGEN",  Family.ARIA, Op.KEYGEN, "ARIA",                 "0x00000560", 0, false, false, false, false, true),
        spec("ARIA_CBC_PAD", Family.ARIA, Op.ENC,    "ARIA/CBC/PKCS5Padding","0x00000565", 0, false, false, false, false, true),
        spec("ARIA_ECB",     Family.ARIA, Op.ENC,    "ARIA/ECB/NoPadding",   "0x00000561", 0, false, false, false, true,  true),
        spec("ARIA_CTR",     Family.ARIA, Op.ENC,    "ARIA/CTR/NoPadding",   "0x80000120", 0, false, true,  false, false, true),
        spec("ARIA_CMAC",    Family.ARIA, Op.MAC,    "ARIACMAC",             "0x80000128", 0, false, true,  false, false, true),

        // ════════════════════════════════════════════════════════════════
        //  DES3 (3DES) — Tier A 이지만 deprecated
        // ════════════════════════════════════════════════════════════════
        spec("DES3_KEYGEN",   Family.DES3, Op.KEYGEN, "DESede",                   "0x00000131", 0, false, false, false, true, false),
        spec("DES3_CBC_PAD",  Family.DES3, Op.ENC,    "DESede/CBC/PKCS5Padding",  "0x00000136", 0, false, false, false, true, false),
        spec("DES3_ECB",      Family.DES3, Op.ENC,    "DESede/ECB/NoPadding",     "0x00000132", 0, false, false, false, true, false),
        spec("DES3_CMAC",     Family.DES3, Op.MAC,    "DESedeCMAC",               "0x00000138", 0, false, false, false, true, false),

        // ════════════════════════════════════════════════════════════════
        //  Digest — Tier A
        // ════════════════════════════════════════════════════════════════
        spec("SHA1",     Family.DIGEST, Op.DIGEST, "SHA-1",    "0x00000220", 0, false, false, false, true, false),
        new AlgoSpec("SHA224",    Family.DIGEST, Op.DIGEST, "SHA-224",  "0x00000255", 0, true, false, false),
        new AlgoSpec("SHA384",    Family.DIGEST, Op.DIGEST, "SHA-384",  "0x00000260", 0, true, false, false),
        new AlgoSpec("SHA512",    Family.DIGEST, Op.DIGEST, "SHA-512",  "0x00000270", 0, true, false, false),
        new AlgoSpec("SHA3_256",  Family.DIGEST, Op.DIGEST, "SHA3-256", "0x000002b0", 0, true, false, false),
        new AlgoSpec("SHA3_384",  Family.DIGEST, Op.DIGEST, "SHA3-384", "0x000002c0", 0, true, false, false),
        new AlgoSpec("SHA3_512",  Family.DIGEST, Op.DIGEST, "SHA3-512", "0x000002d0", 0, true, false, false),
        spec("MD5",      Family.DIGEST, Op.DIGEST, "MD5",      "0x00000210", 0, false, false, false, true, false),

        // ════════════════════════════════════════════════════════════════
        //  HMAC — Tier A
        // ════════════════════════════════════════════════════════════════
        spec("HMAC_SHA1",     Family.HMAC, Op.MAC, "HmacSHA1",     "0x00000221", 0, false, false, false, true, false),
        new AlgoSpec("HMAC_SHA224",    Family.HMAC, Op.MAC, "HmacSHA224",   "0x00000256", 0, true, false, false),
        new AlgoSpec("HMAC_SHA384",    Family.HMAC, Op.MAC, "HmacSHA384",   "0x00000261", 0, true, false, false),
        new AlgoSpec("HMAC_SHA512",    Family.HMAC, Op.MAC, "HmacSHA512",   "0x00000271", 0, true, false, false),
        new AlgoSpec("HMAC_SHA3_256",  Family.HMAC, Op.MAC, "HmacSHA3-256", "0x000002b1", 0, true, false, false),

        // ════════════════════════════════════════════════════════════════
        //  KDF — Tier A
        // ════════════════════════════════════════════════════════════════
        new AlgoSpec("PBKDF2_SHA256",  Family.KDF, Op.KDF, "PBKDF2WithHmacSHA256", "0x000003b0", 0, true, false, false),
        new AlgoSpec("GENERIC_SECRET", Family.KDF, Op.KEYGEN, "GenericSecret",     "0x00000350", 0, true, false, false),

        // ════════════════════════════════════════════════════════════════
        //  PQC — Tier B (LunaProvider 10.7 에서 KeyPairGenerator 로 노출됨)
        //  서명 연산명은 "ML-DSA"(파라미터는 키에서), KEM 은 "KEM.ML-KEM".
        //  카탈로그는 파라미터셋(키생성 기준)으로 표기하고 op=KEYPAIR_GEN 으로 가용성 판정.
        // ════════════════════════════════════════════════════════════════
        new AlgoSpec("ML_DSA_44",   Family.ML_DSA, Op.KEYPAIR_GEN, "ML-DSA-44",   "TBD", 0, true, false, false),
        new AlgoSpec("ML_DSA_65",   Family.ML_DSA, Op.KEYPAIR_GEN, "ML-DSA-65",   "TBD", 0, true, false, false),
        new AlgoSpec("ML_DSA_87",   Family.ML_DSA, Op.KEYPAIR_GEN, "ML-DSA-87",   "TBD", 0, true, false, false),
        new AlgoSpec("ML_KEM_512",  Family.ML_KEM, Op.KEYPAIR_GEN, "ML-KEM-512",  "TBD", 0, true, false, false),
        new AlgoSpec("ML_KEM_768",  Family.ML_KEM, Op.KEYPAIR_GEN, "ML-KEM-768",  "TBD", 0, true, false, false),
        new AlgoSpec("ML_KEM_1024", Family.ML_KEM, Op.KEYPAIR_GEN, "ML-KEM-1024", "TBD", 0, true, false, false),
        new AlgoSpec("SLH_DSA_128S",Family.SLH_DSA,Op.KEYPAIR_GEN, "SLH-DSA-SHA2-128s","TBD",0, true, false, false),

        // ════════════════════════════════════════════════════════════════
        //  SM 🌏 (중국 상용) — Tier B
        // ════════════════════════════════════════════════════════════════
        spec("SM2_KEYPAIR", Family.SM2, Op.KEYPAIR_GEN, "SM2",      "0x80000b20", 0, false, true, false, false, true),
        spec("SM3_SM2",     Family.SM2, Op.SIGN,        "SM3withSM2","0x80000b22",0, false, true, false, false, true),
        spec("SM3",         Family.SM3, Op.DIGEST,      "SM3",      "0x80000b01", 0, false, true, false, false, true),
        spec("SM4_KEYGEN",  Family.SM4, Op.KEYGEN,      "SM4",      "0x80000b10", 0, false, true, false, false, true),
        spec("SM4_CBC",     Family.SM4, Op.ENC,         "SM4/CBC/PKCS5Padding","0x80000b13",0, false, true, false, false, true),

        // ════════════════════════════════════════════════════════════════
        //  도메인 특화 🌏 — Tier B (카탈로그/가용성 전용)
        // ════════════════════════════════════════════════════════════════
        spec("BIP32_MASTER_DERIVE", Family.BIP32,    Op.DERIVE, "BIP32MasterDerive", "0x80000e00", 0, false, true, false, false, true),
        spec("BIP32_CHILD_DERIVE",  Family.BIP32,    Op.DERIVE, "BIP32ChildDerive",  "0x80000e01", 0, false, true, false, false, true),
        spec("DUKPT_IPEK",          Family.DUKPT,    Op.DERIVE, "DES2DUKPTIPEK",     "0x80000610", 0, false, true, false, true,  true),
        spec("MILENAGE",            Family.MILENAGE, Op.DERIVE, "Milenage",          "0x80000e21", 0, false, true, false, false, true),
        spec("TUAK",                Family.TUAK,     Op.DERIVE, "Tuak",              "0x80000e24", 0, false, true, false, false, true),
        spec("SSL3_MASTER_DERIVE",  Family.SSL3,     Op.DERIVE, "SSL3MasterDerive",  "0x00000371", 0, false, false,false, true,  false),
        spec("PBE_SHA1_DES3",       Family.PBE,      Op.ENC,    "PBEWithSHA1AndDESede","0x000003a8",0, false, false,false, true,  false),

        // ════════════════════════════════════════════════════════════════
        //  RC / CAST — Tier B (legacy, 미사용 권장)
        // ════════════════════════════════════════════════════════════════
        spec("RC4",      Family.RC,   Op.ENC, "ARCFOUR",            "0x00000111", 0, false, false, false, true, false),
        spec("RC2_CBC",  Family.RC,   Op.ENC, "RC2/CBC/PKCS5Padding","0x00000105",0, false, false, false, true, false),
        spec("CAST5_CBC",Family.CAST, Op.ENC, "CAST5/CBC/PKCS5Padding","0x00000325",0,false,false, false, true, false)
    );

    public static List<AlgoSpec> all() {
        return ALL;
    }

    /** §11.3 Phase 1 기본 노출 항목(11개). */
    public static List<AlgoSpec> phase1() {
        return ALL.stream().filter(AlgoSpec::phase1Default).toList();
    }

    public static List<AlgoSpec> by(Family family) {
        return ALL.stream().filter(s -> s.family() == family).toList();
    }

    public static List<AlgoSpec> by(Op op) {
        return ALL.stream().filter(s -> s.op() == op).toList();
    }

    public static List<AlgoSpec> by(Family family, Op op) {
        return ALL.stream()
            .filter(s -> s.family() == family && s.op() == op)
            .toList();
    }

    public static Optional<AlgoSpec> findById(String id) {
        return ALL.stream().filter(s -> s.id().equals(id)).findFirst();
    }
}
