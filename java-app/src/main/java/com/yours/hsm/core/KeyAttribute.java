package com.yours.hsm.core;

/**
 * 편집 가능한 PKCS#11 키 속성(CKA_*) 카탈로그.
 * <p>
 * cka 값은 PKCS#11 v2.40 표준 상수. UI 표시는 {@link #label}.
 * boolean 속성만 다룬다(라벨 변경은 {@link KeyManager#relabel} 별도).
 */
public enum KeyAttribute {

    ENCRYPT    (0x00000104L, "암호화",   "이 키로 암호화 가능"),
    DECRYPT    (0x00000105L, "복호화",   "이 키로 복호화 가능"),
    SIGN       (0x00000108L, "서명",     "이 키로 서명 생성 가능"),
    VERIFY     (0x0000010AL, "검증",     "이 키로 서명 검증 가능"),
    WRAP       (0x00000106L, "래핑",     "이 키로 다른 키를 래핑 가능"),
    UNWRAP     (0x00000107L, "언래핑",   "이 키로 다른 키를 언래핑 가능"),
    EXTRACTABLE(0x00000162L, "추출가능", "토큰 밖으로 키 추출 허용 (보안 민감)"),
    DERIVE     (0x0000010CL, "파생",     "이 키로 다른 키 파생 가능"),
    MODIFIABLE (0x00000170L, "수정가능", "이후 속성 변경 허용 (false 시 잠김)");

    private final long   cka;
    private final String label;
    private final String description;

    KeyAttribute(long cka, String label, String description) {
        this.cka         = cka;
        this.label       = label;
        this.description = description;
    }

    public long   cka()         { return cka; }
    public String label()       { return label; }
    public String description() { return description; }
}
