package com.yours.hsm.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 래핑된 키 파일(.key)에 동반되는 메타데이터(.meta.json).
 * <p>
 * 언래핑 시 키를 어떤 알고리즘·타입으로 복원할지 결정하는 데 필요하다.
 * {@code keyType}은 {@code javax.crypto.Cipher} 의 키 타입 상수명
 * ({@code SECRET_KEY} / {@code PRIVATE_KEY} / {@code PUBLIC_KEY}).
 */
public record WrapMetadata(
    @JsonProperty("algorithm")     String algorithm,     // 언래핑 시 사용할 JCE 알고리즘 (예: AES, RSA, ML-DSA)
    @JsonProperty("keyType")       String keyType,       // SECRET_KEY / PRIVATE_KEY / PUBLIC_KEY
    @JsonProperty("sourceAlias")   String sourceAlias,   // 원본 키 라벨
    @JsonProperty("keyBits")       int    keyBits,       // 원본 키 비트 길이(참고용)
    @JsonProperty("wrapAlias")     String wrapAlias,     // 래핑에 사용한 AES 키 라벨
    @JsonProperty("wrapMechanism") String wrapMechanism, // 래핑 메커니즘 (예: AES_KWP)
    @JsonProperty("wrappedAt")     String wrappedAt      // 래핑 시각(ISO)
) {
    @JsonCreator
    public WrapMetadata {}
}
