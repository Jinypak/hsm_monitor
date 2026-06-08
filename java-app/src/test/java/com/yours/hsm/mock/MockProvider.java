package com.yours.hsm.mock;

import java.security.Provider;
import java.security.Security;

/**
 * LunaProvider 없는 환경에서 사용하는 가짜 JCE Provider.
 * SunRsaSign / SunJCE / SunEC 의 알고리즘 이름만 등록하여
 * ProviderProbe 테스트에 사용한다.
 * 실제 암호 연산은 JVM 기본 Provider에 위임.
 */
public final class MockProvider extends Provider {

    public static final String NAME = "MockHSM";

    public MockProvider() {
        super(NAME, "1.0", "Mock HSM provider for unit tests");

        // Signature
        put("Signature.SHA256withRSA",            "sun.security.rsa.RSASignature$SHA256withRSA");
        put("Signature.SHA256withRSA/PSS",        "sun.security.rsa.RSAPSSSignature");
        put("Signature.SHA384withRSA",            "sun.security.rsa.RSASignature$SHA384withRSA");
        put("Signature.SHA512withRSA",            "sun.security.rsa.RSASignature$SHA512withRSA");

        // Cipher
        put("Cipher.AES/CBC/PKCS5Padding",        "com.sun.crypto.provider.AESCipher$AES128_CBC_P5");
        put("Cipher.AES/GCM/NoPadding",           "com.sun.crypto.provider.GaloisCounterMode$AESGCM");
        put("Cipher.RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                                                  "sun.security.rsa.RSACipher");
        // base Cipher 등록 — JCA 가 transformation 을 합성하는 실제 provider 동작 모사
        // (ProviderProbe 가 base 매칭으로 AES/CTR 등도 가용 판정하는지 검증용)
        put("Cipher.AES",                         "com.sun.crypto.provider.AESCipher");

        // KeyGenerator / KeyPairGenerator
        // 구현 클래스명은 JDK 버전에 따라 바뀌므로(예: RSAKeyPairGenerator$Legacy)
        // 실제 Sun provider 에서 런타임에 가져와 등록 — KeyManager 테스트가 실제 생성까지 수행 가능.
        copyImpl("KeyGenerator.AES",     "SunJCE");
        copyImpl("KeyGenerator.DESede",  "SunJCE");
        copyImpl("KeyPairGenerator.RSA", "SunRsaSign");
        copyImpl("KeyPairGenerator.EC",  "SunEC");

        // Mac
        put("Mac.HmacSHA256",                     "com.sun.crypto.provider.HmacSHA256");

        // KeyAgreement
        copyImpl("KeyAgreement.ECDH",    "SunEC");

        // MessageDigest
        put("MessageDigest.SHA-256",              "sun.security.provider.SHA2$SHA256");
        put("MessageDigest.SHA-512",              "sun.security.provider.SHA5$SHA512");
    }

    /** 지정한 Sun provider 의 서비스 구현 클래스명을 그대로 복사해 등록한다. */
    private void copyImpl(String type, String sunProviderName) {
        Provider sun = Security.getProvider(sunProviderName);
        if (sun == null) return;
        String impl = sun.getProperty(type);
        if (impl != null) put(type, impl);
    }
}
