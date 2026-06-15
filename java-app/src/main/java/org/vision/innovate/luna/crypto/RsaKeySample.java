package org.vision.innovate.luna.crypto;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.LunaCertificateX509;
import com.safenetinc.luna.provider.LunaProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;

/**
 * RSA 키쌍 생성 → 자체서명 인증서 → 공개키 추출 샘플.
 */
public class RsaKeySample {

    private static final int    SLOT  = 0;
    private static final String PIN   = "userpin";
    private static final String ALIAS = "sample_rsa_key";
    private static final int    BITS  = 2048;
    private static final String DN    = "CN=sample, O=Vision Innovate, C=KR";
    private static final int    DAYS  = 365;

    // PKCS#11 RSA 공개 속성
    private static final long CKA_MODULUS         = 0x00000120L;
    private static final long CKA_PUBLIC_EXPONENT = 0x00000122L;

    public static void main(String[] args) throws Exception {
        // 0. 로그인
        Provider p = Security.getProvider("LunaProvider");
        if (p == null) { p = new LunaProvider(); Security.addProvider(p); }
        LunaSlotManager sm = LunaSlotManager.getInstance();
        sm.setDefaultSlot(SLOT);
        if (!sm.login(SLOT, PIN)) throw new Exception("login failed: slot " + SLOT);
        KeyStore ks = KeyStore.getInstance("Luna", p);
        ks.load(null, PIN.toCharArray());

        // 1. RSA 키쌍 생성
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", p);
        g.initialize(BITS);
        KeyPair kp = g.generateKeyPair();
        System.out.println("1) RSA 키쌍 생성 (" + BITS + " bits)");

        // 2. 자체서명 인증서 저장 (SHA256withRSA)
        BigInteger sn = new BigInteger(64, new SecureRandom());
        Date nb = new Date();
        Date na = new Date(nb.getTime() + (long) DAYS * 86_400_000L);
        LunaCertificateX509 cert = LunaCertificateX509.SelfSign(
                "SHA256withRSA", kp, DN, sn, nb, na, SLOT);
        ks.setKeyEntry(ALIAS, kp.getPrivate(), null, new LunaCertificateX509[]{ cert });
        System.out.println("2) 자체서명 인증서 저장: alias=" + ALIAS);

        // 3. 공개키 추출 — 세 가지 방법
        // [1] 기본: 인증서에서 그대로
        PublicKey k1 = ks.getCertificate(ALIAS).getPublicKey();

        // [2] 재구성: 기본값이 비면 modulus/exponent 로 다시 만듦
        PublicKey k2 = k1;
        if (k2.getEncoded() == null && k2 instanceof RSAPublicKey r) {
            k2 = rsaPublic(r.getModulus(), r.getPublicExponent());
        }

        // [3] 토큰직접: 토큰의 CKA 값으로 만듦
        LunaTokenObject obj = LunaTokenObject.LocateKeyByAlias(ALIAS, SLOT);
        PublicKey k3 = rsaPublic(
                new BigInteger(1, obj.GetLargeAttribute(CKA_MODULUS)),
                new BigInteger(1, obj.GetLargeAttribute(CKA_PUBLIC_EXPONENT)));

        System.out.println("3) 공개키 추출");
        System.out.println("   [1] 기본     : " + desc(k1));
        System.out.println("   [2] 재구성   : " + desc(k2));
        System.out.println("   [3] 토큰직접 : " + desc(k3));
        System.out.println("   공개키(base64): " + Base64.getEncoder().encodeToString(k2.getEncoded()));

        sm.logout(SLOT);
    }

    private static PublicKey rsaPublic(BigInteger mod, BigInteger exp) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(mod, exp));
    }

    private static String desc(PublicKey k) {
        byte[] e = k.getEncoded();
        return e == null ? "null" : e.length + " bytes";
    }
}
