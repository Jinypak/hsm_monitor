package org.vision.innovate.luna.crypto;

import com.safenetinc.luna.LunaSlotManager;
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
        KeyPair kp = g.generateKeyPair();   // 세션 객체 — 아직 토큰에 저장 안 됨
        System.out.println("[1] RSA keypair generated (" + BITS + " bits)");

        // 2. 자체서명 인증서 — HSM 내부 개인키로 서명
        BigInteger sn = new BigInteger(64, new SecureRandom());
        Date nb = new Date();
        Date na = new Date(nb.getTime() + (long) DAYS * 86_400_000L);
        LunaCertificateX509 cert = LunaCertificateX509.SelfSign(kp, DN, sn, nb, na);
        ks.setKeyEntry(ALIAS, kp.getPrivate(), null, new LunaCertificateX509[]{ cert });
        System.out.println("[2] self-signed cert stored: alias=" + ALIAS + ", serial=" + sn);

        // 3. 공개키 추출 (인증서에서). 토큰 공개키는 getEncoded() 가 null 일 수 있어 재구성.
        PublicKey pub = ks.getCertificate(ALIAS).getPublicKey();
        if (pub.getEncoded() == null && pub instanceof RSAPublicKey r) {
            pub = KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(r.getModulus(), r.getPublicExponent()));
        }
        System.out.println("[3] public key (" + pub.getAlgorithm() + ", X.509 DER base64):");
        System.out.println(Base64.getEncoder().encodeToString(pub.getEncoded()));

        sm.logout(SLOT);
    }
}
