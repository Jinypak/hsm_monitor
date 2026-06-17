package org.vision.innovate.luna.crypto;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.LunaCertificateX509;
import com.safenetinc.luna.provider.LunaProvider;
import com.safenetinc.luna.provider.key.LunaKey;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

/**
 * 인증서 재발급 샘플 — 기존 키는 그대로 두고 인증서만 새 유효기간으로 다시 발급.
 * (인증서 날짜는 서명 대상이라 기존 인증서를 직접 수정할 수 없어, 같은 키로 재서명한다.)
 */
public class CertReissueSample {

    private static final int    SLOT  = 0;
    private static final String PIN   = "userpin";   // CO 패스워드
    private static final String ALIAS = "KEY_ALIAS"; // 기존 키 라벨
    private static final int    DAYS  = 365;          // 새 유효기간(일)

    // RSA 공개 속성 (PKCS#11)
    private static final long CKA_MODULUS         = 0x00000120L;
    private static final long CKA_PUBLIC_EXPONENT = 0x00000122L;

    public static void main(String[] args) throws Exception {
        int    slot  = Integer.getInteger("slot", SLOT);
        String pin   = System.getProperty("pin", PIN);
        String alias = System.getProperty("label", ALIAS);
        int    days  = Integer.getInteger("days", DAYS);

        // 0. 로그인
        Provider provider = Security.getProvider("LunaProvider");
        if (provider == null) { provider = new LunaProvider(); Security.addProvider(provider); }
        LunaSlotManager slotManager = LunaSlotManager.getInstance();
        slotManager.setDefaultSlot(slot);
        if (!slotManager.login(slot, pin)) throw new Exception("login failed: slot " + slot);
        KeyStore keyStore = KeyStore.getInstance("Luna", provider);
        keyStore.load(null, pin.toCharArray());

        if (!keyStore.containsAlias(alias)) throw new Exception("기존 키 없음: " + alias);

        // 1. 재발급 전 인증서
        X509Certificate before = (X509Certificate) keyStore.getCertificate(alias);
        String subjectDn = before.getSubjectX500Principal().getName(); // 기존 주체 유지
        System.out.println("재발급 전 : " + before.getNotBefore() + " ~ " + before.getNotAfter());

        // 2. 기존 키 로드 (토큰에서 — 구버전에서도 동작)
        PrivateKey privateKey = (PrivateKey) LunaKey.LocateKeyByAlias(alias, slot);
        LunaTokenObject tokenObject = LunaTokenObject.LocateKeyByAlias(alias, slot);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, tokenObject.GetLargeAttribute(CKA_MODULUS)),
                new BigInteger(1, tokenObject.GetLargeAttribute(CKA_PUBLIC_EXPONENT))));
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        // 3. 새 유효기간으로 인증서 재서명 (notBefore 는 시계차 대비 1분 전)
        Date startDate = new Date(System.currentTimeMillis() - 60_000L);
        Date endDate   = new Date(System.currentTimeMillis() + (long) days * 86_400_000L);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        LunaCertificateX509[] certChain = { LunaCertificateX509.SelfSign(
                "SHA256withRSA", keyPair, subjectDn, serialNumber, startDate, endDate, slot) };

        // 4. 같은 라벨로 교체 저장 (키는 그대로, 인증서만 새것)
        keyStore.setKeyEntry(alias, privateKey, null, certChain);

        // 5. 결과
        X509Certificate after = (X509Certificate) keyStore.getCertificate(alias);
        System.out.println("재발급 후 : " + after.getNotBefore() + " ~ " + after.getNotAfter());
        System.out.println("완료: 키 유지, 인증서만 재발급 (serial=" + serialNumber + ")");

        slotManager.logout(slot);
    }
}
