package org.vision.innovate.luna.crypto;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.LunaCertificateX509;
import com.safenetinc.luna.provider.LunaProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

/**
 * Luna HSM RSA 키 생성 샘플.
 1) RSA 키쌍 생성
 2) 공개키/개인키 조회 
 3) 인증서 내보내기 
 4) 공개키 내보내기 
 */
public class LunaRsaKeyLifecycle {

    private static final Logger log = LoggerFactory.getLogger(LunaRsaKeyLifecycle.class);

    private static final int    SLOT  = 0;
    private static final String PIN   = "userpin"; // CO 패스워드        
    private static final String LABEL = "KEY_ALIAS"; // 키 라벨
    private static final int    BITS  = 2048;
    private static final String DN    = "CN=test, O=test, C=kr";
    private static final int    DAYS  = 365;

    // PKCS#11 RSA 공개 속성
    private static final long CKA_MODULUS         = 0x00000120L;
    private static final long CKA_PUBLIC_EXPONENT = 0x00000122L;

    private final KeyStore ks;
    private final Provider p;

    public LunaRsaKeyLifecycle(KeyStore ks, Provider p) {
        this.ks = ks;
        this.p  = p;
    }

    /** HSM 로그인 */
    public static LunaRsaKeyLifecycle hsmConnect(int slot, String pin) throws Exception {
        Provider luna = Security.getProvider("LunaProvider");
        if (luna == null) {
            luna = new LunaProvider();
            Security.addProvider(luna);
        }
        LunaSlotManager sm = LunaSlotManager.getInstance();
        sm.setDefaultSlot(slot);
        if (!sm.login(slot, pin)) throw new Exception("HSM login failed: slot " + slot);
        KeyStore ks = KeyStore.getInstance("Luna", luna);
        ks.load(null, pin.toCharArray());
        log.info("slot {} login", slot);
        return new LunaRsaKeyLifecycle(ks, luna);
    }

    /** RSA 키쌍 생성 */
    public KeyPair generate(String alias, int bits, String dn, int days) throws Exception {
        KeyPairGenerator generateKey = KeyPairGenerator.getInstance("RSA", p);
        generateKey.initialize(bits);
        KeyPair keyPairRSA = generateKey.generateKeyPair(); // 키 생성

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + (long) days * 86_400_000L);
        int slot = LunaSlotManager.getInstance().getDefaultSlot();
        LunaCertificateX509[] chain = { LunaCertificateX509.SelfSign(
                "SHA256withRSA", keyPairRSA, dn, serialNumber, startDate, endDate, slot) };

        ks.setKeyEntry(alias, keyPairRSA.getPrivate(), null, chain);  // 개인키 + 인증서 토큰 저장
        log.info("saved: alias={}, serial={}, notAfter={}", alias, serialNumber, endDate);
        return keyPairRSA;
    }

    // 공개키 
    public PublicKey publicKeyRaw(String alias) throws Exception {
        Certificate c = ks.getCertificate(alias);
        if (c == null) throw new Exception("no cert: " + alias);
        return c.getPublicKey();
    }

    // 공개키 조회 (기본 조회 후 값이 비어 있으면 modulus/exponent 로 재구성)
    public PublicKey publicKey(String alias) throws Exception {
        PublicKey pub = publicKeyRaw(alias);
        if (pub.getEncoded() == null && pub instanceof RSAPublicKey r) {
            return rsaPublic(r.getModulus(), r.getPublicExponent());
        }
        return pub;
    }

    // 공개키 조회 (PKCS#11 — 토큰 객체의 CKA_MODULUS/CKA_PUBLIC_EXPONENT 직접 읽기)
    public PublicKey publicKeyFromToken(String alias) throws Exception {
        int slot = LunaSlotManager.getInstance().getDefaultSlot();
        LunaTokenObject obj = LunaTokenObject.LocateKeyByAlias(alias, slot);
        if (obj == null) throw new Exception("no token object: " + alias);
        BigInteger mod = new BigInteger(1, obj.GetLargeAttribute(CKA_MODULUS));
        BigInteger exp = new BigInteger(1, obj.GetLargeAttribute(CKA_PUBLIC_EXPONENT));
        return rsaPublic(mod, exp);
    }

    private static PublicKey rsaPublic(BigInteger mod, BigInteger exp) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(mod, exp));
    }

    /** 공개키 세 가지 방법 비교 */
    public void diagnosePublicKey(String alias) throws Exception {
        byte[] r1 = enc(() -> publicKeyRaw(alias));
        byte[] r2 = enc(() -> publicKey(alias));
        byte[] r3 = enc(() -> publicKeyFromToken(alias));

        log.info("[1] 기본      : {}", desc(r1));
        log.info("[2] 재구성    : {}", desc(r2));
        log.info("[3] 토큰직접  : {}", desc(r3));

        byte[] ref = r2 != null ? r2 : r3;                 // 유효한 값 기준 비교
        log.info("[결과] 1={} 2={} 3={}{}",
                ok(r1), ok(r2), ok(r3),
                ref == null ? "" : " | 일치: 1=" + same(r1, ref)
                        + " 2=" + same(r2, ref) + " 3=" + same(r3, ref));
    }

    private interface Sup { PublicKey get() throws Exception; }
    private static byte[] enc(Sup s) {
        try { return s.get().getEncoded(); } catch (Exception e) { return null; }
    }
    private static String desc(byte[] b) { return b == null ? "null ← 실패" : b.length + " bytes"; }
    private static String ok(byte[] b)   { return b == null ? "NULL" : "OK"; }
    private static boolean same(byte[] a, byte[] b) { return a != null && Arrays.equals(a, b); }

    // 개인키 조회
    public PrivateKey privateKey(String alias) throws Exception {
        return (PrivateKey) ks.getKey(alias, null);
    }

    // 인증서 내보내기
    public void exportCert(String alias, String file) throws Exception {
        X509Certificate c = (X509Certificate) ks.getCertificate(alias);
        write(file, c.getEncoded(), "CERTIFICATE");
        log.info("cert exported: {}", file);
    }

    // 공개키 내보내기
    public void exportPublicKey(String alias, String file) throws Exception {
        write(file, publicKey(alias).getEncoded(), "PUBLIC KEY");
        log.info("public key exported: {}", file);
    }

    private static void write(String file, byte[] der, String type) throws Exception {
        byte[] out = file.toLowerCase().endsWith(".pem") ? pem(type, der) : der;
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(out);
        }
    }

    private static byte[] pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return ("-----BEGIN " + type + "-----\n" + b64
              + "\n-----END " + type + "-----\n").getBytes();
    }

    public static void main(String[] args) throws Exception {
        
        int    slot  = Integer.getInteger("slot", SLOT);
        String pin   = System.getProperty("pin", PIN);
        String label = System.getProperty("label", LABEL);

        LunaRsaKeyLifecycle hsm = hsmConnect(slot, pin);
        hsm.generate(label, BITS, DN, DAYS);
        hsm.diagnosePublicKey(label);   
        log.info("public  = {}", hsm.publicKey(label).getAlgorithm());
        log.info("private = {}", hsm.privateKey(label).getAlgorithm());
        hsm.exportCert(label, label + ".crt");
        hsm.exportPublicKey(label, label + "_pub.der");
    }
}
