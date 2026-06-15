package org.vision.innovate.luna.crypto;

import com.safenetinc.luna.LunaSlotManager;
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

    // 공개키 조회
    public PublicKey publicKey(String alias) throws Exception {
        Certificate c = ks.getCertificate(alias);
        if (c == null) throw new Exception("no cert: " + alias);
        PublicKey pub = c.getPublicKey();
        // Luna 토큰 공개키는 getEncoded() 가 null 일 수 있음 → modulus/exponent 로 표준 키 재구성
        if (pub.getEncoded() == null && pub instanceof RSAPublicKey r) {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(r.getModulus(), r.getPublicExponent()));
        }
        return pub;
    }

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
        // 파라미터
        int    slot  = Integer.getInteger("slot", SLOT);
        String pin   = System.getProperty("pin", PIN);
        String label = System.getProperty("label", LABEL);

        LunaRsaKeyLifecycle hsm = hsmConnect(slot, pin);
        hsm.generate(label, BITS, DN, DAYS);
        log.info("public  = {}", hsm.publicKey(label).getAlgorithm());
        log.info("private = {}", hsm.privateKey(label).getAlgorithm());
        hsm.exportCert(label, label + ".crt");
        hsm.exportPublicKey(label, label + "_pub.der");
    }
}
