package org.vision.innovate.luna.crypto;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.LunaCertificateX509;
import com.safenetinc.luna.provider.LunaProvider;
import com.safenetinc.luna.provider.key.LunaKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Signature;

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
 * Luna HSM RSA 키 샘플.
 *  1) 키쌍 생성 + 자체서명 인증서 저장
 *  2) 공개키 / 개인키 조회
 *  3) 인증서 내보내기
 *  4) 공개키 내보내기
 */
public class LunaRsaKeyLifecycle {

    private static final Logger log = LoggerFactory.getLogger(LunaRsaKeyLifecycle.class);

    private static final int    SLOT  = 0;
    private static final String PIN   = "userpin";   // CO 패스워드
    private static final String LABEL = "KEY_ALIAS"; // 키 라벨
    private static final int    BITS  = 2048;
    private static final String DN    = "CN=test, O=test, C=kr";
    private static final int    DAYS  = 365;

    // RSA 공개 속성 (PKCS#11)
    private static final long CKA_MODULUS         = 0x00000120L;
    private static final long CKA_PUBLIC_EXPONENT = 0x00000122L;

    private final KeyStore keyStore;
    private final Provider provider;

    public LunaRsaKeyLifecycle(KeyStore keyStore, Provider provider) {
        this.keyStore = keyStore;
        this.provider = provider;
    }

    /** HSM 로그인 */
    public static LunaRsaKeyLifecycle hsmConnect(int slot, String pin) throws Exception {
        Provider lunaProvider = Security.getProvider("LunaProvider");
        if (lunaProvider == null) {
            lunaProvider = new LunaProvider();
            Security.addProvider(lunaProvider);
        }
        LunaSlotManager slotManager = LunaSlotManager.getInstance();
        slotManager.setDefaultSlot(slot);
        if (!slotManager.login(slot, pin)) throw new Exception("HSM login failed: slot " + slot);
        KeyStore keyStore = KeyStore.getInstance("Luna", lunaProvider);
        keyStore.load(null, pin.toCharArray());
        log.info("slot {} login", slot);
        return new LunaRsaKeyLifecycle(keyStore, lunaProvider);
    }

    /** RSA 키쌍 생성 + 자체서명 인증서 저장 (현재 ~ +days 유효) */
    public KeyPair generate(String alias, int bits, String subjectDn, int days) throws Exception {
        Date startDate = new Date();
        Date endDate   = new Date(startDate.getTime() + (long) days * 86_400_000L);
        return generate(alias, bits, subjectDn, startDate, endDate);
    }

    /** RSA 키쌍 생성 + 자체서명 인증서 저장 (유효기간 직접 지정) */
    public KeyPair generate(String alias, int bits, String subjectDn,
                            Date startDate, Date endDate) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
        keyPairGenerator.initialize(bits);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        int slot = LunaSlotManager.getInstance().getDefaultSlot();

        // 자체서명 인증서 (SHA256withRSA 로 서명)
        LunaCertificateX509[] certChain = { LunaCertificateX509.SelfSign(
                "SHA256withRSA", keyPair, subjectDn, serialNumber, startDate, endDate, slot) };

        // 개인키 + 인증서를 토큰에 함께 저장
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), null, certChain);
        log.info("saved: alias={}, notBefore={}, notAfter={}", alias, startDate, endDate);
        return keyPair;
    }

    public boolean contains(String alias) throws Exception {
        return keyStore.containsAlias(alias);
    }

    public X509Certificate certificate(String alias) throws Exception {
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    /**
     * 기존 키는 그대로 두고 인증서만 새 유효기간으로 재발급(재서명) 후 교체.
     * (인증서 날짜는 서명 대상이라 기존 인증서의 날짜를 직접 못 고친다 → 같은 키로 새로 서명)
     */
    public void reissueCert(String alias, String subjectDn, Date startDate, Date endDate) throws Exception {
        PublicKey  publicKey  = publicKey(alias);
        PrivateKey privateKey = privateKey(alias);
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        int slot = LunaSlotManager.getInstance().getDefaultSlot();
        LunaCertificateX509[] certChain = { LunaCertificateX509.SelfSign(
                "SHA256withRSA", keyPair, subjectDn, serialNumber, startDate, endDate, slot) };

        keyStore.setKeyEntry(alias, privateKey, null, certChain);  // 같은 키, 인증서만 교체
        log.info("재발급: alias={}, {} ~ {}", alias, startDate, endDate);
    }

    /** 인증서 유효기간 검사 (현재 시각 기준) */
    public boolean checkValidity(String alias) throws Exception {
        return checkValidityAt(alias, new Date());
    }

    /** 인증서 유효기간 검사 (지정 시각 기준) — 유효하면 true, 만료/미발효면 false */
    public boolean checkValidityAt(String alias, Date when) throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        if (cert == null) throw new Exception("no cert: " + alias);
        try {
            cert.checkValidity(when);
            log.info("유효: 검사시각={} (유효기간 {} ~ {})", when, cert.getNotBefore(), cert.getNotAfter());
            return true;
        } catch (java.security.cert.CertificateExpiredException e) {
            log.warn("만료됨: 검사시각={} > notAfter={}", when, cert.getNotAfter());
            return false;
        } catch (java.security.cert.CertificateNotYetValidException e) {
            log.warn("아직 유효 전: 검사시각={} < notBefore={}", when, cert.getNotBefore());
            return false;
        }
    }

    /**
     * 기존 키/인증서로 유효기간 테스트.
     * [1] 현재 시각 → 유효 → 서명·검증 동작
     * [2] 만료 후 시점 → 만료 → 사용 차단
     * (토큰의 인증서는 건드리지 않고 검사 기준 시각만 바꿔서 두 경우를 보여줌)
     */
    public void validityTest(String alias) throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        if (cert == null) throw new Exception("no cert: " + alias + " (먼저 키를 생성하세요)");
        log.info("기존 인증서 사용: alias={}, 유효기간 {} ~ {}",
                alias, cert.getNotBefore(), cert.getNotAfter());

        log.info("=== [1] 현재 시각 (유효 기대) ===");
        if (checkValidity(alias)) {
            log.info("  -> 사용 가능, sign/verify = {}", signVerifyTest(alias) ? "성공" : "실패");
        } else {
            log.info("  -> 이미 만료되어 사용 불가");
        }

        Date afterExpiry = new Date(cert.getNotAfter().getTime() + 86_400_000L); // notAfter + 1일
        log.info("=== [2] 만료 후 시점 (만료 기대) ===");
        if (!checkValidityAt(alias, afterExpiry)) {
            log.info("  -> 사용 차단 (만료된 인증서)");
        } else {
            log.info("  -> 예상과 다름: 여전히 유효");
        }
    }

    /** 공개키 조회 (기본: 인증서에서 그대로) */
    public PublicKey publicKeyBasic(String alias) throws Exception {
        Certificate cert = keyStore.getCertificate(alias);
        if (cert == null) throw new Exception("no cert: " + alias);
        return cert.getPublicKey();
    }

    /**
     * 공개키 조회 (자동).
     * 1) 인증서에서 그대로 → 2) 값이 비면 modulus/exponent 로 재구성 → 3) 그래도 안 되면 토큰에서 직접.
     * (구버전 Luna 10.5 는 인증서의 공개키가 null 이라 토큰 직접 경로로 동작)
     */
    public PublicKey publicKey(String alias) throws Exception {
        try {
            PublicKey publicKey = publicKeyBasic(alias);
            if (publicKey != null && publicKey.getEncoded() != null) return publicKey;
            if (publicKey instanceof RSAPublicKey rsaKey) {
                return buildRsaPublicKey(rsaKey.getModulus(), rsaKey.getPublicExponent());
            }
        } catch (Exception ignore) {
            // 인증서 경로 실패 → 토큰 직접
        }
        return publicKeyFromToken(alias);
    }

    /** 공개키 조회 (토큰의 CKA 값으로 직접 재구성) */
    public PublicKey publicKeyFromToken(String alias) throws Exception {
        int slot = LunaSlotManager.getInstance().getDefaultSlot();
        LunaTokenObject tokenObject = LunaTokenObject.LocateKeyByAlias(alias, slot);
        if (tokenObject == null) throw new Exception("no token object: " + alias);
        BigInteger modulus  = new BigInteger(1, tokenObject.GetLargeAttribute(CKA_MODULUS));
        BigInteger exponent = new BigInteger(1, tokenObject.GetLargeAttribute(CKA_PUBLIC_EXPONENT));
        return buildRsaPublicKey(modulus, exponent);
    }

    private static PublicKey buildRsaPublicKey(BigInteger modulus, BigInteger exponent) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    /** 공개키 세 가지 방법 비교 */
    public void diagnosePublicKey(String alias) throws Exception {
        byte[] basicDer  = encodedOf(() -> publicKeyBasic(alias));
        byte[] rebuiltDer = encodedOf(() -> publicKey(alias));
        byte[] tokenDer  = encodedOf(() -> publicKeyFromToken(alias));

        log.info("[1] 기본      : {}", describe(basicDer));
        log.info("[2] 재구성    : {}", describe(rebuiltDer));
        log.info("[3] 토큰직접  : {}", describe(tokenDer));

        byte[] reference = rebuiltDer != null ? rebuiltDer : tokenDer;
        log.info("[결과] 1={} 2={} 3={}{}",
                status(basicDer), status(rebuiltDer), status(tokenDer),
                reference == null ? "" : " | 일치: 1=" + matches(basicDer, reference)
                        + " 2=" + matches(rebuiltDer, reference) + " 3=" + matches(tokenDer, reference));
    }

    private interface KeySupplier { PublicKey get() throws Exception; }
    private static byte[] encodedOf(KeySupplier supplier) {
        try { return supplier.get().getEncoded(); } catch (Exception e) { return null; }
    }
    private static String describe(byte[] der) { return der == null ? "null (실패)" : der.length + " bytes"; }
    private static String status(byte[] der)   { return der == null ? "실패" : "성공"; }
    private static boolean matches(byte[] a, byte[] b) { return a != null && Arrays.equals(a, b); }

    /**
     * 개인키 조회 (자동).
     * 1) KeyStore.getKey → 2) null 이면 토큰에서 직접.
     * (구버전 Luna 10.5 는 getKey 가 null 이라 토큰 직접 경로로 동작)
     */
    public PrivateKey privateKey(String alias) throws Exception {
        try {
            PrivateKey key = (PrivateKey) keyStore.getKey(alias, null);
            if (key != null) return key;
        } catch (Exception ignore) {
            // getKey 실패 → 토큰 직접
        }
        return privateKeyFromToken(alias);
    }

    /**
     * 개인키 조회 (토큰 직접).
     * 개인키는 비밀값이라 "재구성"이 불가하다. 대신 토큰의 개인키 객체를 핸들로 가져온다.
     * 이 핸들로 서명/복호화하면 연산은 HSM 내부에서 수행되고 키 값은 밖으로 나오지 않는다.
     */
    public PrivateKey privateKeyFromToken(String alias) throws Exception {
        int slot = LunaSlotManager.getInstance().getDefaultSlot();
        LunaKey key = LunaKey.LocateKeyByAlias(alias, slot);
        if (key instanceof PrivateKey privateKey) return privateKey;
        throw new Exception("no private key on token: " + alias);
    }

    /** 개인키(서명)·공개키(검증) 동작 확인 — 두 키가 실제로 쓸 수 있는지 검증 */
    public boolean signVerifyTest(String alias) throws Exception {
        byte[] data = "vision sign test".getBytes();
        Signature signer = Signature.getInstance("SHA256withRSA", provider);
        signer.initSign(privateKey(alias));
        signer.update(data);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA", provider);
        verifier.initVerify(publicKey(alias));
        verifier.update(data);
        return verifier.verify(signature);
    }

    /** 인증서 내보내기 (.pem 이면 PEM, 그 외 DER) */
    public void exportCert(String alias, String file) throws Exception {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        writeFile(file, cert.getEncoded(), "CERTIFICATE");
        log.info("cert exported: {}", file);
    }

    /** 공개키 내보내기 (.pem 이면 PEM, 그 외 DER) */
    public void exportPublicKey(String alias, String file) throws Exception {
        writeFile(file, publicKey(alias).getEncoded(), "PUBLIC KEY");
        log.info("public key exported: {}", file);
    }

    private static void writeFile(String file, byte[] der, String pemType) throws Exception {
        byte[] content = file.toLowerCase().endsWith(".pem") ? toPem(pemType, der) : der;
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(content);
        }
    }

    private static byte[] toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return ("-----BEGIN " + type + "-----\n" + base64
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
        log.info("sign/verify = {}", hsm.signVerifyTest(label) ? "성공" : "실패");
        hsm.exportCert(label, label + ".crt");
        hsm.exportPublicKey(label, label + "_pub.der");
    }
}
