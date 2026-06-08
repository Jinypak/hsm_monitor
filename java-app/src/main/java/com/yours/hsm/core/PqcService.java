package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.util.Arrays;

/**
 * PQC(양자내성암호) 연산 — ML-DSA/SLH-DSA 서명, ML-KEM 키 캡슐화.
 * <p>
 * JDK 25 는 ML-KEM(JEP 496)·ML-DSA(JEP 497)를 표준 Provider 로 제공한다.
 * {@code provider=null} 이면 JCA 기본(소프트웨어, 펌웨어 PQC 미지원 HSM에서도 시연 가능),
 * {@code provider=LunaProvider} 이면 HSM 경로로 동작한다(펌웨어가 PQC 를 노출할 때).
 * <p>JavaFX 미사용 — CLI/테스트에서도 쓸 수 있다.
 */
public final class PqcService {

    private static final Logger logger = LoggerFactory.getLogger(PqcService.class);

    /** null = JCA 기본 Provider(소프트웨어). */
    private final Provider provider;

    public PqcService(Provider provider) {
        this.provider = provider;
    }

    /** ML-DSA-65 / ML-KEM-768 / SLH-DSA-... 등 파라미터셋 이름으로 키쌍 생성. */
    public KeyPair generateKeyPair(String paramSet) throws CryptoOpException {
        try {
            KeyPairGenerator kpg = provider == null
                ? KeyPairGenerator.getInstance(paramSet)
                : KeyPairGenerator.getInstance(paramSet, provider);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoOpException(Code.MECH_NOT_SUPPORTED,
                paramSet + " 미지원 — Provider 가 노출하지 않습니다" + providerNote(), e);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, paramSet + " 키쌍 생성 실패: " + e.getMessage(), e);
        }
    }

    public record SignResult(byte[] signature, boolean verified, long signNs, long verifyNs) {
        public double signMs()   { return signNs   / 1_000_000.0; }
        public double verifyMs() { return verifyNs / 1_000_000.0; }
    }

    /**
     * 서명(개인키) → 검증(공개키) 라운드트립. 서명 알고리즘은 키의 algorithm("ML-DSA"/"SLH-DSA")에서 얻는다.
     */
    public SignResult signVerify(KeyPair kp, byte[] message) throws CryptoOpException {
        // Provider 마다 키 algorithm 이 "ML-DSA" 또는 "ML-DSA-65" 로 다르므로 base 로 정규화
        String algo = baseAlgo(kp.getPublic().getAlgorithm());
        try {
            Signature signer = sig(algo);
            long s0 = System.nanoTime();
            signer.initSign(kp.getPrivate());
            signer.update(message);
            byte[] sig = signer.sign();
            long signNs = System.nanoTime() - s0;

            Signature verifier = sig(algo);
            long v0 = System.nanoTime();
            verifier.initVerify(kp.getPublic());
            verifier.update(message);
            boolean ok = verifier.verify(sig);
            long verifyNs = System.nanoTime() - v0;

            logger.info("PQC 서명/검증: algo={} sigLen={} verified={}", algo, sig.length, ok);
            return new SignResult(sig, ok, signNs, verifyNs);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, algo + " 서명/검증 실패: " + e.getMessage(), e);
        }
    }

    public record KemResult(byte[] encapsulation, byte[] fingerprintA, byte[] fingerprintB,
                            boolean match, long encNs, long decNs) {
        public double encMs() { return encNs / 1_000_000.0; }
        public double decMs() { return decNs / 1_000_000.0; }
    }

    /**
     * 캡슐화(공개키) → 디캡슐화(개인키) 라운드트립. 두 공유비밀이 일치하면 성공.
     * <p>HSM 토큰의 공유비밀은 추출 불가(getEncoded 가 핸들 반환)이므로, 비밀 바이트를
     * 직접 비교하지 않고 각 비밀로 <b>HMAC-SHA256 지문</b>을 (같은 Provider에서) 계산해 비교한다.
     * 비밀이 같으면 지문도 같다. 소프트웨어 Provider 에서도 동일하게 동작한다.
     */
    public KemResult kemRoundtrip(KeyPair kp) throws CryptoOpException {
        // KEM 서비스는 base 이름("ML-KEM")으로 등록됨 — 키 algorithm 이 "ML-KEM-768" 이어도 정규화
        String algo = baseAlgo(kp.getPublic().getAlgorithm());
        try {
            KEM kem = provider == null ? KEM.getInstance(algo) : KEM.getInstance(algo, provider);

            long e0 = System.nanoTime();
            KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated en = enc.encapsulate();
            long encNs = System.nanoTime() - e0;
            SecretKey a = en.key();
            byte[] ct  = en.encapsulation();

            long d0 = System.nanoTime();
            KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());
            SecretKey b = dec.decapsulate(ct);
            long decNs = System.nanoTime() - d0;

            byte[] fpA = fingerprint(a);
            byte[] fpB = fingerprint(b);
            boolean match = Arrays.equals(fpA, fpB);
            logger.info("PQC KEM: algo={} ctLen={} match={}", algo, ct.length, match);
            return new KemResult(ct, fpA, fpB, match, encNs, decNs);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, algo + " KEM 실패: " + e.getMessage(), e);
        }
    }

    /** 공유비밀 SecretKey 의 HMAC-SHA256 지문 — 토큰 키(추출 불가)도 HSM에서 계산 가능. */
    private byte[] fingerprint(SecretKey secret) throws Exception {
        javax.crypto.Mac mac = provider == null
            ? javax.crypto.Mac.getInstance("HmacSHA256")
            : javax.crypto.Mac.getInstance("HmacSHA256", provider);
        mac.init(secret);
        return mac.doFinal("ML-KEM shared-secret fingerprint".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private Signature sig(String algo) throws NoSuchAlgorithmException {
        return provider == null ? Signature.getInstance(algo) : Signature.getInstance(algo, provider);
    }

    /** 파라미터 포함 이름을 family base 로 정규화 (ML-DSA-65→ML-DSA, ML-KEM-768→ML-KEM). */
    private static String baseAlgo(String algo) {
        if (algo == null) return null;
        if (algo.startsWith("ML-DSA"))  return "ML-DSA";
        if (algo.startsWith("ML-KEM"))  return "ML-KEM";
        if (algo.startsWith("SLH-DSA")) return "SLH-DSA";
        return algo;
    }

    private String providerNote() {
        return provider == null ? " (소프트웨어/JDK)" : " (" + provider.getName() + ")";
    }
}
