package com.yours.hsm.algo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 대칭/비대칭 암복호화 — 블록암호 전 모드 + RSA.
 * <p>
 * 모드는 JCE transformation(예: {@code AES/CTR/NoPadding})에서 파싱하며,
 * IV 길이는 {@link Cipher#getBlockSize()} 로 결정한다(AES/ARIA/SM4=16, DESede=8).
 * <ul>
 *   <li>RSA(OAEP/PKCS/raw) — IV 없음</li>
 *   <li>ECB / 스트림(RC4 등) — IV 없음</li>
 *   <li>GCM — 12B IV + 128bit tag</li>
 *   <li>CBC/CTR/CFB/OFB/XTS — 블록크기 IV</li>
 * </ul>
 * IV 처리: ENCRYPT_MODE + iv=null 일 때 IV를 자동 생성하여 출력 앞에 붙이고,
 * DECRYPT_MODE + iv=null 일 때 입력 앞에서 IV를 추출 후 복호화한다.
 * (iv를 직접 지정하면 지정값 사용)
 */
public final class EncryptOp implements CryptoOperation {

    private static final Logger logger = LoggerFactory.getLogger(EncryptOp.class);
    private static final int GCM_IV_LEN = 12;

    private final Provider provider;
    private final AlgoSpec spec;
    private final Key      key;
    private final int      mode;
    private final byte[]   iv;   // null = auto

    public EncryptOp(Provider provider, AlgoSpec spec, Key key, int mode, byte[] iv) {
        this.provider = provider;
        this.spec     = spec;
        this.key      = key;
        this.mode     = mode;
        this.iv       = iv;
    }

    @Override
    public AlgoSpec spec() { return spec; }

    @Override
    public OpResult execute(byte[] input) throws CryptoOpException {
        long start = System.nanoTime();
        try {
            Cipher cipher = Cipher.getInstance(spec.jceName(), provider);
            String chainMode = parseMode(spec.jceName());
            byte[] result;

            if (spec.family() == AlgoSpec.Family.RSA || chainMode == null
                || "ECB".equals(chainMode)) {
                // RSA(OAEP/PKCS/raw), ECB, 스트림(RC4 등) — IV 없음
                cipher.init(mode, key);
                result = cipher.doFinal(input);
            } else if ("GCM".equals(chainMode)) {
                result = handleGcm(cipher, input);
            } else {
                // CBC/CTR/CFB/OFB/XTS — 블록크기 IV 사용
                result = handleIv(cipher, input, cipher.getBlockSize());
            }

            long elapsed = System.nanoTime() - start;
            logger.debug("암복호화 완료: algo={} mode={} elapsed={}ms",
                spec.id(), mode == Cipher.ENCRYPT_MODE ? "ENC" : "DEC", elapsed / 1_000_000.0);
            return OpResult.success(elapsed, result);

        } catch (Exception e) {
            long elapsed = System.nanoTime() - start;
            logger.error("암복호화 실패: algo={}", spec.id(), e);
            throw new CryptoOpException(CryptoOpException.Code.GENERAL,
                "암복호화 실패: " + e.getMessage(), e);
        }
    }

    private byte[] handleGcm(Cipher cipher, byte[] input) throws Exception {
        if (mode == Cipher.ENCRYPT_MODE) {
            byte[] actualIv = iv != null ? iv : randomBytes(GCM_IV_LEN);
            cipher.init(mode, key, new GCMParameterSpec(128, actualIv));
            byte[] ct = cipher.doFinal(input);
            // prepend IV: [12B iv][ciphertext]
            byte[] out = new byte[GCM_IV_LEN + ct.length];
            System.arraycopy(actualIv, 0, out, 0, GCM_IV_LEN);
            System.arraycopy(ct, 0, out, GCM_IV_LEN, ct.length);
            return out;
        } else {
            if (iv != null) {
                cipher.init(mode, key, new GCMParameterSpec(128, iv));
                return cipher.doFinal(input);
            }
            // extract IV from head
            byte[] actualIv = Arrays.copyOf(input, GCM_IV_LEN);
            byte[] ct       = Arrays.copyOfRange(input, GCM_IV_LEN, input.length);
            cipher.init(mode, key, new GCMParameterSpec(128, actualIv));
            return cipher.doFinal(ct);
        }
    }

    /** CBC/CTR/CFB/OFB/XTS 공통 — {@code ivLen} 길이 IV를 앞에 붙이거나 추출한다. */
    private byte[] handleIv(Cipher cipher, byte[] input, int ivLen) throws Exception {
        if (ivLen <= 0) ivLen = 16; // 안전망 (getBlockSize()=0 인 경우)
        if (mode == Cipher.ENCRYPT_MODE) {
            byte[] actualIv = iv != null ? iv : randomBytes(ivLen);
            cipher.init(mode, key, new IvParameterSpec(actualIv));
            byte[] ct = cipher.doFinal(input);
            byte[] out = new byte[actualIv.length + ct.length];
            System.arraycopy(actualIv, 0, out, 0, actualIv.length);
            System.arraycopy(ct, 0, out, actualIv.length, ct.length);
            return out;
        } else {
            if (iv != null) {
                cipher.init(mode, key, new IvParameterSpec(iv));
                return cipher.doFinal(input);
            }
            byte[] actualIv = Arrays.copyOf(input, ivLen);
            byte[] ct       = Arrays.copyOfRange(input, ivLen, input.length);
            cipher.init(mode, key, new IvParameterSpec(actualIv));
            return cipher.doFinal(ct);
        }
    }

    /** transformation 의 체이닝 모드 토큰을 반환("AES/CTR/NoPadding"→"CTR"). 모드 없으면 null. */
    private static String parseMode(String transformation) {
        String[] parts = transformation.split("/");
        return parts.length >= 2 ? parts[1] : null;
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }
}
