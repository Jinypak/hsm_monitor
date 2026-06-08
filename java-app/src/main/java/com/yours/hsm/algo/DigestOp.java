package com.yours.hsm.algo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.Provider;

/**
 * 해시(Digest) 연산 — 키 불필요.
 * SHA-1/224/256/384/512, SHA3-*, SM3 등 {@code MessageDigest} 서비스에 위임.
 */
public final class DigestOp implements CryptoOperation {

    private static final Logger logger = LoggerFactory.getLogger(DigestOp.class);

    private final Provider provider;
    private final AlgoSpec spec;

    public DigestOp(Provider provider, AlgoSpec spec) {
        this.provider = provider;
        this.spec     = spec;
    }

    @Override
    public AlgoSpec spec() { return spec; }

    @Override
    public OpResult execute(byte[] input) throws CryptoOpException {
        long start = System.nanoTime();
        try {
            MessageDigest md = MessageDigest.getInstance(spec.jceName(), provider);
            byte[] digest = md.digest(input);
            long elapsed = System.nanoTime() - start;
            logger.debug("해시 완료: algo={} elapsed={}ms", spec.id(), elapsed / 1_000_000.0);
            return OpResult.success(elapsed, digest);
        } catch (Exception e) {
            long elapsed = System.nanoTime() - start;
            logger.error("해시 실패: algo={}", spec.id(), e);
            throw new CryptoOpException(CryptoOpException.Code.GENERAL, "해시 실패: " + e.getMessage(), e);
        }
    }
}
