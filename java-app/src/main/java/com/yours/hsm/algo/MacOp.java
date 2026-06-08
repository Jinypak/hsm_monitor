package com.yours.hsm.algo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.Provider;

public final class MacOp implements CryptoOperation {

    private static final Logger logger = LoggerFactory.getLogger(MacOp.class);

    private final Provider  provider;
    private final AlgoSpec  spec;
    private final SecretKey key;

    public MacOp(Provider provider, AlgoSpec spec, SecretKey key) {
        this.provider = provider;
        this.spec     = spec;
        this.key      = key;
    }

    @Override
    public AlgoSpec spec() { return spec; }

    @Override
    public OpResult execute(byte[] input) throws CryptoOpException {
        long start = System.nanoTime();
        try {
            Mac mac = Mac.getInstance(spec.jceName(), provider);
            mac.init(key);
            byte[] result = mac.doFinal(input);
            long elapsed = System.nanoTime() - start;
            logger.debug("MAC 완료: algo={} elapsed={}ms", spec.id(), elapsed / 1_000_000.0);
            return OpResult.success(elapsed, result);
        } catch (Exception e) {
            long elapsed = System.nanoTime() - start;
            logger.error("MAC 실패: algo={}", spec.id(), e);
            throw new CryptoOpException(CryptoOpException.Code.GENERAL, "MAC 실패: " + e.getMessage(), e);
        }
    }
}
