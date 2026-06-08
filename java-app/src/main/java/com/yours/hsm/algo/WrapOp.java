package com.yours.hsm.algo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.Provider;

public final class WrapOp implements CryptoOperation {

    private static final Logger logger = LoggerFactory.getLogger(WrapOp.class);

    private final Provider provider;
    private final AlgoSpec spec;
    private final Key      wrappingKey;
    private final Key      keyToWrap;

    public WrapOp(Provider provider, AlgoSpec spec, Key wrappingKey, Key keyToWrap) {
        this.provider    = provider;
        this.spec        = spec;
        this.wrappingKey = wrappingKey;
        this.keyToWrap   = keyToWrap;
    }

    @Override
    public AlgoSpec spec() { return spec; }

    @Override
    public OpResult execute(byte[] input) throws CryptoOpException {
        long start = System.nanoTime();
        try {
            Cipher cipher = Cipher.getInstance(spec.jceName(), provider);
            cipher.init(Cipher.WRAP_MODE, wrappingKey);
            byte[] wrapped = cipher.wrap(keyToWrap);
            long elapsed = System.nanoTime() - start;
            logger.debug("키 래핑 완료: algo={} elapsed={}ms", spec.id(), elapsed / 1_000_000.0);
            return OpResult.success(elapsed, wrapped);
        } catch (Exception e) {
            long elapsed = System.nanoTime() - start;
            logger.error("키 래핑 실패: algo={}", spec.id(), e);
            throw new CryptoOpException(CryptoOpException.Code.GENERAL, "키 래핑 실패: " + e.getMessage(), e);
        }
    }
}
