package com.yours.hsm.algo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

public final class SignOp implements CryptoOperation {

    private static final Logger logger = LoggerFactory.getLogger(SignOp.class);

    private final Provider  provider;
    private final AlgoSpec  spec;
    private final PrivateKey privateKey;

    public SignOp(Provider provider, AlgoSpec spec, PrivateKey privateKey) {
        this.provider   = provider;
        this.spec       = spec;
        this.privateKey = privateKey;
    }

    @Override
    public AlgoSpec spec() { return spec; }

    @Override
    public OpResult execute(byte[] input) throws CryptoOpException {
        long start = System.nanoTime();
        try {
            Signature sig = Signature.getInstance(spec.jceName(), provider);
            sig.initSign(privateKey);
            sig.update(input);
            byte[] signature = sig.sign();
            long elapsed = System.nanoTime() - start;
            logger.debug("서명 완료: algo={} elapsed={}ms", spec.id(), elapsed / 1_000_000.0);
            return OpResult.success(elapsed, signature);
        } catch (Exception e) {
            long elapsed = System.nanoTime() - start;
            logger.error("서명 실패: algo={}", spec.id(), e);
            throw new CryptoOpException(CryptoOpException.Code.GENERAL, "서명 실패: " + e.getMessage(), e);
        }
    }
}
