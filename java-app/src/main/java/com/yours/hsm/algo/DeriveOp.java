package com.yours.hsm.algo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * 키 합의(Key Agreement) 기반 공유 비밀 도출 — ECDH / DiffieHellman / XDH.
 * <p>
 * {@code execute(input)} 의 입력은 사용하지 않는다(상대방 공개키로 도출).
 * 결과 {@code output} 은 도출된 공유 비밀 바이트열.
 */
public final class DeriveOp implements CryptoOperation {

    private static final Logger logger = LoggerFactory.getLogger(DeriveOp.class);

    private final Provider   provider;
    private final AlgoSpec   spec;
    private final PrivateKey ownPrivate;
    private final PublicKey  peerPublic;

    public DeriveOp(Provider provider, AlgoSpec spec, PrivateKey ownPrivate, PublicKey peerPublic) {
        this.provider   = provider;
        this.spec       = spec;
        this.ownPrivate = ownPrivate;
        this.peerPublic = peerPublic;
    }

    @Override
    public AlgoSpec spec() { return spec; }

    @Override
    public OpResult execute(byte[] input) throws CryptoOpException {
        long start = System.nanoTime();
        try {
            KeyAgreement ka = KeyAgreement.getInstance(spec.jceName(), provider);
            ka.init(ownPrivate);
            ka.doPhase(peerPublic, true);
            byte[] shared = ka.generateSecret();
            long elapsed = System.nanoTime() - start;
            logger.debug("키 합의 완료: algo={} sharedLen={} elapsed={}ms",
                spec.id(), shared.length, elapsed / 1_000_000.0);
            return OpResult.success(elapsed, shared);
        } catch (Exception e) {
            long elapsed = System.nanoTime() - start;
            logger.error("키 합의 실패: algo={}", spec.id(), e);
            throw new CryptoOpException(CryptoOpException.Code.GENERAL, "키 합의 실패: " + e.getMessage(), e);
        }
    }
}
