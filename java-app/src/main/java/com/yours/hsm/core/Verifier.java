package com.yours.hsm.core;

import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.algo.CryptoOpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

public final class Verifier {

    private static final Logger logger = LoggerFactory.getLogger(Verifier.class);

    private final Provider provider;

    /** provider=null 이면 JVM 기본(SunRsaSign 등) 사용 */
    public Verifier(Provider provider) {
        this.provider = provider;
    }

    public boolean verify(AlgoSpec spec, PublicKey pub, byte[] data, byte[] sig)
        throws CryptoOpException {
        try {
            Signature verifier = provider != null
                ? Signature.getInstance(spec.jceName(), provider)
                : Signature.getInstance(spec.jceName());
            verifier.initVerify(pub);
            verifier.update(data);
            boolean ok = verifier.verify(sig);
            logger.debug("서명 검증: algo={} result={}", spec.id(), ok ? "PASS" : "FAIL");
            return ok;
        } catch (Exception e) {
            logger.error("서명 검증 중 예외: algo={}", spec.id(), e);
            throw new CryptoOpException(CryptoOpException.Code.GENERAL,
                "서명 검증 실패: " + e.getMessage(), e);
        }
    }
}
