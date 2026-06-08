package com.yours.hsm.core;

import com.yours.hsm.algo.AlgoSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public final class ProviderProbe {

    private static final Logger logger = LoggerFactory.getLogger(ProviderProbe.class);

    private final Set<String> jceAlgorithms;

    private ProviderProbe(Set<String> jceAlgorithms) {
        this.jceAlgorithms = jceAlgorithms;
    }

    public static ProviderProbe of(Provider provider) {
        Set<String> algos = provider.getServices().stream()
            .map(svc -> svc.getType() + "." + svc.getAlgorithm())
            .collect(Collectors.toUnmodifiableSet());
        logger.info("ProviderProbe: {} 서비스 탐지 from {}", algos.size(), provider.getName());
        return new ProviderProbe(algos);
    }

    public Set<String> jceAlgorithms() {
        return jceAlgorithms;
    }

    public boolean supports(AlgoSpec spec) {
        String type = serviceType(spec.op());
        if (type == null) return false;
        String key = type + "." + spec.jceName();
        if (jceAlgorithms.contains(key)) return true;

        // Cipher 는 JCA 가 base 알고리즘에서 transformation 을 합성한다.
        // 예: provider 가 "Cipher.RSA" 만 등록해도 "RSA/ECB/OAEP..." 사용 가능.
        // → base("AES","RSA","ARIA"...)로도 매칭해 과도하게 걸러내지 않는다.
        if ("Cipher".equals(type)) {
            int slash = spec.jceName().indexOf('/');
            if (slash > 0) {
                String base = type + "." + spec.jceName().substring(0, slash);
                if (jceAlgorithms.contains(base)) return true;
            }
        }
        logger.debug("미지원 알고리즘: {}", key);
        return false;
    }

    public List<AlgoSpec> filter(Collection<AlgoSpec> candidates) {
        return candidates.stream()
            .filter(this::supports)
            .toList();
    }

    private static String serviceType(AlgoSpec.Op op) {
        return switch (op) {
            case SIGN, VERIFY -> "Signature";
            case ENC, DEC     -> "Cipher";
            case WRAP, UNWRAP -> "Cipher";
            case MAC          -> "Mac";
            case KEYGEN       -> "KeyGenerator";
            case KEYPAIR_GEN  -> "KeyPairGenerator";
            case DIGEST       -> "MessageDigest";
            case DERIVE       -> "KeyAgreement";     // ECDH / DiffieHellman / XDH
            case KDF          -> "SecretKeyFactory"; // PBKDF2 등
            default           -> null;               // PARAM_GEN 등 가용성 판정 제외
        };
    }
}
