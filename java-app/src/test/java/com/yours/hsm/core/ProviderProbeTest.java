package com.yours.hsm.core;

import com.yours.hsm.algo.AlgoCatalog;
import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.mock.MockProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ProviderProbeTest {

    private ProviderProbe probe;

    @BeforeEach
    void setUp() {
        probe = ProviderProbe.of(new MockProvider());
    }

    @Test
    void supports_knownAlgo_returnsTrue() {
        AlgoSpec spec = AlgoCatalog.findById("RSA_SIGN_SHA256").orElseThrow();
        assertTrue(probe.supports(spec));
    }

    @Test
    void supports_unknownAlgo_returnsFalse() {
        // ML-DSA는 MockProvider에 없음
        AlgoSpec spec = AlgoCatalog.findById("ML_DSA_44").orElseThrow();
        assertFalse(probe.supports(spec));
    }

    @Test
    void filter_phase1_returnsOnlySupported() {
        List<AlgoSpec> supported = probe.filter(AlgoCatalog.phase1());
        // MockProvider는 phase1 11개 중 일부를 지원
        assertFalse(supported.isEmpty());
        // 미지원 항목이 필터된 결과에 없어야 함
        for (AlgoSpec s : supported) {
            assertTrue(probe.supports(s), s.id() + " 는 지원되어야 함");
        }
    }

    @Test
    void filter_allCatalog_noPqcItems() {
        List<AlgoSpec> supported = probe.filter(AlgoCatalog.all());
        // PQC 항목은 MockProvider에 없으므로 필터 결과에 없어야 함
        boolean hasPqc = supported.stream().anyMatch(
            s -> s.family() == AlgoSpec.Family.ML_DSA
              || s.family() == AlgoSpec.Family.ML_KEM);
        assertFalse(hasPqc, "MockProvider는 PQC를 지원하지 않음");
    }

    @Test
    void supports_cipherBaseMatch_returnsTrue() {
        // MockProvider 에 "Cipher.AES/CTR/NoPadding" 은 없지만 base "Cipher.AES" 가 있으므로
        // JCA transformation 합성 규칙대로 가용 판정되어야 함.
        AlgoSpec ctr = AlgoCatalog.findById("AES_CTR").orElseThrow();
        assertTrue(probe.supports(ctr), "base Cipher.AES 매칭으로 AES/CTR 가용");
    }

    @Test
    void jceAlgorithms_notEmpty() {
        assertFalse(probe.jceAlgorithms().isEmpty());
    }
}
