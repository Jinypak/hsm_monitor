package com.yours.hsm.ui;

import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.algo.AlgoSpec.Family;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.ProviderProbe;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * 연산 탭 공용 — 연산 콤보에 노출할 메커니즘을 결정한다.
 * <p>
 * <b>Tier A(표준 family)</b>는 항상 노출한다. LunaProvider 의 Cipher/Signature 등록명이
 * 카탈로그 jceName 표기와 달라 {@link ProviderProbe} 정확매칭이 빗나가도(예: RSA-OAEP)
 * 사용자가 표준 알고리즘을 못 쓰는 일이 없게 한다 — 실제 미지원이면 실행 시 오류로 드러난다.
 * <p>
 * <b>Tier B(PQC·SM·도메인 특화)</b>만 Provider 가 실제로 노출할 때 표시한다
 * (펌웨어 업그레이드 시 자동 등장). 세션이 null 이면 전체 후보를 보여준다.
 */
final class MechanismAvailability {

    private MechanismAvailability() {}

    /** 항상 노출하는 표준 family(Tier A). */
    private static final Set<Family> CORE = EnumSet.of(
        Family.RSA, Family.AES, Family.EC, Family.EDDSA, Family.MONTGOMERY,
        Family.DSA, Family.DH, Family.ARIA, Family.DES3, Family.DES,
        Family.HMAC, Family.DIGEST, Family.KDF);

    static List<AlgoSpec> filter(LunaSession session, List<AlgoSpec> candidates) {
        if (session == null) return candidates;
        try {
            ProviderProbe probe = ProviderProbe.of(session.provider());
            return candidates.stream()
                .filter(s -> CORE.contains(s.family()) || probe.supports(s))
                .toList();
        } catch (Exception e) {
            return candidates;
        }
    }
}
