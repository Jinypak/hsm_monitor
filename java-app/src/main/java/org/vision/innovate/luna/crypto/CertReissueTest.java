package org.vision.innovate.luna.crypto;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * 인증서 유효기간을 "수정해서 사용"할 수 있는지 확인.
 * 인증서 날짜는 서명 대상이라 직접 못 고치고, 같은 키로 재발급(재서명)해야 한다.
 * 기존 키를 사용:
 *  [1] 새 유효기간(미래)으로 재발급 → 유효 → 서명·검증 동작
 *  [2] 만료 기간(과거)으로 재발급   → 만료 → 사용 차단
 */
public class CertReissueTest {

    private static final long DAY = 86_400_000L;

    public static void main(String[] args) throws Exception {
        int    slot  = Integer.getInteger("slot", 0);
        String pin   = System.getProperty("pin", "userpin");
        String label = System.getProperty("label", "KEY_ALIAS");

        LunaRsaKeyLifecycle hsm = LunaRsaKeyLifecycle.hsmConnect(slot, pin);
        if (!hsm.contains(label)) {
            throw new Exception("기존 키가 없습니다: " + label + " (먼저 rsatest 로 생성)");
        }

        X509Certificate before = hsm.certificate(label);
        System.out.println("재발급 전 유효기간: " + before.getNotBefore() + " ~ " + before.getNotAfter());
        Date now = new Date();

        // notBefore 는 시계차를 피해 약간 과거로(백데이트) — 즉시 유효
        System.out.println("=== [1] 유효 기간으로 재발급 (유효 기대) ===");
        hsm.reissueCert(label, "CN=reissued, O=test, C=kr",
                new Date(now.getTime() - DAY), new Date(now.getTime() + 30 * DAY));
        System.out.println("  유효성    = " + hsm.checkValidity(label));
        System.out.println("  sign/verify = " + (hsm.signVerifyTest(label) ? "성공" : "실패"));

        System.out.println("=== [2] 과거(만료) 기간으로 재발급 (만료 기대) ===");
        hsm.reissueCert(label, "CN=reissued, O=test, C=kr",
                new Date(now.getTime() - 30 * DAY), new Date(now.getTime() - DAY));
        boolean valid = hsm.checkValidity(label);
        System.out.println("  유효성    = " + valid + (valid ? "" : "  → 사용 차단"));

        System.out.println("결론: 기존 인증서 날짜 직접 수정은 불가. 같은 키로 재발급(재서명)은 가능.");
    }
}
