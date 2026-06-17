package org.vision.innovate.luna.crypto;

/**
 * 인증서 유효기간 테스트 — 기존에 생성한 키/인증서를 사용.
 * 실행: -Dslot, -Dpin, -Dlabel(기존 키 라벨)
 *  [1] 현재 시각   → 유효 → 서명·검증 동작
 *  [2] 만료 후 시점 → 만료 → 사용 차단
 */
public class CertValidityTest {

    public static void main(String[] args) throws Exception {
        int    slot  = Integer.getInteger("slot", 0);
        String pin   = System.getProperty("pin", "userpin");
        String label = System.getProperty("label", "KEY_ALIAS");

        LunaRsaKeyLifecycle hsm = LunaRsaKeyLifecycle.hsmConnect(slot, pin);

        // 기존 키/인증서 사용 (없으면 안내)
        if (!hsm.contains(label)) {
            throw new Exception("기존 키가 없습니다: " + label
                    + "  (먼저 ./vision rsatest 또는 rsaLifecycle 로 생성하세요)");
        }
        hsm.validityTest(label);
    }
}
