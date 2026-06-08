package com.yours.hsm.tools;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.key.LunaKey;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.LunaTokenKeyAccess;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * X.509(SubjectPublicKeyInfo) DER 공개키 파일을 HSM 토큰에 import 하여 영구 저장한다.
 * <p>
 * LunaProvider 의 KeyFactory 로 공개키를 토큰 객체(LunaKey)로 만든 뒤 MakePersistent 한다.
 * 실행: {@code ./gradlew importPub -Pslot=1 -Pfile=<pub.der> -Plabel=<라벨> -Ppin=<핀>}
 */
public final class ImportPublicKeyHarness {

    /** 시도할 KeyFactory 알고리즘명 (구체명 우선, 실패 시 family). */
    private static final String[] ALGS = {"ML-DSA-65", "ML-DSA"};

    public static void main(String[] args) {
        int    slot  = Integer.parseInt(System.getProperty("slot", "1"));
        String file  = System.getProperty("file");
        String label = System.getProperty("label");
        String pin   = orElse(System.getProperty("pin"), System.getenv("HSM_PIN"));
        if (file == null || label == null || pin == null || pin.isBlank()) {
            log("필수: -Pfile=<pub.der> -Plabel=<라벨> -Ppin=<핀> [-Pslot=1]");
            System.exit(2);
            return;
        }

        LunaSession s = null;
        try {
            byte[] der = Files.readAllBytes(Path.of(file));
            log("=== ML-DSA 공개키 import (slot %d) ===".formatted(slot));
            log("입력 파일: %s (%d bytes)".formatted(file, der.length));

            LunaSlotManager.getInstance().setDefaultSlot(slot);
            s = LunaSession.connect(slot, pin.toCharArray());
            Provider luna = s.provider();
            LunaTokenKeyAccess access = new LunaTokenKeyAccess(s);
            log("[*] slot %d 연결 — %s".formatted(slot, s.tokenLabel()));

            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            PublicKey pub = null;
            Exception last = null;
            for (String alg : ALGS) {
                try {
                    pub = KeyFactory.getInstance(alg, luna).generatePublic(spec);
                    log("[1] KeyFactory(%s, LunaProvider) 로 공개키 생성: %s".formatted(
                        alg, pub.getClass().getSimpleName()));
                    break;
                } catch (Exception e) {
                    last = e;
                    log("    (%s 실패: %s)".formatted(alg, e.getMessage()));
                }
            }
            if (pub == null) throw new IllegalStateException("공개키 생성 실패", last);

            if (!(pub instanceof LunaKey)) {
                throw new IllegalStateException(
                    "LunaKey 가 아니라 토큰 저장 불가: " + pub.getClass().getName()
                    + " (LunaProvider KeyFactory 가 토큰 객체를 만들지 못함)");
            }
            access.makePersistent(pub, label);
            log("[2] 공개키 토큰 저장 완료: %s".formatted(label));
            log("=== ✅ import 성공 ===");

        } catch (Throwable t) {
            log("=== ❌ 실패: " + t.getMessage());
            t.printStackTrace(System.out);
            System.exit(1);
        } finally {
            if (s != null) s.close();
        }
    }

    private static String orElse(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    private static void log(String msg) {
        System.out.println(msg);
    }
}
