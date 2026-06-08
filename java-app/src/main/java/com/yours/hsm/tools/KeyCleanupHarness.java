package com.yours.hsm.tools;

import com.safenetinc.luna.LunaSlotManager;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.KeyManager;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.LunaTokenKeyAccess;

import java.util.ArrayList;
import java.util.List;

/**
 * 테스트로 생성한 키만 prefix 로 골라 삭제한다. 고객 원본 키는 prefix 가 달라 매칭되지 않으므로 보존된다.
 * <p>
 * 실행: {@code ./gradlew keyCleanup -Pslots=0,1 -Ppin=<핀>}
 * prefix 를 직접 지정하려면 {@code -Pprefixes=hsm2hsm_,import_,...}
 */
public final class KeyCleanupHarness {

    /** 이 세션/이전 테스트들이 만든 키 라벨 prefix (고객 원본과 겹치지 않음). */
    private static final String[] DEFAULT_PREFIXES = {
        "transfer_mldsa", "import_mldsa", "import_tmp", "20260601_", "hsm2hsm_"
    };

    public static void main(String[] args) {
        String pin = orElse(System.getProperty("pin"), System.getenv("HSM_PIN"));
        if (pin == null || pin.isBlank()) {
            log("PIN이 필요합니다: -Ppin=<핀>");
            System.exit(2);
            return;
        }
        int[] slots = parseSlots(System.getProperty("slots", "0,1"));
        String[] prefixes = System.getProperty("prefixes") != null
            ? System.getProperty("prefixes").split(",")
            : DEFAULT_PREFIXES;

        log("=== 테스트 키 정리 ===");
        log("대상 슬롯: %s".formatted(java.util.Arrays.toString(slots)));
        log("삭제 prefix: %s".formatted(String.join(", ", prefixes)));

        int totalDeleted = 0;
        for (int slot : slots) {
            LunaSession s = null;
            try {
                LunaSlotManager.getInstance().setDefaultSlot(slot);
                s = LunaSession.connect(slot, pin.toCharArray());
                log("\n── slot %d (%s) ──".formatted(slot, s.tokenLabel()));
                KeyManager km  = new KeyManager(s);
                KeyCatalog cat = new KeyCatalog(s);
                LunaTokenKeyAccess access = new LunaTokenKeyAccess(s);

                // 라벨 같은 잔여 객체(개인키/공개키/cert)까지 정리하려 여러 번 순회
                int deleted = 0;
                for (int pass = 0; pass < 6; pass++) {
                    List<String> targets = collectTargets(cat, prefixes);
                    if (targets.isEmpty()) break;
                    for (String alias : targets) {
                        if (tryDelete(km, alias)) deleted++;
                        // generateRsa/MlDsa 가 만든 공개키 라벨(-pub)도 함께 정리
                        String pub = alias + KeyManager.PUBLIC_SUFFIX;
                        if (safeExists(access, pub) && tryDelete(km, pub)) deleted++;
                    }
                }
                log("  삭제 완료: %d개".formatted(deleted));
                totalDeleted += deleted;

                log("  남은 키:");
                for (KeyCatalog.KeyEntry e : cat.list()) log("    - " + e);

            } catch (Throwable t) {
                log("  slot %d 처리 실패: %s".formatted(slot, t.getMessage()));
            } finally {
                if (s != null) s.close();
            }
        }
        log("\n=== 총 %d개 삭제 ===".formatted(totalDeleted));
    }

    private static List<String> collectTargets(KeyCatalog cat, String[] prefixes) throws Exception {
        List<String> out = new ArrayList<>();
        for (KeyCatalog.KeyEntry e : cat.list()) {
            String alias = e.alias();
            for (String p : prefixes) {
                if (alias.startsWith(p)) { out.add(alias); break; }
            }
        }
        return out;
    }

    private static boolean tryDelete(KeyManager km, String alias) {
        try {
            km.delete(alias);
            log("    (del) " + alias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean safeExists(LunaTokenKeyAccess access, String alias) {
        try { return access.exists(alias); } catch (Exception e) { return false; }
    }

    private static int[] parseSlots(String csv) {
        String[] parts = csv.split(",");
        int[] r = new int[parts.length];
        for (int i = 0; i < parts.length; i++) r[i] = Integer.parseInt(parts[i].trim());
        return r;
    }

    private static String orElse(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    private static void log(String msg) {
        System.out.println(msg);
    }
}
