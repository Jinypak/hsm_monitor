package com.yours.hsm.tools;

import com.safenetinc.luna.LunaSlotManager;
import com.yours.hsm.core.KeyAttribute;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.KeyManager;
import com.yours.hsm.core.KeyUnwrapper;
import com.yours.hsm.core.KeyWrapper;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.WrapMetadata;

import java.nio.file.Path;
import java.security.Key;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import java.util.List;

/**
 * slot 0 → slot 1 키 이전(transfer) CLI 하니스. (HA 풀고 단일 멤버 대상)
 * <p>
 * 절차:
 *   1. slot 0 에서 ML-DSA-65 키쌍 생성 (라벨: transfer_mldsa_src_&lt;ts&gt;)
 *   2. slot 0 의 기존 AES KEK 로 개인키 래핑 → LunaClient 폴더에 .key + .meta.json 내보내기
 *   3. slot 1 의 동일 KEK 로 언래핑 → slot 1 토큰에 저장 (라벨: transfer_mldsa_dst_&lt;ts&gt;)
 *   4. 양 슬롯 키 목록 출력으로 결과 확인
 * <p>
 * 실행:
 *   ./gradlew keyTransfer -Pslot0=0 -Pslot1=1 -PkekLabel=&lt;기존AES라벨&gt;
 * PIN 은 환경변수 HSM_PIN0 / HSM_PIN1 에서 읽는다(미설정 시 HSM_PIN 공용).
 */
public final class KeyTransferHarness {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    public static void main(String[] args) {
        Args a = Args.parse(args);

        // KEK 라벨 미지정 시: slot0/slot1 키 목록만 출력하고 종료 (KEK 라벨 찾기용)
        if (a.kekLabel == null || a.kekLabel.isBlank()) {
            listOnly(a);
            return;
        }

        String ts       = TS.format(LocalDateTime.now());
        String srcAlias = "transfer_mldsa_src_" + ts;
        String dstAlias = "transfer_mldsa_dst_" + ts;
        Path   lunaDir  = Path.of(a.lunaDir);

        log("=== 키 이전 테스트 시작 ===");
        log("slot0=%d  slot1=%d  KEK라벨=%s".formatted(a.slot0, a.slot1, a.kekLabel));
        log("대상 알고리즘=ML-DSA-65  srcAlias=%s  dstAlias=%s".formatted(srcAlias, dstAlias));

        LunaSession s0 = null, s1 = null;
        try {
            // ── 1. slot 0 연결 + ML-DSA 키 생성 ───────────────
            LunaSlotManager.getInstance().setDefaultSlot(a.slot0);
            s0 = LunaSession.connect(a.slot0, a.pin0.toCharArray());
            log("[1] slot %d 연결됨 — 토큰: %s".formatted(a.slot0, s0.tokenLabel()));

            LunaSlotManager.getInstance().setDefaultSlot(a.slot0);
            KeyManager km0 = new KeyManager(s0);
            // 래핑(추출) 대상이므로 생성 시점에 CKA_EXTRACTABLE=true 로 만든다.
            // (생성 후 false→true 변경은 PKCS#11 상 불가 → CKR_ATTRIBUTE_VALUE_INVALID)
            km0.generateMlDsa(srcAlias, "ML-DSA-65", true);
            log("[1] slot %d 에 ML-DSA-65 생성(extractable): %s".formatted(a.slot0, srcAlias));

            KeyCatalog cat0 = new KeyCatalog(s0);
            KeyCatalog.KeyEntry kek0 = requireEntry(cat0, a.kekLabel, "slot0 KEK");
            KeyCatalog.KeyEntry src  = requireEntry(cat0, srcAlias, "slot0 ML-DSA");
            log("[1] KEK 확인: %s / 대상 확인: %s".formatted(kek0, src));

            // ── 1b. 진단 + 속성 설정 (CKR_KEY_NOT_WRAPPABLE 대응) ──
            LunaSlotManager.getInstance().setDefaultSlot(a.slot0);
            log("[1b] 속성 진단:");
            dumpAttrs(km0, a.kekLabel, "    KEK ");
            dumpAttrs(km0, srcAlias,   "    SRC ");

            ensureAttr(km0, a.kekLabel, KeyAttribute.WRAP,        true);  // KEK 로 래핑 가능하게
            // 대상 키 EXTRACTABLE 은 생성 시점에 이미 true 로 박았다(사후 변경 불가). 여기선 진단만.
            log("[1b] 속성 설정 후:");
            dumpAttrs(km0, a.kekLabel, "    KEK ");
            dumpAttrs(km0, srcAlias,   "    SRC ");

            // ── 2. 래핑 + 내보내기 ────────────────────────────
            LunaSlotManager.getInstance().setDefaultSlot(a.slot0);
            KeyWrapper wrapper = new KeyWrapper(s0);
            byte[] wrapped = wrapper.wrap(kek0, src);
            WrapMetadata meta = wrapper.metadataFor(kek0, src);
            Path keyFile = wrapper.export(wrapped, meta, lunaDir);
            log("[2] 래핑 완료 (%d bytes) → 내보냄: %s".formatted(wrapped.length, keyFile));
            log("[2] 메타데이터: algo=%s type=%s".formatted(meta.algorithm(), meta.keyType()));

            // ── 3. slot 1 연결 + 언래핑 + 저장 ────────────────
            LunaSlotManager.getInstance().setDefaultSlot(a.slot1);
            s1 = LunaSession.connect(a.slot1, a.pin1.toCharArray());
            log("[3] slot %d 연결됨 — 토큰: %s".formatted(a.slot1, s1.tokenLabel()));

            KeyCatalog cat1 = new KeyCatalog(s1);
            KeyCatalog.KeyEntry kek1 = requireEntry(cat1, a.kekLabel, "slot1 KEK");
            log("[3] slot1 KEK 확인: %s".formatted(kek1));

            // ── 3b. slot 1 KEK UNWRAP 속성 확인 ──────────────
            // slot 0 의 WRAP 과 달리 slot 1 의 UNWRAP 은 별도로 체크해야 한다.
            KeyManager km1 = new KeyManager(s1);
            log("[3b] slot1 KEK 속성 진단:");
            dumpAttrs(km1, a.kekLabel, "    KEK1 ");
            ensureAttr(km1, a.kekLabel, KeyAttribute.UNWRAP, true);
            log("[3b] 속성 설정 후:");
            dumpAttrs(km1, a.kekLabel, "    KEK1 ");

            LunaSlotManager.getInstance().setDefaultSlot(a.slot1);
            Key recovered = new KeyUnwrapper(s1).unwrapAndStore(kek1, keyFile, dstAlias);
            log("[3] 언래핑·저장 완료: algo=%s class=%s → %s".formatted(
                recovered.getAlgorithm(), recovered.getClass().getSimpleName(), dstAlias));

            // ── 4. 결과 확인 ──────────────────────────────────
            log("[4] slot %d 키 목록:".formatted(a.slot1));
            for (KeyCatalog.KeyEntry e : cat1.list()) {
                if (e.alias().contains("transfer_mldsa") || e.alias().equals(a.kekLabel)) {
                    log("      - " + e);
                }
            }
            log("=== ✅ 키 이전 성공: slot %d:%s → slot %d:%s ===".formatted(
                a.slot0, srcAlias, a.slot1, dstAlias));

        } catch (Throwable t) {
            log("=== ❌ 실패: " + t.getMessage());
            t.printStackTrace(System.out);
            System.exit(1);
        } finally {
            if (s0 != null) s0.close();
            if (s1 != null) s1.close();
        }
    }

    /** KEK 라벨 탐색용 — 양 슬롯의 키 목록만 출력. */
    private static void listOnly(Args a) {
        for (int slot : new int[]{a.slot0, a.slot1}) {
            String pin = slot == a.slot0 ? a.pin0 : a.pin1;
            LunaSession s = null;
            try {
                LunaSlotManager.getInstance().setDefaultSlot(slot);
                s = LunaSession.connect(slot, pin.toCharArray());
                log("=== slot %d (%s) 키 목록 ===".formatted(slot, s.tokenLabel()));
                for (KeyCatalog.KeyEntry e : new KeyCatalog(s).list()) {
                    log("   " + e);
                }
            } catch (Throwable t) {
                log("slot %d 조회 실패: %s".formatted(slot, t.getMessage()));
            } finally {
                if (s != null) s.close();
            }
        }
        log("→ AES SECRET 키 라벨을 -PkekLabel=<라벨> 로 지정해 다시 실행하세요.");
    }

    /** 키의 주요 boolean 속성을 한 줄로 출력. */
    private static void dumpAttrs(KeyManager km, String alias, String prefix) {
        try {
            var m = km.attributes(alias);
            StringBuilder sb = new StringBuilder(prefix).append(alias).append(": ");
            for (KeyAttribute at : new KeyAttribute[]{
                    KeyAttribute.WRAP, KeyAttribute.UNWRAP, KeyAttribute.EXTRACTABLE,
                    KeyAttribute.ENCRYPT, KeyAttribute.DECRYPT, KeyAttribute.SIGN}) {
                if (m.containsKey(at)) sb.append(at.name()).append('=').append(m.get(at)).append(' ');
            }
            log(sb.toString());
        } catch (Exception e) {
            log(prefix + alias + ": 속성 조회 실패 — " + e.getMessage());
        }
    }

    /** 속성이 목표값과 다르면 설정 시도(실패해도 진단 메시지만 남기고 계속). */
    private static void ensureAttr(KeyManager km, String alias, KeyAttribute attr, boolean want) {
        try {
            var m = km.attributes(alias);
            if (!m.containsKey(attr)) { log("    (skip) %s 에 %s 속성 없음".formatted(alias, attr.name())); return; }
            if (Boolean.valueOf(want).equals(m.get(attr))) { log("    (ok)   %s.%s 이미 %s".formatted(alias, attr.name(), want)); return; }
            km.setAttribute(alias, attr, want);
            log("    (set)  %s.%s → %s".formatted(alias, attr.name(), want));
        } catch (Exception e) {
            log("    (fail) %s.%s 설정 실패 — %s".formatted(alias, attr.name(), e.getMessage()));
        }
    }

    private static KeyCatalog.KeyEntry requireEntry(KeyCatalog cat, String alias, String what)
        throws Exception {
        List<KeyCatalog.KeyEntry> all = cat.list();
        return all.stream().filter(e -> e.alias().equals(alias)).findFirst().orElseThrow(() ->
            new IllegalStateException(what + " 키를 찾을 수 없습니다: " + alias
                + " (존재하는 라벨: " + all.stream().map(KeyCatalog.KeyEntry::alias).toList() + ")"));
    }

    private static void log(String msg) {
        System.out.println(msg);
    }

    /** 실행 인자/환경변수 파싱. */
    private record Args(int slot0, int slot1, String kekLabel, String pin0, String pin1, String lunaDir) {
        static Args parse(String[] argv) {
            int slot0 = Integer.parseInt(prop("slot0", "0"));
            int slot1 = Integer.parseInt(prop("slot1", "1"));
            String kek = prop("kekLabel", System.getenv("HSM_KEK_LABEL"));
            // kek 미지정 시 listOnly 모드로 진행 (여기서 throw 하지 않음)
            String pinCommon = System.getenv("HSM_PIN");
            String pin0 = orElse(System.getenv("HSM_PIN0"), pinCommon);
            String pin1 = orElse(System.getenv("HSM_PIN1"), pinCommon);
            if (pin0 == null || pin1 == null) {
                throw new IllegalArgumentException(
                    "PIN 환경변수가 필요합니다: HSM_PIN0/HSM_PIN1 또는 공용 HSM_PIN");
            }
            String lunaDir = prop("lunaDir",
                orElse(System.getenv("LUNA_CLIENT_DIR"), "C:\\Program Files\\SafeNet\\LunaClient"));
            return new Args(slot0, slot1, kek, pin0, pin1, lunaDir);
        }
        private static String prop(String key, String def) {
            return System.getProperty(key, def);
        }
        private static String orElse(String a, String b) {
            return (a != null && !a.isBlank()) ? a : b;
        }
    }
}
