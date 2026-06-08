package com.yours.hsm.tools;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.key.LunaKey;
import com.yours.hsm.core.KeyAttribute;
import com.yours.hsm.core.KeyManager;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.LunaTokenKeyAccess;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

/**
 * HSM → HSM ML-DSA 개인키 이전 하니스 (slot0 에서 래핑·추출 → slot1 에 언래핑·저장).
 * <p>
 * slot0 은 Extract 모드(파티션 정책 {@code Allow private key wrapping=1} 필요),
 * slot1 은 Cloning 모드({@code Allow private key unwrapping=1})를 가정한다.
 * <p>
 * 래핑에 쓰는 AES KEK 는 <b>외부(소프트웨어)에서 생성</b>해 RSA 봉투로 두 슬롯에 동일하게 주입한다.
 * 같은 값의 KEK 가 양쪽에 있어야 slot0 에서 래핑한 것을 slot1 에서 언래핑할 수 있다.
 * <pre>
 *   [slot0]
 *     1. ML-DSA-65 키쌍 생성 (CKA_EXTRACTABLE=true)
 *     2. 외부 AES-256 KEK 를 RSA 로 봉투화해 slot0 에 주입(+CKA_WRAP)
 *     3. KEK 로 ML-DSA 개인키 래핑(AES-KWP) → 파일로 내보내기
 *   [slot1]
 *     4. 같은 AES KEK 를 RSA 봉투로 slot1 에 주입(+CKA_UNWRAP)
 *     5. KEK 로 래핑 파일을 언래핑 → ML-DSA 개인키 토큰 저장
 *     6. slot1 개인키로 서명 → slot0 공개키(외부 재구성)로 검증
 * </pre>
 * 실행: {@code ./gradlew keyMigrate -Pslot0=0 -Pslot1=1 -Ppin=<핀>}
 */
public final class Hsm2HsmTransferHarness {

    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final String MLDSA_SET     = "ML-DSA-65";
    private static final String HSM_AES_KWP   = "AES/KWP/NoPadding";
    private static final String SW_AES_KWP    = "AESWrapPad";
    private static final String RSA_TRANSPORT = "RSA/ECB/PKCS1Padding";
    private static final Path   LUNA_DIR      = Path.of("C:/Program Files/SafeNet/LunaClient");

    public static void main(String[] args) {
        int    slot0 = Integer.parseInt(System.getProperty("slot0", "0"));
        int    slot1 = Integer.parseInt(System.getProperty("slot1", "1"));
        String pin   = orElse(System.getProperty("pin"), System.getenv("HSM_PIN"));
        if (pin == null || pin.isBlank()) {
            log("PIN이 필요합니다: -Ppin=<핀> 또는 환경변수 HSM_PIN");
            System.exit(2);
            return;
        }

        // 라벨 prefix. 기본은 날짜(yyyyMMdd), -Pbase 로 직접 지정 가능. (시간 미포함)
        String base       = orElse(System.getProperty("base"), DATE.format(LocalDate.now()));
        String mldsaSrc    = base + "_mldsa65_src";   // slot0
        String kekLabel    = base + "_kek";           // 양 슬롯 동일 라벨
        String rsa0Label   = base + "_rsa_s0";
        String rsa1Label   = base + "_rsa_s1";
        String mldsaDst    = base + "_mldsa65_dst";    // slot1
        Path   wrappedFile = LUNA_DIR.resolve(base + "_mldsa65_wrapped.key");
        Path   pubFile     = LUNA_DIR.resolve(base + "_mldsa65_pub.der");

        Provider sun = Security.getProvider("SunJCE");

        log("=== HSM→HSM ML-DSA 이전 (slot %d → slot %d) ===".formatted(slot0, slot1));
        log("라벨 base: " + base);

        LunaSession s0 = null, s1 = null;
        try {
            // 외부 AES KEK 생성 (양 슬롯에 동일 값으로 주입)
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey kek = kg.generateKey();
            log("[*] 외부 AES-256 KEK 생성 (key %d bytes)".formatted(kek.getEncoded().length));

            // ── slot 0 ───────────────────────────────────────
            LunaSlotManager.getInstance().setDefaultSlot(slot0);
            s0 = LunaSession.connect(slot0, pin.toCharArray());
            Provider luna0 = s0.provider();
            KeyManager km0 = new KeyManager(s0);
            LunaTokenKeyAccess acc0 = new LunaTokenKeyAccess(s0);
            log("[0] slot %d 연결 — %s".formatted(slot0, s0.tokenLabel()));

            // 1. ML-DSA-65 생성 (extractable)
            LunaSlotManager.getInstance().setDefaultSlot(slot0);
            KeyPair mldsaPair = km0.generateMlDsa(mldsaSrc, MLDSA_SET, true);
            log("[1] slot%d ML-DSA-65 생성(extractable): %s".formatted(slot0, mldsaSrc));

            // 2. AES KEK 를 slot0 에 주입 (RSA 봉투) + WRAP 속성
            Key hsmKek0 = injectKek(km0, acc0, luna0, sun, kek, rsa0Label, kekLabel, slot0);
            setAttr(acc0, kekLabel, KeyAttribute.WRAP,    true);
            setAttr(acc0, kekLabel, KeyAttribute.ENCRYPT, true);
            log("[2] slot%d KEK 주입(WRAP=true): %s".formatted(slot0, kekLabel));

            // 3. KEK 로 ML-DSA 개인키 래핑 → 파일
            LunaSlotManager.getInstance().setDefaultSlot(slot0);
            Cipher wrap = newKwp(luna0);
            wrap.init(Cipher.WRAP_MODE, (SecretKey) hsmKek0);
            byte[] wrapped = wrap.wrap(mldsaPair.getPrivate());
            Files.createDirectories(LUNA_DIR);
            Files.write(wrappedFile, wrapped);
            Files.write(pubFile, mldsaPair.getPublic().getEncoded());
            log("[3] slot%d 래핑·내보내기: %s (%d bytes)".formatted(
                slot0, wrappedFile.getFileName(), wrapped.length));
            log("    공개키 저장: %s".formatted(pubFile.getFileName()));

            // ── slot 1 ───────────────────────────────────────
            LunaSlotManager.getInstance().setDefaultSlot(slot1);
            s1 = LunaSession.connect(slot1, pin.toCharArray());
            Provider luna1 = s1.provider();
            KeyManager km1 = new KeyManager(s1);
            LunaTokenKeyAccess acc1 = new LunaTokenKeyAccess(s1);
            log("[4] slot %d 연결 — %s".formatted(slot1, s1.tokenLabel()));

            // 4. 같은 AES KEK 를 slot1 에 주입 + UNWRAP 속성
            Key hsmKek1 = injectKek(km1, acc1, luna1, sun, kek, rsa1Label, kekLabel, slot1);
            setAttr(acc1, kekLabel, KeyAttribute.UNWRAP,  true);
            setAttr(acc1, kekLabel, KeyAttribute.DECRYPT, true);
            log("[5] slot%d KEK 주입(UNWRAP=true): %s".formatted(slot1, kekLabel));

            // 5. KEK 로 ML-DSA 언래핑 → 토큰 저장
            LunaSlotManager.getInstance().setDefaultSlot(slot1);
            Cipher unwrap = newKwp(luna1);
            unwrap.init(Cipher.UNWRAP_MODE, (SecretKey) hsmKek1);
            Key recovered = unwrap.unwrap(wrapped, MLDSA_SET, Cipher.PRIVATE_KEY);
            persist(acc1, recovered, mldsaDst);
            log("[6] slot%d 언래핑·저장: %s (class=%s)".formatted(
                slot1, mldsaDst, recovered.getClass().getSimpleName()));

            // 6. 검증: slot1 개인키로 서명 → slot0 공개키(외부 재구성)로 검증
            byte[] msg = ("hsm2hsm transfer " + base).getBytes();
            Signature sgn = Signature.getInstance("ML-DSA", luna1);
            sgn.initSign((PrivateKey) recovered);
            sgn.update(msg);
            byte[] sig = sgn.sign();

            PublicKey swPub = KeyFactory.getInstance(MLDSA_SET)
                .generatePublic(new X509EncodedKeySpec(mldsaPair.getPublic().getEncoded()));
            Signature ver = Signature.getInstance(MLDSA_SET);   // 외부(SunJCE)
            ver.initVerify(swPub);
            ver.update(msg);
            boolean ok = ver.verify(sig);
            log("[7] slot%d 서명 → slot%d 공개키 검증: %s".formatted(
                slot1, slot0, ok ? "성공 ✅" : "실패 ❌"));

            if (!ok) {
                log("=== ❌ 검증 실패: 키는 옮겨졌으나 서명이 일치하지 않음 ===");
                System.exit(1);
            }
            log("=== ✅ HSM→HSM 이전 성공: slot%d:%s → slot%d:%s ===".formatted(
                slot0, mldsaSrc, slot1, mldsaDst));
            log("");
            log("── slot%d 토큰 키 ──".formatted(slot0));
            log("  %s  (ML-DSA-65 원본, extractable)".formatted(mldsaSrc));
            log("  %s  (AES KEK)".formatted(kekLabel));
            log("  %s  (임시 RSA 전송키)".formatted(rsa0Label));
            log("── slot%d 토큰 키 ──".formatted(slot1));
            log("  %s  (이전된 ML-DSA-65 개인키)".formatted(mldsaDst));
            log("  %s  (AES KEK)".formatted(kekLabel));
            log("  %s  (임시 RSA 전송키)".formatted(rsa1Label));
            log("── LunaClient 파일 ──");
            log("  %s  (래핑된 ML-DSA 개인키, AES-KWP)".formatted(wrappedFile));
            log("  %s  (ML-DSA-65 공개키, X.509 DER)".formatted(pubFile));

        } catch (Throwable t) {
            log("=== ❌ 실패: " + t.getMessage());
            t.printStackTrace(System.out);
            System.exit(1);
        } finally {
            if (s0 != null) s0.close();
            if (s1 != null) s1.close();
        }
    }

    /** 외부 AES KEK 를 RSA 봉투(공개키 암호화 → HSM 언래핑)로 해당 슬롯에 주입하고 토큰 저장. */
    private static Key injectKek(KeyManager km, LunaTokenKeyAccess acc, Provider luna, Provider sun,
                                 SecretKey kek, String rsaLabel, String kekLabel, int slot)
        throws Exception {
        KeyPair rsa = km.generateRsa(rsaLabel, 2048);
        // HSM 공개키를 표준 RSAPublicKey 로 재구성해 외부에서 KEK 암호화
        PublicKey swPub = KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(rsa.getPublic().getEncoded()));
        Cipher enc = Cipher.getInstance(RSA_TRANSPORT, sun);
        enc.init(Cipher.ENCRYPT_MODE, swPub);
        byte[] encKek = enc.doFinal(kek.getEncoded());

        LunaSlotManager.getInstance().setDefaultSlot(slot);
        Cipher rsaUnwrap = Cipher.getInstance(RSA_TRANSPORT, luna);
        rsaUnwrap.init(Cipher.UNWRAP_MODE, rsa.getPrivate());
        Key hsmKek = rsaUnwrap.unwrap(encKek, "AES", Cipher.SECRET_KEY);
        persist(acc, hsmKek, kekLabel);
        return hsmKek;
    }

    /** provider 가 AES/KWP/NoPadding 미노출 시 AESWrapPad 폴백. */
    private static Cipher newKwp(Provider p) throws Exception {
        if (p.getService("Cipher", HSM_AES_KWP) != null) return Cipher.getInstance(HSM_AES_KWP, p);
        return Cipher.getInstance(SW_AES_KWP, p);
    }

    private static void persist(LunaTokenKeyAccess acc, Key key, String label) throws Exception {
        if (!(key instanceof LunaKey)) {
            throw new IllegalStateException("LunaKey 가 아니라 토큰 저장 불가: " + key.getClass().getName());
        }
        acc.makePersistent(key, label);
    }

    private static void setAttr(LunaTokenKeyAccess acc, String label, KeyAttribute attr, boolean v) {
        try {
            acc.setAttribute(label, attr, v);
            log("    (set)  %s.%s → %s".formatted(label, attr.name(), v));
        } catch (Exception e) {
            log("    (warn) %s.%s 설정 실패 — %s".formatted(label, attr.name(), e.getMessage()));
        }
    }

    private static String orElse(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    private static void log(String msg) {
        System.out.println(msg);
    }
}
