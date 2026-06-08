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
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

/**
 * 외부(소프트웨어)에서 만든 ML-DSA 개인키를 AES(DEK)로 래핑한 뒤, 그 DEK 를 HSM 에 주입하고
 * HSM 안에서 ML-DSA 개인키를 언래핑해 토큰에 저장하는 import 방향 시연 하니스.
 * <p>
 * 배경: 슬롯 정책 {@code Allow private key wrapping=0} 으로 HSM 키의 <b>추출(export)</b>은 막혀 있다.
 * 하지만 {@code Allow private/secret key unwrapping=1} 이라 <b>주입(import/unwrap)</b>은 허용된다.
 * 이 하니스는 허용된 방향만 사용해, 외부 생성 PQC 키를 HSM 으로 들여올 수 있는지 검증한다.
 * <p>
 * 절차:
 * <pre>
 *   [외부/SunJCE]
 *     1. ML-DSA-65 키쌍 + AES-256 DEK 생성
 *     2. wrappedMldsa = AES-KWP_wrap(DEK, mldsaPrivate)          (소프트웨어 래핑)
 *   [HSM]
 *     3. 임시 RSA-2048 키쌍 생성(공개키를 외부 암호화에 사용)
 *     4. encDek = RSA_encrypt(rsaPub, DEK)                        (외부에서 DEK 암호화)
 *     5. hsmDek = RSA_unwrap(rsaPriv, encDek)  → DEK 를 HSM 토큰에 주입, UNWRAP 속성 부여
 *     6. hsmMldsaPriv = AES-KWP_unwrap(hsmDek, wrappedMldsa)      → ML-DSA 개인키 HSM 토큰에 저장
 *     7. HSM 개인키로 서명 → 외부 공개키로 검증
 * </pre>
 * 실행: {@code ./gradlew keyImport -Pslot=1}  (PIN 은 HSM_PIN 환경변수)
 */
public final class ExternalKeyImportHarness {

    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final String MLDSA_SET = "ML-DSA-65";
    /** SunJCE 의 AES-KWP 메커니즘명(=RFC 5649). HSM 도 동일 메커니즘으로 언래핑한다. */
    private static final String SW_AES_KWP    = "AESWrapPad";
    private static final String HSM_AES_KWP   = "AES/KWP/NoPadding";
    /** DEK 전송용 RSA 패딩. */
    private static final String RSA_TRANSPORT = "RSA/ECB/PKCS1Padding";
    /** 래핑 파일 저장 디렉터리 */
    private static final Path LUNA_DIR = Path.of("C:/Program Files/SafeNet/LunaClient");

    public static void main(String[] args) {
        int    slot = Integer.parseInt(System.getProperty("slot", "1"));
        // -Ppin=... (커맨드라인) 우선, 없으면 환경변수 폴백
        String pin = orElse(System.getProperty("pin"),
                     orElse(System.getenv("HSM_PIN0"), System.getenv("HSM_PIN")));
        if (pin == null || pin.isBlank()) {
            log("PIN이 필요합니다: -Ppin=<핀> 또는 환경변수 HSM_PIN");
            System.exit(2);
            return;
        }
        // 날짜 기반 네이밍 — 같은 날 중복이면 숫자 접미사로 구분
        String date = DATE.format(LocalDate.now());

        // HSM 토큰 라벨: <날짜>_<알고리즘>_<역할>
        String rsaLabel   = date + "_rsa2048_transport";
        String dekLabel   = date + "_aes256_dek";
        String mldsaLabel = date + "_mldsa65_priv";

        // LunaClient 저장 파일: <날짜>_<알고리즘>_<형태>.<ext>
        Path wrappedKeyFile = LUNA_DIR.resolve(date + "_mldsa65_wrapped.key");
        Path pubKeyFile     = LUNA_DIR.resolve(date + "_mldsa65_pub.der");
        Path encDekFile     = LUNA_DIR.resolve(date + "_aes256_dek_enc.bin");

        Provider sun = Security.getProvider("SunJCE");

        log("=== 외부 ML-DSA → HSM import 테스트 시작 (slot %d) ===".formatted(slot));
        log("HSM 토큰 라벨: rsa=%s  dek=%s  mldsa=%s".formatted(rsaLabel, dekLabel, mldsaLabel));
        log("저장 파일: %s  %s  %s".formatted(
            wrappedKeyFile.getFileName(), pubKeyFile.getFileName(), encDekFile.getFileName()));

        LunaSession s = null;
        try {
            // ── 1~2. 외부(소프트웨어)에서 ML-DSA 키쌍/DEK 생성 + AES-KWP 래핑 ──
            KeyPair mldsa = KeyPairGenerator.getInstance(MLDSA_SET).generateKeyPair();
            log("[1] 외부 ML-DSA-65 키쌍 생성 (pub %d bytes)".formatted(mldsa.getPublic().getEncoded().length));

            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey dek = kg.generateKey();
            log("[1] 외부 AES-256 DEK 생성 (key %d bytes)".formatted(dek.getEncoded().length));

            Cipher swWrap = Cipher.getInstance(SW_AES_KWP, sun);
            swWrap.init(Cipher.WRAP_MODE, dek);
            byte[] wrappedMldsa = swWrap.wrap(mldsa.getPrivate());
            log("[2] 외부 래핑 완료: AES-KWP(DEK, ML-DSA priv) = %d bytes".formatted(wrappedMldsa.length));

            // ── 파일로 내보내기 (래핑된 개인키 / 공개키 / 암호화전 DEK 파일은 단계5에서 저장) ──
            Files.createDirectories(LUNA_DIR);
            Files.write(wrappedKeyFile, wrappedMldsa);
            Files.write(pubKeyFile, mldsa.getPublic().getEncoded());
            log("[2] 파일 저장: %s (%d bytes)".formatted(wrappedKeyFile.getFileName(), wrappedMldsa.length));
            log("[2] 파일 저장: %s (%d bytes)".formatted(pubKeyFile.getFileName(), mldsa.getPublic().getEncoded().length));

            // ── HSM 연결 ──
            LunaSlotManager.getInstance().setDefaultSlot(slot);
            s = LunaSession.connect(slot, pin.toCharArray());
            log("[*] slot %d 연결 — 토큰: %s".formatted(slot, s.tokenLabel()));
            Provider luna = s.provider();
            KeyManager km = new KeyManager(s);
            LunaTokenKeyAccess access = new LunaTokenKeyAccess(s);

            // ── 3. HSM 임시 RSA 키쌍 (공개키 확보) ──
            LunaSlotManager.getInstance().setDefaultSlot(slot);
            KeyPair rsa = km.generateRsa(rsaLabel, 2048);
            log("[3] HSM 임시 RSA-2048 생성: %s".formatted(rsaLabel));

            // HSM 공개키를 표준 RSAPublicKey 로 재구성해 외부 암호화에 사용
            PublicKey swRsaPub = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(rsa.getPublic().getEncoded()));

            // ── 4. 외부에서 DEK 를 RSA 로 암호화 + 파일 저장 ──
            Cipher rsaEnc = Cipher.getInstance(RSA_TRANSPORT, sun);
            rsaEnc.init(Cipher.ENCRYPT_MODE, swRsaPub);
            byte[] encDek = rsaEnc.doFinal(dek.getEncoded());
            Files.write(encDekFile, encDek);
            log("[4] 외부 RSA 암호화: enc(DEK) = %d bytes".formatted(encDek.length));
            log("[4] 파일 저장: %s (%d bytes)".formatted(encDekFile.getFileName(), encDek.length));

            // ── 5. HSM 에서 RSA 언래핑 → DEK 주입 + UNWRAP 속성 부여 ──
            LunaSlotManager.getInstance().setDefaultSlot(slot);
            Cipher rsaUnwrap = Cipher.getInstance(RSA_TRANSPORT, luna);
            rsaUnwrap.init(Cipher.UNWRAP_MODE, rsa.getPrivate());
            Key hsmDek = rsaUnwrap.unwrap(encDek, "AES", Cipher.SECRET_KEY);
            log("[5] HSM DEK 주입 완료: class=%s".formatted(hsmDek.getClass().getSimpleName()));

            persist(access, hsmDek, dekLabel);
            log("[5] DEK 토큰 저장: %s".formatted(dekLabel));
            // 언래핑 키로 쓰려면 CKA_UNWRAP=true 필요 (사용 플래그라 사후 변경 가능)
            trySetAttr(access, dekLabel, KeyAttribute.UNWRAP,  true);
            trySetAttr(access, dekLabel, KeyAttribute.DECRYPT, true);

            // ── 6. HSM 에서 DEK 로 ML-DSA 언래핑 → 토큰 저장 ──
            LunaSlotManager.getInstance().setDefaultSlot(slot);
            SecretKey dekForUnwrap = (SecretKey) hsmDek;
            Cipher kwpUnwrap = newAesKwp(luna);
            kwpUnwrap.init(Cipher.UNWRAP_MODE, dekForUnwrap);
            Key hsmMldsaPriv = kwpUnwrap.unwrap(wrappedMldsa, MLDSA_SET, Cipher.PRIVATE_KEY);
            log("[6] HSM ML-DSA 언래핑 완료: algo=%s class=%s".formatted(
                hsmMldsaPriv.getAlgorithm(), hsmMldsaPriv.getClass().getSimpleName()));

            persist(access, hsmMldsaPriv, mldsaLabel);
            log("[6] ML-DSA 개인키 토큰 저장: %s".formatted(mldsaLabel));

            // ── 7. 검증: HSM 개인키로 서명 → 외부 공개키로 검증 ──
            byte[] msg = "external mldsa imported into hsm".getBytes();
            Signature sign = Signature.getInstance("ML-DSA", luna);
            sign.initSign((PrivateKey) hsmMldsaPriv);
            sign.update(msg);
            byte[] sig = sign.sign();

            Signature verify = Signature.getInstance("ML-DSA");           // 외부(SunJCE) 검증
            verify.initVerify(mldsa.getPublic());
            verify.update(msg);
            boolean ok = verify.verify(sig);
            log("[7] HSM 서명 → 외부 공개키 검증: %s".formatted(ok ? "성공 ✅" : "실패 ❌"));

            if (ok) {
                log("=== ✅ import 성공: 외부 ML-DSA 개인키가 HSM(%s)에 저장되어 동작함 ===".formatted(mldsaLabel));
                log("");
                log("── 생성된 HSM 토큰 키 ──────────────────────────");
                log("  %s  (임시: DEK 전송용 RSA)".formatted(rsaLabel));
                log("  %s  (임시: AES-256 DEK)".formatted(dekLabel));
                log("  %s  (보존: 가져온 ML-DSA-65 개인키)".formatted(mldsaLabel));
                log("── 생성된 LunaClient 파일 ──────────────────────");
                log("  %s  (래핑된 ML-DSA 개인키, AES-KWP)".formatted(wrappedKeyFile));
                log("  %s  (ML-DSA-65 공개키, X.509 DER)".formatted(pubKeyFile));
                log("  %s  (RSA로 암호화된 DEK)".formatted(encDekFile));
            } else {
                log("=== ❌ 검증 실패: 키는 들어갔으나 서명 검증이 안 됨 ===");
                System.exit(1);
            }

        } catch (Throwable t) {
            log("=== ❌ 실패: " + t.getMessage());
            t.printStackTrace(System.out);
            System.exit(1);
        } finally {
            if (s != null) s.close();
        }
    }

    /** 카탈로그 기본 AES-KWP 이름이 provider 에 없으면 폴백명으로 Cipher 생성. */
    private static Cipher newAesKwp(Provider p) throws Exception {
        if (p.getService("Cipher", HSM_AES_KWP) != null) return Cipher.getInstance(HSM_AES_KWP, p);
        return Cipher.getInstance(SW_AES_KWP, p);
    }

    private static void persist(LunaTokenKeyAccess access, Key key, String label) throws Exception {
        if (!(key instanceof LunaKey)) {
            throw new IllegalStateException("LunaKey 가 아니라 토큰 저장 불가: " + key.getClass().getName());
        }
        access.makePersistent(key, label);
    }

    private static void trySetAttr(LunaTokenKeyAccess access, String label, KeyAttribute attr, boolean v) {
        try {
            access.setAttribute(label, attr, v);
            log("    (set)  %s.%s → %s".formatted(label, attr.name(), v));
        } catch (Exception e) {
            log("    (warn) %s.%s 설정 실패(계속 진행) — %s".formatted(label, attr.name(), e.getMessage()));
        }
    }

    private static String orElse(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    private static void log(String msg) {
        System.out.println(msg);
    }
}
