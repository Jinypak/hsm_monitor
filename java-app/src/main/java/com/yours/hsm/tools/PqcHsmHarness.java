package com.yours.hsm.tools;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.KeyManager;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.PqcService;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

/**
 * 실제 HSM 에 PQC 키를 만들어 서명/검증·캡슐화/디캡슐화를 검증하는 CLI 하니스.
 * <p>실행(사용자가 PIN 과 함께 직접):
 * <pre>./gradlew pqcHsmTest -Pslot=0 -Ppin=YOUR_PIN</pre>
 * 테스트로 만든 키({@code pqc-test-*})는 끝에서 삭제한다.
 */
public final class PqcHsmHarness {

    public static void main(String[] args) {
        int    slot = Integer.parseInt(System.getProperty("slot", "0"));
        String pin  = System.getProperty("pin", "");
        if (pin.isBlank()) {
            System.out.println("[ERROR] -Ppin=<PIN> is required.");
            return;
        }
        long stamp = System.currentTimeMillis() % 100000;
        String dsaAlias = "pqc-test-mldsa-" + stamp;
        String kemAlias = "pqc-test-mlkem-" + stamp;

        System.out.println("=== PQC HSM verification (slot " + slot + ") ===");
        try (LunaSession session = LunaSession.connect(slot, pin.toCharArray())) {
            System.out.println("[OK] connected: " + session.tokenLabel());
            KeyManager mgr  = new KeyManager(session);
            KeyCatalog cat  = new KeyCatalog(session);
            PqcService pqc  = new PqcService(session.provider());

            // ── ML-DSA 서명/검증 (토큰에서 다시 로드한 키쌍 사용) ──
            try {
                System.out.println("\n-- ML-DSA-65 sign/verify --");
                mgr.generateMlDsa(dsaAlias, "ML-DSA-65");
                KeyPair kp = loadPair(cat, dsaAlias);  // 토큰 재조회(LunaKey.LocateKeyByAlias)
                System.out.println("[OK] loaded token key: " + dsaAlias
                    + " (algorithm=" + kp.getPublic().getAlgorithm() + ")");
                byte[] msg = "real HSM PQC test".getBytes(StandardCharsets.UTF_8);
                PqcService.SignResult r = pqc.signVerify(kp, msg);
                System.out.printf("     signature=%dB sign=%.2fms verify=%.2fms verified=%s%n",
                    r.signature().length, r.signMs(), r.verifyMs(), r.verified() ? "PASS" : "FAIL");
            } catch (Exception e) {
                System.out.println("[FAIL] ML-DSA: " + e.getMessage());
            } finally {
                deleteQuietly(mgr, dsaAlias);
                deleteQuietly(mgr, dsaAlias + "-pub");
            }

            // ── ML-KEM 캡슐화/디캡슐화 (토큰에서 다시 로드한 키쌍 사용) ──
            try {
                System.out.println("\n-- ML-KEM-768 encapsulate/decapsulate --");
                mgr.generateMlKem(kemAlias, "ML-KEM-768");
                KeyPair kp = loadPair(cat, kemAlias);  // 토큰 재조회
                System.out.println("[OK] loaded token key: " + kemAlias
                    + " (algorithm=" + kp.getPublic().getAlgorithm() + ")");
                PqcService.KemResult r = pqc.kemRoundtrip(kp);
                System.out.printf("     encapsulation=%dB enc=%.2fms dec=%.2fms match=%s (HMAC fingerprint)%n",
                    r.encapsulation().length, r.encMs(), r.decMs(),
                    r.match() ? "PASS" : "FAIL");
            } catch (Exception e) {
                System.out.println("[FAIL] ML-KEM: " + e.getMessage());
            } finally {
                deleteQuietly(mgr, kemAlias);
                deleteQuietly(mgr, kemAlias + "-pub");
            }

            System.out.println("\n=== done (test keys cleaned up) ===");
        } catch (CryptoOpException e) {
            System.out.println("[ERROR] " + e.getMessage());
        }
    }

    private static KeyPair loadPair(KeyCatalog cat, String alias) throws CryptoOpException {
        KeyCatalog.KeyEntry e = cat.findByAlias(alias).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "not found: " + alias));
        var pub  = cat.asPublicKey(e).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "no public key: " + alias));
        var priv = cat.asPrivateKey(e).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "no private key: " + alias));
        return new KeyPair(pub, priv);
    }

    private static void deleteQuietly(KeyManager mgr, String alias) {
        try { mgr.delete(alias); System.out.println("     cleaned: " + alias); }
        catch (Exception ignored) { /* 없으면 무시 */ }
    }
}
