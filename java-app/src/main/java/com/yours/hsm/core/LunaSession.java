package com.yours.hsm.core;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaProvider;
import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * LunaProvider를 JCE에 등록하고 슬롯에 로그인한다.
 * <p>
 * 네이티브 라이브러리(LunaAPI.dll)는 gradle.properties 의 lunaClientPath/JSP/lib 에서 로드.
 * Gradle run 태스크가 -Djava.library.path 를 자동 설정하므로 별도 지정 불필요.
 */
public final class LunaSession implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(LunaSession.class);

    private final Provider  provider;
    private final KeyStore  keyStore;
    private final String    tokenLabel;
    private final int       slot;
    private       boolean   loggedIn;

    private LunaSession(Provider provider, KeyStore keyStore, String tokenLabel, int slot) {
        this.provider   = provider;
        this.keyStore   = keyStore;
        this.tokenLabel = tokenLabel;
        this.slot       = slot;
        this.loggedIn   = true;
    }

    public static LunaSession connect(int slot, char[] pin) throws CryptoOpException {
        try {
            // 1. LunaProvider JCE 등록 (이미 등록되어 있으면 재사용)
            Provider luna = Security.getProvider("LunaProvider");
            if (luna == null) {
                luna = new LunaProvider();
                Security.addProvider(luna);
                logger.info("LunaProvider 등록 — 버전 {}", luna.getVersionStr());
            } else {
                logger.info("LunaProvider 재사용 — 버전 {}", luna.getVersionStr());
            }

            // 2. 슬롯 로그인: login(int slot, String pin)
            LunaSlotManager mgr = LunaSlotManager.getInstance();
            // KeyStore("Luna") 는 기본 슬롯에 바인딩되므로, 로드 전에 대상 슬롯을 기본으로 지정.
            // (멀티 슬롯을 동시에 다루는 키 이전 시나리오에서 슬롯 혼선을 막는다)
            mgr.setDefaultSlot(slot);
            boolean ok = mgr.login(slot, new String(pin));
            if (!ok) {
                throw new CryptoOpException(Code.PIN_INCORRECT, "PIN이 올바르지 않습니다.");
            }
            logger.info("슬롯 {} 로그인 완료", slot);

            // 3. KeyStore 로드
            mgr.setDefaultSlot(slot);
            KeyStore ks = KeyStore.getInstance("Luna");
            ks.load(null, pin);
            logger.info("KeyStore 로드 완료 — alias 수: {}", ks.size());

            // 4. 토큰 레이블
            String label;
            try {
                label = mgr.getTokenLabel(slot).strip();
            } catch (Exception e) {
                label = "Slot-" + slot;
            }

            return new LunaSession(luna, ks, label, slot);

        } catch (CryptoOpException e) {
            throw e;
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (msg.contains("CKR_PIN") || msg.contains("PIN_INCORRECT")) {
                throw new CryptoOpException(Code.PIN_INCORRECT, "PIN이 올바르지 않습니다.", e);
            }
            if (msg.contains("LOCKED") || msg.contains("PIN_LOCKED")) {
                throw new CryptoOpException(Code.SLOT_LOCKED, "슬롯이 잠겼습니다. HSM 관리자에게 문의하세요.", e);
            }
            throw new CryptoOpException(Code.GENERAL, "HSM 연결 실패: " + msg, e);
        }
    }

    public KeyStore  keyStore()   { return keyStore; }
    public Provider  provider()   { return provider; }
    public String    tokenLabel() { return tokenLabel; }
    public int       slot()       { return slot; }
    public boolean   isLoggedIn() { return loggedIn; }

    @Override
    public void close() {
        if (!loggedIn) return;
        try {
            LunaSlotManager.getInstance().logout(slot);
            loggedIn = false;
            logger.info("슬롯 {} 로그아웃", slot);
        } catch (Exception e) {
            logger.warn("로그아웃 중 오류 (무시)", e);
        }
    }
}
