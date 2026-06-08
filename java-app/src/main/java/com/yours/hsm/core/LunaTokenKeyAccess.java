package com.yours.hsm.core;

import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.key.LunaKey;
import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.EnumMap;
import java.util.Map;

/**
 * {@link TokenKeyAccess}의 Luna 구현. Luna 고유 API(LunaKey / LunaTokenObject)를 호출하므로
 * 실제 HSM 연결 + LunaProvider가 있어야 동작한다. 단위 테스트는 fake 구현을 사용한다.
 */
public final class LunaTokenKeyAccess implements TokenKeyAccess {

    private static final Logger logger = LoggerFactory.getLogger(LunaTokenKeyAccess.class);
    private static final long CKA_LABEL = 0x00000003L;

    private final int slot;

    public LunaTokenKeyAccess(LunaSession session) {
        this.slot = session.slot();
    }

    @Override
    public void makePersistent(Key key, String alias) throws CryptoOpException {
        if (!(key instanceof LunaKey lk)) {
            throw new CryptoOpException(Code.GENERAL,
                "LunaProvider 키가 아니라 토큰에 저장할 수 없습니다: " + key.getClass().getName());
        }
        try {
            lk.MakePersistent(alias);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "키 영구화 실패: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean exists(String alias) throws CryptoOpException {
        return locateOrNull(alias) != null;
    }

    @Override
    public void relabel(String oldAlias, String newAlias) throws CryptoOpException {
        LunaTokenObject obj = locate(oldAlias);
        try {
            obj.SetLargeAttribute(CKA_LABEL, newAlias.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "라벨 변경 실패: " + e.getMessage(), e);
        }
    }

    @Override
    public Map<KeyAttribute, Boolean> readAttributes(String alias) throws CryptoOpException {
        LunaTokenObject obj = locate(alias);
        Map<KeyAttribute, Boolean> result = new EnumMap<>(KeyAttribute.class);
        for (KeyAttribute attr : KeyAttribute.values()) {
            try {
                result.put(attr, obj.GetBooleanAttribute(attr.cka()));
            } catch (Exception e) {
                // 키 종류에 따라 일부 속성은 미존재 — 조회 생략
                logger.debug("alias={} 속성 {} 조회 불가 — 생략", alias, attr.name());
            }
        }
        return result;
    }

    @Override
    public void setAttribute(String alias, KeyAttribute attr, boolean value) throws CryptoOpException {
        LunaTokenObject obj = locate(alias);
        try {
            obj.SetBooleanAttribute(attr.cka(), value);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL,
                "속성 변경 실패(" + attr.label() + "): " + e.getMessage(), e);
        }
    }

    @Override
    public void destroy(String alias) throws CryptoOpException {
        LunaTokenObject obj = locate(alias);
        try {
            obj.DestroyObject();
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "키 삭제 실패: " + e.getMessage(), e);
        }
    }

    private LunaTokenObject locate(String alias) throws CryptoOpException {
        LunaTokenObject obj = locateOrNull(alias);
        if (obj == null) {
            throw new CryptoOpException(Code.KEY_NOT_FOUND, "키를 찾을 수 없습니다: " + alias);
        }
        return obj;
    }

    private LunaTokenObject locateOrNull(String alias) throws CryptoOpException {
        try {
            return LunaTokenObject.LocateKeyByAlias(alias, slot);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "키 조회 실패: " + e.getMessage(), e);
        }
    }
}
