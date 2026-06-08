package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;

import java.security.Key;
import java.util.Map;

/**
 * 토큰 객체에 대한 저수준 PKCS#11 접근 추상화.
 * <p>
 * 실제 구현({@link LunaTokenKeyAccess})은 Luna 고유 API를 호출하므로 HSM 없이는
 * 동작하지 않는다. 이 인터페이스로 격리해 {@link KeyManager}의 검증·오케스트레이션
 * 로직을 LunaProvider 없는 환경에서도 단위 테스트할 수 있다.
 */
public interface TokenKeyAccess {

    /** JCE로 생성한 키를 주어진 alias(CKA_LABEL)로 토큰에 영구 저장한다. */
    void makePersistent(Key key, String alias) throws CryptoOpException;

    /** 해당 alias의 키 객체가 토큰에 존재하는지. */
    boolean exists(String alias) throws CryptoOpException;

    /** 키의 CKA_LABEL(alias)을 변경한다. */
    void relabel(String oldAlias, String newAlias) throws CryptoOpException;

    /** 키의 현재 boolean 속성을 읽는다. 토큰이 지원하지 않는 속성은 결과에서 생략될 수 있다. */
    Map<KeyAttribute, Boolean> readAttributes(String alias) throws CryptoOpException;

    /** 키의 boolean 속성 하나를 변경한다. */
    void setAttribute(String alias, KeyAttribute attr, boolean value) throws CryptoOpException;

    /** 토큰에서 키를 영구 삭제한다(되돌릴 수 없음). */
    void destroy(String alias) throws CryptoOpException;
}
