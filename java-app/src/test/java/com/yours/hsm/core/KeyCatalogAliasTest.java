package com.yours.hsm.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 키쌍 동반 별칭 자동 탐색 로직(라벨 규칙) 단위 검증 — HSM 불필요.
 */
class KeyCatalogAliasTest {

    @Test
    void baseAlias_stripsKnownSuffixes() {
        assertEquals("myrsa", KeyCatalog.baseAlias("myrsa-pub"));
        assertEquals("myrsa", KeyCatalog.baseAlias("myrsa-priv"));
        assertEquals("myrsa", KeyCatalog.baseAlias("myrsa_pub"));
        assertEquals("myrsa", KeyCatalog.baseAlias("myrsa.private"));
        assertEquals("myrsa", KeyCatalog.baseAlias("myrsa"));   // 접미사 없음
    }

    @Test
    void publicCandidates_fromPrivateAlias_includesPubVariant() {
        List<String> cands = KeyCatalog.publicAliasCandidates("myrsa-priv");
        // -priv 를 떼고 -pub 를 붙인 표준 후보가 포함되어야 함
        assertTrue(cands.contains("myrsa-pub"), "myrsa-pub 후보 포함: " + cands);
        // 자기 자신은 제외
        assertFalse(cands.contains("myrsa-priv"));
    }

    @Test
    void publicCandidates_fromBareAlias_appendsPub() {
        List<String> cands = KeyCatalog.publicAliasCandidates("myrsa");
        assertTrue(cands.contains("myrsa-pub"), cands.toString());
    }

    @Test
    void privateCandidates_fromPublicAlias_includesPrivVariant() {
        List<String> cands = KeyCatalog.privateAliasCandidates("myrsa-pub");
        assertTrue(cands.contains("myrsa-priv"), "myrsa-priv 후보 포함: " + cands);
        // base 명(개인키가 bare 라벨로 저장된 경우)도 후보
        assertTrue(cands.contains("myrsa"), cands.toString());
        assertFalse(cands.contains("myrsa-pub"));
    }
}
