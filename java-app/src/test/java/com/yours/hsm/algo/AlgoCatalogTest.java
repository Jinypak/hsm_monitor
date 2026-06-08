package com.yours.hsm.algo;

import com.yours.hsm.algo.AlgoSpec.Family;
import com.yours.hsm.algo.AlgoSpec.Op;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlgoCatalogTest {

    @Test
    void phase1_matchesMechanismCatalogSection_11_3() {
        // mechanism-catalog.md §11.3 와 정확히 일치 — 11개
        List<String> expected = List.of(
            "RSA_KEYPAIR",
            "RSA_SIGN_SHA256",
            "RSA_SIGN_SHA256_PSS",
            "RSA_OAEP_SHA256",
            "AES_KEYGEN",
            "AES_CBC_PKCS5",
            "AES_GCM",
            "AES_KWP",
            "AES_CMAC",
            "HMAC_SHA256",
            "SHA256"
        );
        List<String> actual = AlgoCatalog.phase1().stream().map(AlgoSpec::id).toList();
        assertEquals(expected, actual,
                     "Phase 1 항목은 §11.3 와 1:1 일치해야 함");
    }

    @Test
    void allItemsHaveUniqueIds() {
        var ids = AlgoCatalog.all().stream().map(AlgoSpec::id).toList();
        assertEquals(ids.size(), ids.stream().distinct().count(),
                     "id 는 중복 없어야 함");
    }

    @Test
    void findById_existing_returnsSpec() {
        var spec = AlgoCatalog.findById("RSA_SIGN_SHA256").orElseThrow();
        assertEquals("SHA256withRSA", spec.jceName());
        assertEquals(Family.RSA,      spec.family());
        assertEquals(Op.SIGN,         spec.op());
        assertEquals("0x00000040",    spec.ckmHex());
        assertTrue(spec.phase1Default());
    }

    @Test
    void findById_unknown_returnsEmpty() {
        assertTrue(AlgoCatalog.findById("DOES_NOT_EXIST").isEmpty());
    }

    @Test
    void byFamily_RSA_includesPhase1AndExtras() {
        var rsa = AlgoCatalog.by(Family.RSA);
        var ids = rsa.stream().map(AlgoSpec::id).toList();
        assertTrue(ids.contains("RSA_SIGN_SHA256"));
        assertTrue(ids.contains("RSA_OAEP_SHA256"));
        assertTrue(ids.contains("RSA_SIGN_SHA384"));   // 비-Phase1
        assertTrue(ids.contains("RSA_SIGN_SHA512"));   // 비-Phase1
    }

    @Test
    void byFamilyOp_AES_ENC_includesPhase1AndExtraModes() {
        var aesEnc = AlgoCatalog.by(Family.AES, Op.ENC);
        var ids = aesEnc.stream().map(AlgoSpec::id).toList();
        // Phase 1 핵심
        assertTrue(ids.contains("AES_CBC_PKCS5"));
        assertTrue(ids.contains("AES_GCM"));
        // 확장된 모드
        assertTrue(ids.contains("AES_CTR"));
        assertTrue(ids.contains("AES_CFB128"));
        assertTrue(ids.contains("AES_OFB"));
    }

    @Test
    void phase1Flag_onlyTheEleven() {
        // phase1Default=true 는 정확히 §11.3 의 11개여야 함
        assertEquals(11, AlgoCatalog.phase1().size(),
                     "phase1Default 항목은 정확히 11개여야 함");
    }

    @Test
    void mlDsa_existsButNotPhase1() {
        var mlDsa = AlgoCatalog.by(Family.ML_DSA);
        assertEquals(3, mlDsa.size());
        assertTrue(mlDsa.stream().noneMatch(AlgoSpec::phase1Default),
                   "PQC 는 펌웨어 업그레이드 전까지 Phase 1 노출 X");
    }

    @Test
    void mlKem_existsButNotPhase1() {
        var mlKem = AlgoCatalog.by(Family.ML_KEM);
        assertEquals(3, mlKem.size());
        assertTrue(mlKem.stream().noneMatch(AlgoSpec::phase1Default));
    }

    @Test
    void aesKwp_isVendorOnly() {
        var kwp = AlgoCatalog.findById("AES_KWP").orElseThrow();
        assertTrue(kwp.vendorOnly(), "AES_KWP 는 0x80000171 벤더 확장");
    }

    @Test
    void invalidSpec_blankId_throws() {
        assertThrows(IllegalArgumentException.class, () ->
            new AlgoSpec("", Family.RSA, Op.SIGN, "x", "0x0", 0, true, false, true));
    }

    @Test
    void invalidSpec_nullFamily_throws() {
        assertThrows(IllegalArgumentException.class, () ->
            new AlgoSpec("id", null, Op.SIGN, "x", "0x0", 0, true, false, true));
    }

    @Test
    void invalidSpec_negativeKeyBits_throws() {
        assertThrows(IllegalArgumentException.class, () ->
            new AlgoSpec("id", Family.RSA, Op.SIGN, "x", "0x0", -1, true, false, true));
    }
}
