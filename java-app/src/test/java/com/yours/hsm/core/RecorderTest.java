package com.yours.hsm.core;

import com.yours.hsm.algo.OpResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RecorderTest {

    private static final MetricsSnapshot DUMMY_STATS = new MetricsSnapshot(
        10, 9, 1, 1.5, 2.0, 1.0, Duration.ofSeconds(6)
    );

    @Test
    void saveJson_createsFileWithRecords(@TempDir Path tmp) throws IOException {
        Recorder r = new Recorder();
        r.append(0, OpResult.success(1_000_000L, new byte[]{0x01}));
        r.append(1, OpResult.failure(500_000L, "GENERAL", "오류 메시지"));

        Path out = r.saveJson(tmp, DUMMY_STATS);

        assertTrue(Files.exists(out));
        String json = Files.readString(out);
        assertTrue(json.contains("\"total\""));
        assertTrue(json.contains("\"records\""));
        assertTrue(json.contains("\"ok\" : true"));
        assertTrue(json.contains("\"ok\" : false"));
    }

    @Test
    void saveCsv_createsFileWithHeader(@TempDir Path tmp) throws IOException {
        Recorder r = new Recorder();
        r.append(0, OpResult.success(2_000_000L, new byte[]{0x02}));

        Path out = r.saveCsv(tmp, DUMMY_STATS);

        assertTrue(Files.exists(out));
        List<String> lines = Files.readAllLines(out);
        assertEquals("seq,ok,durationMs,errorCode,errorMsg", lines.get(0));
        assertEquals(2, lines.size()); // header + 1 row
    }

    @Test
    void clear_removesAllRecords(@TempDir Path tmp) throws IOException {
        Recorder r = new Recorder();
        r.append(0, OpResult.success(1_000_000L, new byte[]{1}));
        r.clear();

        Path out = r.saveJson(tmp, DUMMY_STATS);
        String json = Files.readString(out);
        assertTrue(json.contains("\"records\" : [ ]"));
    }

    @Test
    void multipleAppend_allRecordsPresent(@TempDir Path tmp) throws IOException {
        Recorder r = new Recorder();
        for (int i = 0; i < 5; i++) {
            r.append(i, OpResult.success(1_000_000L, new byte[]{(byte) i}));
        }

        Path out = r.saveCsv(tmp, DUMMY_STATS);
        List<String> lines = Files.readAllLines(out);
        assertEquals(6, lines.size()); // header + 5 rows
    }

    @Test
    void saveCsv_withExtraColumns_includesOpAndMech(@TempDir Path tmp) throws IOException {
        Recorder r = new Recorder();
        r.append(0, OpResult.success(1_000_000L, new byte[]{0x01}), extra("ENCRYPT", "AES_GCM"));
        r.append(1, OpResult.failure(500_000L, "GENERAL", "복호화 실패"), extra("DECRYPT", "AES_GCM"));

        Path out = r.saveCsv(tmp, DUMMY_STATS, List.of("op", "mech"));

        List<String> lines = Files.readAllLines(out);
        assertEquals("seq,op,mech,ok,durationMs,errorCode,errorMsg", lines.get(0));
        assertTrue(lines.get(1).startsWith("0,ENCRYPT,AES_GCM,true,"));
        assertTrue(lines.get(2).startsWith("1,DECRYPT,AES_GCM,false,"));
        assertTrue(lines.get(2).endsWith("GENERAL,복호화 실패"));
    }

    @Test
    void saveJson_withExtraColumns_serializesExtraFields(@TempDir Path tmp) throws IOException {
        Recorder r = new Recorder();
        r.append(0, OpResult.success(1_000_000L, new byte[]{0x01}), extra("ENCRYPT", "RSA_OAEP"));

        Path out = r.saveJson(tmp, DUMMY_STATS);
        String json = Files.readString(out);
        assertTrue(json.contains("\"op\" : \"ENCRYPT\""));
        assertTrue(json.contains("\"mech\" : \"RSA_OAEP\""));
    }

    @Test
    void saveCsv_emptyExtraColumns_matchesLegacyHeader(@TempDir Path tmp) throws IOException {
        Recorder r = new Recorder();
        r.append(0, OpResult.success(1_000_000L, new byte[]{0x01}), extra("ENCRYPT", "AES_GCM"));

        // extraCols 없이 저장하면 기존 포맷과 동일해야 한다
        Path out = r.saveCsv(tmp, DUMMY_STATS);
        List<String> lines = Files.readAllLines(out);
        assertEquals("seq,ok,durationMs,errorCode,errorMsg", lines.get(0));
    }

    private static Map<String, Object> extra(String op, String mech) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("op",   op);
        m.put("mech", mech);
        return m;
    }
}
