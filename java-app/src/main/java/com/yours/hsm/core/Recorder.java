package com.yours.hsm.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.yours.hsm.algo.OpResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public final class Recorder {

    private static final Logger logger = LoggerFactory.getLogger(Recorder.class);
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
    private static final ObjectMapper MAPPER =
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private final List<Map<String, Object>> records = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();

    public void append(int seq, OpResult r) {
        append(seq, r, Map.of());
    }

    /**
     * 추가 컬럼(예: 암복호화 탭의 op/mech)을 함께 기록한다.
     * extra 항목은 seq 바로 뒤에 삽입되어 JSON·CSV에 노출된다.
     */
    public void append(int seq, OpResult r, Map<String, Object> extra) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("seq",        seq);
        if (extra != null) extra.forEach(row::put);
        row.put("ok",         r.ok());
        row.put("durationMs", r.durationMs());
        r.output().ifPresent(b -> row.put("outputB64", Base64.getEncoder().encodeToString(b)));
        r.errorCode().ifPresent(c -> row.put("errorCode", c));
        r.errorMsg() .ifPresent(m -> row.put("errorMsg",  m));
        lock.lock();
        try {
            records.add(row);
        } finally {
            lock.unlock();
        }
    }

    public void clear() {
        lock.lock();
        try {
            records.clear();
        } finally {
            lock.unlock();
        }
    }

    public Path saveJson(Path dir, MetricsSnapshot stats) throws IOException {
        Files.createDirectories(dir);
        Path out = dir.resolve("hsm-result-" + TS.format(LocalDateTime.now()) + ".json");

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("stats",   statsMap(stats));
        root.put("records", snapshotRecords());

        MAPPER.writeValue(out.toFile(), root);
        logger.info("JSON 저장: {}", out);
        return out;
    }

    public Path saveCsv(Path dir, MetricsSnapshot stats) throws IOException {
        return saveCsv(dir, stats, List.of());
    }

    /**
     * 추가 컬럼을 포함해 CSV로 저장한다. extraCols 가 비면 기존 포맷
     * ({@code seq,ok,durationMs,errorCode,errorMsg})과 동일하다.
     * 컬럼은 {@code seq, [extraCols...], ok, durationMs, errorCode, errorMsg} 순서로 기록된다.
     */
    public Path saveCsv(Path dir, MetricsSnapshot stats, List<String> extraCols) throws IOException {
        Files.createDirectories(dir);
        Path out = dir.resolve("hsm-result-" + TS.format(LocalDateTime.now()) + ".csv");

        List<Map<String, Object>> snap = snapshotRecords();
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            StringBuilder header = new StringBuilder("seq");
            for (String c : extraCols) header.append(',').append(c);
            header.append(",ok,durationMs,errorCode,errorMsg");
            w.write(header.toString());
            w.newLine();

            for (Map<String, Object> row : snap) {
                StringBuilder line = new StringBuilder();
                line.append(row.getOrDefault("seq", ""));
                for (String c : extraCols) line.append(',').append(row.getOrDefault(c, ""));
                line.append(',').append(row.getOrDefault("ok",         ""))
                    .append(',').append(row.getOrDefault("durationMs", ""))
                    .append(',').append(row.getOrDefault("errorCode",  ""))
                    .append(',').append(row.getOrDefault("errorMsg",   ""));
                w.write(line.toString());
                w.newLine();
            }
        }
        logger.info("CSV 저장: {}", out);
        return out;
    }

    private List<Map<String, Object>> snapshotRecords() {
        lock.lock();
        try {
            return new ArrayList<>(records);
        } finally {
            lock.unlock();
        }
    }

    private static Map<String, Object> statsMap(MetricsSnapshot s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("total",      s.total());
        m.put("pass",       s.pass());
        m.put("fail",       s.fail());
        m.put("rate",       s.rate());
        m.put("avgSignMs",  s.avgSignMs());
        m.put("avgVerifyMs",s.avgVerifyMs());
        m.put("elapsedSec", s.elapsed().toSeconds());
        return m;
    }
}
