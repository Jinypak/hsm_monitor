package com.yours.hsm.core;

import com.yours.hsm.algo.OpResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MetricsCollectorTest {

    private MetricsCollector collector;

    @BeforeEach
    void setUp() {
        collector = new MetricsCollector();
    }

    @Test
    void emptySnapshot_allZero() {
        MetricsSnapshot s = collector.snapshot();
        assertEquals(0, s.total());
        assertEquals(0, s.pass());
        assertEquals(0, s.fail());
        assertEquals(0.0, s.avgSignMs());
    }

    @Test
    void addSuccess_incrementsPassAndTotal() {
        collector.add(OpResult.success(1_000_000L, new byte[]{1}));
        collector.add(OpResult.success(2_000_000L, new byte[]{2}));

        MetricsSnapshot s = collector.snapshot();
        assertEquals(2, s.total());
        assertEquals(2, s.pass());
        assertEquals(0, s.fail());
    }

    @Test
    void addFailure_incrementsFailAndTotal() {
        collector.add(OpResult.failure(500_000L, "GENERAL", "오류"));

        MetricsSnapshot s = collector.snapshot();
        assertEquals(1, s.total());
        assertEquals(0, s.pass());
        assertEquals(1, s.fail());
    }

    @Test
    void avgSignMs_calculatedCorrectly() {
        // 2ms, 4ms → avg 3ms
        collector.add(OpResult.success(2_000_000L, new byte[]{1}));
        collector.add(OpResult.success(4_000_000L, new byte[]{2}));

        double avg = collector.snapshot().avgSignMs();
        assertEquals(3.0, avg, 0.01);
    }

    @Test
    void reset_clearsAllState() {
        collector.add(OpResult.success(1_000_000L, new byte[]{1}));
        collector.add(OpResult.failure(500_000L, "E", "msg"));
        collector.reset();

        MetricsSnapshot s = collector.snapshot();
        assertEquals(0, s.total());
        assertEquals(0, s.pass());
        assertEquals(0, s.fail());
    }

    @Test
    void addVerify_reflectsInAvgVerifyMs() {
        collector.addVerify(3_000_000L);  // 3ms
        collector.addVerify(1_000_000L);  // 1ms

        double avg = collector.snapshot().avgVerifyMs();
        assertEquals(2.0, avg, 0.01);
    }

    @Test
    void largeVolume_remainsAccurate() {
        for (int i = 0; i < 1000; i++) {
            collector.add(OpResult.success(1_000_000L, new byte[]{1}));
        }
        MetricsSnapshot s = collector.snapshot();
        assertEquals(1000, s.total());
        assertEquals(1000, s.pass());
        assertEquals(0,    s.fail());
        assertEquals(1.0,  s.avgSignMs(), 0.001);
    }
}
