package com.yours.hsm.core;

import com.yours.hsm.algo.OpResult;

import java.time.Duration;
import java.time.Instant;
import java.util.LongSummaryStatistics;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.ReentrantLock;
import java.util.ArrayList;
import java.util.List;

public final class MetricsCollector {

    private final LongAdder total  = new LongAdder();
    private final LongAdder pass   = new LongAdder();
    private final LongAdder fail   = new LongAdder();

    private final ReentrantLock lock       = new ReentrantLock();
    private final List<Long>    signTimes  = new ArrayList<>();
    private final List<Long>    verifyTimes= new ArrayList<>();

    private volatile Instant startTime = Instant.now();

    public void add(OpResult r) {
        total.increment();
        if (r.ok()) {
            pass.increment();
            lock.lock();
            try {
                signTimes.add(r.durationNs());
            } finally {
                lock.unlock();
            }
        } else {
            fail.increment();
        }
    }

    public void addVerify(long durationNs) {
        lock.lock();
        try {
            verifyTimes.add(durationNs);
        } finally {
            lock.unlock();
        }
    }

    public MetricsSnapshot snapshot() {
        long t = total.sum();
        long p = pass.sum();
        long f = fail.sum();
        Duration elapsed = Duration.between(startTime, Instant.now());

        lock.lock();
        try {
            double avgSign   = signTimes.isEmpty()   ? 0.0 : avgMs(signTimes);
            double avgVerify = verifyTimes.isEmpty() ? 0.0 : avgMs(verifyTimes);
            double rate = elapsed.toSeconds() > 0 ? (double) p / elapsed.toSeconds() : 0.0;
            return new MetricsSnapshot(t, p, f, rate, avgSign, avgVerify, elapsed);
        } finally {
            lock.unlock();
        }
    }

    public void reset() {
        total.reset();
        pass.reset();
        fail.reset();
        lock.lock();
        try {
            signTimes.clear();
            verifyTimes.clear();
        } finally {
            lock.unlock();
        }
        startTime = Instant.now();
    }

    private static double avgMs(List<Long> nsList) {
        return nsList.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;
    }
}
