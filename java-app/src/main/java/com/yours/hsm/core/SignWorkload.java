package com.yours.hsm.core;

import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.OpResult;
import com.yours.hsm.algo.SignOp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class SignWorkload implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(SignWorkload.class);

    public record WorkloadConfig(
        double  ratePerSec,
        boolean externalVerify
    ) {}

    public interface Listener {
        void onResult(int seq, OpResult r);
        void onStats(MetricsSnapshot snapshot);
        void onError(Throwable t);
    }

    private final LunaSession      session;
    private final AlgoSpec         spec;
    private final KeyCatalog.KeyEntry key;

    private ScheduledExecutorService executor;
    private ScheduledFuture<?>       future;
    private final AtomicInteger      seq = new AtomicInteger(0);
    private MetricsCollector         collector;
    private Recorder                 recorder;

    private static final byte[] SAMPLE_DATA;
    static {
        SAMPLE_DATA = new byte[64];
        new SecureRandom().nextBytes(SAMPLE_DATA);
    }

    public SignWorkload(LunaSession session, AlgoSpec spec, KeyCatalog.KeyEntry key) {
        this.session = session;
        this.spec    = spec;
        this.key     = key;
    }

    public void start(WorkloadConfig cfg, Listener listener) {
        if (executor != null && !executor.isShutdown()) {
            throw new IllegalStateException("워크로드가 이미 실행 중입니다.");
        }

        collector = new MetricsCollector();
        recorder  = new Recorder();
        seq.set(0);

        long intervalMs = (long) (1000.0 / Math.max(0.1, Math.min(10.0, cfg.ratePerSec())));
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "sign-workload");
            t.setDaemon(true);
            return t;
        });

        future = executor.scheduleAtFixedRate(() -> {
            try {
                KeyPair pair = new KeyCatalog(session).asKeyPair(key).orElseThrow(
                    () -> new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                        "키쌍을 찾을 수 없습니다: " + key.alias()));

                SignOp op = new SignOp(session.provider(), spec, pair.getPrivate());
                OpResult result = op.execute(SAMPLE_DATA);

                if (result.ok() && cfg.externalVerify() && pair.getPublic() != null) {
                    Verifier verifier = new Verifier(null);
                    long vStart = System.nanoTime();
                    boolean ok = verifier.verify(spec, pair.getPublic(), SAMPLE_DATA,
                        result.output().orElseThrow());
                    collector.addVerify(System.nanoTime() - vStart);
                    if (!ok) {
                        logger.warn("seq={} 외부 서명 검증 실패", seq.get());
                    }
                } else if (result.ok() && cfg.externalVerify() && pair.getPublic() == null) {
                    logger.warn("외부 검증 건너뜀 — 인증서 없는 키쌍이므로 공개키 없음: {}", key.alias());
                }

                int current = seq.getAndIncrement();
                collector.add(result);
                recorder.append(current, result);

                listener.onResult(current, result);
                listener.onStats(collector.snapshot());

            } catch (Exception e) {
                logger.error("워크로드 루프 예외", e);
                listener.onError(e);
            }
        }, 0, intervalMs, TimeUnit.MILLISECONDS);

        logger.info("서명 워크로드 시작: spec={} ratePerSec={}", spec.id(), cfg.ratePerSec());
    }

    public void stop() {
        if (future != null) future.cancel(false);
        if (executor != null) executor.shutdown();
        logger.info("서명 워크로드 중지: 총 {}건", seq.get());
    }

    public MetricsCollector collector() { return collector; }
    public Recorder         recorder()  { return recorder; }

    @Override
    public void close() { stop(); }
}
