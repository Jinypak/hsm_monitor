package com.yours.hsm.algo;

public final class KemOp implements CryptoOperation {

    private final AlgoSpec spec;

    public KemOp(AlgoSpec spec) {
        this.spec = spec;
    }

    @Override
    public AlgoSpec spec() { return spec; }

    @Override
    public OpResult execute(byte[] input) throws CryptoOpException {
        // Phase 4 자리 — 펌웨어 PQC 빌드 후 구현
        throw new UnsupportedOperationException("KEM 연산은 Phase 4 (PQC 펌웨어 업그레이드) 이후 구현됩니다.");
    }
}
