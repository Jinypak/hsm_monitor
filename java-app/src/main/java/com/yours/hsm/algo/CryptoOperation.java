package com.yours.hsm.algo;

public sealed interface CryptoOperation
    permits SignOp, EncryptOp, WrapOp, MacOp, DigestOp, DeriveOp, KemOp {

    AlgoSpec spec();

    OpResult execute(byte[] input) throws CryptoOpException;
}
