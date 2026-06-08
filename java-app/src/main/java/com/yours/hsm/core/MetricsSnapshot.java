package com.yours.hsm.core;

import java.time.Duration;

public record MetricsSnapshot(
    long     total,
    long     pass,
    long     fail,
    double   rate,
    double   avgSignMs,
    double   avgVerifyMs,
    Duration elapsed
) {}
