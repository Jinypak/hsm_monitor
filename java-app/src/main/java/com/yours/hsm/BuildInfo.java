package com.yours.hsm;

import java.io.InputStream;
import java.util.Properties;

/**
 * 빌드 시 {@code processResources} 가 스탬핑한 build-info.properties 를 읽어
 * 버전·빌드 타임스탬프를 노출한다. 리소스가 없으면 dev 기본값을 사용한다.
 */
public final class BuildInfo {

    private static final String VERSION;
    private static final String BUILD_TIMESTAMP;

    static {
        String version = "dev";
        String stamp   = "unknown";
        try (InputStream in = BuildInfo.class.getResourceAsStream("/build-info.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                version = p.getProperty("version", version);
                stamp   = p.getProperty("buildTimestamp", stamp);
            }
        } catch (Exception ignored) {
            // 리소스 누락 시 기본값 유지
        }
        VERSION         = version;
        BUILD_TIMESTAMP = stamp;
    }

    private BuildInfo() {}

    public static String version()   { return VERSION; }
    public static String buildTime() { return BUILD_TIMESTAMP; }

    /** 제목 표시줄용 라벨: {@code v0.1.0-SNAPSHOT (build 20260530-1432)} */
    public static String label() {
        return "v" + VERSION + " (build " + BUILD_TIMESTAMP + ")";
    }
}
