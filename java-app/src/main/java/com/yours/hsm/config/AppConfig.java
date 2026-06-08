package com.yours.hsm.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public record AppConfig(
    @JsonProperty("lunaLibPath")       String lunaLibPath,
    @JsonProperty("defaultSlot")       int    defaultSlot,
    @JsonProperty("lastSelectedAlias") String lastSelectedAlias,
    @JsonProperty("lastSelectedAlgoId")String lastSelectedAlgoId,
    @JsonProperty("lastRate")          double lastRate,
    @JsonProperty("lastSaveDir")       String lastSaveDir
) {
    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);

    private static final Path CONFIG_DIR =
        Path.of(System.getenv().getOrDefault("APPDATA",
            System.getProperty("user.home")), "HSMMonitor");
    private static final Path CONFIG_FILE = CONFIG_DIR.resolve("config.json");
    private static final ObjectMapper MAPPER =
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @JsonCreator
    public AppConfig {
        if (lunaLibPath      == null) lunaLibPath      = defaults().lunaLibPath();
        if (lastSelectedAlias == null) lastSelectedAlias = "";
        if (lastSelectedAlgoId== null) lastSelectedAlgoId= defaults().lastSelectedAlgoId();
        if (lastSaveDir       == null) lastSaveDir       = System.getProperty("user.home");
    }

    public static AppConfig defaults() {
        return new AppConfig(
            "C:\\Program Files\\SafeNet\\LunaClient",
            0, "", "RSA_SIGN_SHA256", 1.0,
            System.getProperty("user.home")
        );
    }

    public static AppConfig load() {
        if (!Files.exists(CONFIG_FILE)) {
            logger.info("설정 파일 없음 — 기본값 사용: {}", CONFIG_FILE);
            return defaults();
        }
        try {
            AppConfig cfg = MAPPER.readValue(CONFIG_FILE.toFile(), AppConfig.class);
            logger.info("설정 로드: {}", CONFIG_FILE);
            return cfg;
        } catch (IOException e) {
            logger.warn("설정 파일 로드 실패 — 기본값 사용", e);
            return defaults();
        }
    }

    public void save() {
        try {
            Files.createDirectories(CONFIG_DIR);
            MAPPER.writeValue(CONFIG_FILE.toFile(), this);
            logger.info("설정 저장: {}", CONFIG_FILE);
        } catch (IOException e) {
            logger.error("설정 저장 실패", e);
        }
    }
}
