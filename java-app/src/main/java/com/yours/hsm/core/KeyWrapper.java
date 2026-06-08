package com.yours.hsm.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.yours.hsm.algo.AlgoCatalog;
import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import com.yours.hsm.algo.OpResult;
import com.yours.hsm.algo.WrapOp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.Provider;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * AES 키로 다른 키를 래핑(AES-KWP)하고, 래핑 결과를 파일로 내보낸다.
 * <p>
 * 래핑 자체는 기존 {@link WrapOp}(JCE WRAP_MODE)을 재사용하므로 운영 경로와 동일하다.
 * 내보낼 때 원시 래핑 바이트({@code .key})와 메타데이터({@code .meta.json})를 함께 저장해
 * {@link KeyUnwrapper}가 알고리즘·타입을 알고 복원할 수 있게 한다.
 */
public final class KeyWrapper {

    private static final Logger logger = LoggerFactory.getLogger(KeyWrapper.class);
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
    private static final ObjectMapper MAPPER =
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    static final String AES_KWP_ID = "AES_KWP";

    private final Provider   provider;
    private final KeyCatalog catalog;

    public KeyWrapper(LunaSession session) {
        this.provider = session.provider();
        this.catalog  = new KeyCatalog(session);
    }

    /**
     * wrappingEntry(AES 키)로 targetEntry를 래핑한다.
     * @return 래핑된 키 바이트(AES-KWP)
     */
    public byte[] wrap(KeyCatalog.KeyEntry wrappingEntry, KeyCatalog.KeyEntry targetEntry)
        throws CryptoOpException {

        if (wrappingEntry == null || targetEntry == null) {
            throw new CryptoOpException(Code.GENERAL, "래핑 키와 대상 키를 선택하세요.");
        }
        if (wrappingEntry.kind() != KeyCatalog.KeyKind.SECRET) {
            throw new CryptoOpException(Code.GENERAL,
                "래핑 키는 AES 대칭키여야 합니다: " + wrappingEntry.alias());
        }
        if (wrappingEntry.alias().equals(targetEntry.alias())) {
            throw new CryptoOpException(Code.GENERAL, "래핑 키와 대상 키가 동일합니다.");
        }

        SecretKey wrapKey = catalog.asSecretKey(wrappingEntry).orElseThrow(() ->
            new CryptoOpException(Code.KEY_NOT_FOUND, "래핑 키를 찾을 수 없습니다: " + wrappingEntry.alias()));
        Key target = resolveTarget(targetEntry);

        byte[] wrapped = wrapRaw(provider, wrapKey, target);
        logger.info("키 래핑 완료: wrapKey={} target={} bytes={}",
            wrappingEntry.alias(), targetEntry.alias(), wrapped.length);
        return wrapped;
    }

    /** 래핑 결과에 동반할 메타데이터를 구성한다. */
    public WrapMetadata metadataFor(KeyCatalog.KeyEntry wrappingEntry, KeyCatalog.KeyEntry targetEntry) {
        String keyType = switch (targetEntry.kind()) {
            case SECRET           -> "SECRET_KEY";
            case KEYPAIR, PRIVATE -> "PRIVATE_KEY";
            case PUBLIC           -> "PUBLIC_KEY";
        };
        return new WrapMetadata(
            targetEntry.algorithm(), keyType, targetEntry.alias(), targetEntry.keyBits(),
            wrappingEntry.alias(), "AES_KWP", Instant.now().toString());
    }

    /** AES-KWP로 target을 wrapKey로 래핑. provider 주입형이라 단위 테스트 가능. */
    static byte[] wrapRaw(Provider provider, Key wrapKey, Key target) throws CryptoOpException {
        AlgoSpec spec = aesKwpSpecFor(provider);
        WrapOp op = new WrapOp(provider, spec, wrapKey, target);
        OpResult r = op.execute(null);
        if (!r.ok()) {
            throw new CryptoOpException(Code.GENERAL, r.errorMsg().orElse("래핑 실패"));
        }
        return r.output().orElseThrow();
    }

    /**
     * AES-KWP 메커니즘 스펙을 provider 에 맞는 JCE 이름으로 반환한다.
     * <p>
     * 카탈로그 기본 이름은 Luna 표준({@code AES/KWP/NoPadding})이지만, SunJCE 는
     * {@code AESWrapPad} 만 노출한다. provider 가 카탈로그 이름을 모르면 대체명으로 교체.
     */
    static AlgoSpec aesKwpSpecFor(Provider provider) throws CryptoOpException {
        AlgoSpec spec = AlgoCatalog.findById(AES_KWP_ID).orElseThrow(() ->
            new CryptoOpException(Code.MECH_NOT_SUPPORTED, "AES_KWP 메커니즘을 찾을 수 없습니다."));
        if (provider.getService("Cipher", spec.jceName()) != null) return spec;
        // 폴백: SunJCE 의 AESWrapPad
        if (provider.getService("Cipher", "AESWrapPad") != null) {
            return new AlgoSpec(spec.id(), spec.family(), spec.op(), "AESWrapPad",
                spec.ckmHex(), spec.keyBits(), spec.fipsApproved(), spec.vendorOnly(), spec.phase1Default());
        }
        return spec; // 둘 다 없으면 원본으로(실행 시 명확한 오류)
    }

    /**
     * 래핑 바이트와 메타데이터를 {@code dir}에 내보낸다.
     * {@code <yyyyMMdd_HHmmss>_wrapping_key.key} + 동일 basename의 {@code .meta.json}.
     * @return 생성된 .key 파일 경로
     */
    public Path export(byte[] wrapped, WrapMetadata meta, Path dir) throws CryptoOpException {
        String base    = TS.format(LocalDateTime.now()) + "_wrapping_key";
        Path keyFile   = dir.resolve(base + ".key");
        Path metaFile  = dir.resolve(base + ".meta.json");
        try {
            Files.createDirectories(dir);
            Files.write(keyFile, wrapped);
            MAPPER.writeValue(metaFile.toFile(), meta);
        } catch (IOException e) {
            throw new CryptoOpException(Code.GENERAL,
                "파일 내보내기 실패(" + keyFile + "): " + e.getMessage(), e);
        }
        logger.info("래핑 키 내보내기: {} (+ {})", keyFile, metaFile.getFileName());
        return keyFile;
    }

    /** 내보내기 .key 파일명: {@code <yyyyMMdd_HHmmss>_wrapping_key.key} */
    public static String exportFileName(LocalDateTime when) {
        return TS.format(when) + "_wrapping_key.key";
    }

    private Key resolveTarget(KeyCatalog.KeyEntry entry) throws CryptoOpException {
        return switch (entry.kind()) {
            case SECRET -> catalog.asSecretKey(entry).orElseThrow(() ->
                new CryptoOpException(Code.KEY_NOT_FOUND, "대상 키를 찾을 수 없습니다: " + entry.alias()));
            case KEYPAIR, PRIVATE -> catalog.asKeyPair(entry)
                .map(java.security.KeyPair::getPrivate)
                .orElseThrow(() -> new CryptoOpException(Code.KEY_NOT_FOUND,
                    "대상 개인키를 찾을 수 없습니다: " + entry.alias()));
            case PUBLIC -> throw new CryptoOpException(Code.GENERAL,
                "공개키는 래핑 대상으로 적절하지 않습니다: " + entry.alias());
        };
    }
}
