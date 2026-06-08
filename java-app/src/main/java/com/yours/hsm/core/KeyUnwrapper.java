package com.yours.hsm.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.Provider;

/**
 * {@link KeyWrapper}가 내보낸 {@code .key} + {@code .meta.json}을 읽어
 * AES 키로 언래핑하고, 복원된 키를 새 라벨로 토큰에 영구 저장한다.
 */
public final class KeyUnwrapper {

    private static final Logger logger = LoggerFactory.getLogger(KeyUnwrapper.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Provider       provider;
    private final KeyCatalog     catalog;
    private final TokenKeyAccess access;

    public KeyUnwrapper(LunaSession session) {
        this(session.provider(), new KeyCatalog(session), new LunaTokenKeyAccess(session));
    }

    KeyUnwrapper(Provider provider, KeyCatalog catalog, TokenKeyAccess access) {
        this.provider = provider;
        this.catalog  = catalog;
        this.access   = access;
    }

    /**
     * unwrapKeyEntry(AES 키)로 keyFile을 언래핑하여 newAlias로 토큰에 저장한다.
     * 메타데이터는 keyFile 옆의 {@code .meta.json}에서 읽는다.
     * @return 복원된 키 객체
     */
    public Key unwrapAndStore(KeyCatalog.KeyEntry unwrapKeyEntry, Path keyFile, String newAlias)
        throws CryptoOpException {

        if (newAlias == null || newAlias.isBlank()) {
            throw new CryptoOpException(Code.GENERAL, "복원할 키의 새 라벨을 입력하세요.");
        }
        if (unwrapKeyEntry == null || unwrapKeyEntry.kind() != KeyCatalog.KeyKind.SECRET) {
            throw new CryptoOpException(Code.GENERAL, "언래핑 키는 AES 대칭키여야 합니다.");
        }
        if (access.exists(newAlias)) {
            throw new CryptoOpException(Code.GENERAL, "이미 존재하는 라벨입니다: " + newAlias);
        }

        WrapMetadata meta = readMetadata(keyFile);
        byte[] wrapped;
        try {
            wrapped = Files.readAllBytes(keyFile);
        } catch (IOException e) {
            throw new CryptoOpException(Code.GENERAL, "키 파일 읽기 실패: " + e.getMessage(), e);
        }

        SecretKey unwrapKey = catalog.asSecretKey(unwrapKeyEntry).orElseThrow(() ->
            new CryptoOpException(Code.KEY_NOT_FOUND, "언래핑 키를 찾을 수 없습니다: " + unwrapKeyEntry.alias()));

        Key recovered = unwrapRaw(provider, unwrapKey, wrapped, meta);
        access.makePersistent(recovered, newAlias);
        logger.info("키 언래핑·저장 완료: algo={} type={} newAlias={}",
            meta.algorithm(), meta.keyType(), newAlias);
        return recovered;
    }

    /** keyFile 옆의 {@code .meta.json}을 읽는다. */
    public WrapMetadata readMetadata(Path keyFile) throws CryptoOpException {
        Path metaFile = metaPathFor(keyFile);
        if (!Files.exists(metaFile)) {
            throw new CryptoOpException(Code.GENERAL,
                "메타데이터 파일이 없습니다: " + metaFile.getFileName()
                + " (래핑 시 함께 생성된 .meta.json 이 필요합니다)");
        }
        try {
            return MAPPER.readValue(metaFile.toFile(), WrapMetadata.class);
        } catch (IOException e) {
            throw new CryptoOpException(Code.GENERAL, "메타데이터 읽기 실패: " + e.getMessage(), e);
        }
    }

    /** {@code foo.key} → {@code foo.meta.json} */
    public static Path metaPathFor(Path keyFile) {
        String name = keyFile.getFileName().toString();
        String base = name.endsWith(".key") ? name.substring(0, name.length() - 4) : name;
        Path parent = keyFile.getParent();
        String metaName = base + ".meta.json";
        return parent == null ? Path.of(metaName) : parent.resolve(metaName);
    }

    /** AES-KWP 언래핑. provider 주입형이라 단위 테스트 가능. */
    static Key unwrapRaw(Provider provider, SecretKey unwrapKey, byte[] wrapped, WrapMetadata meta)
        throws CryptoOpException {
        AlgoSpec spec = KeyWrapper.aesKwpSpecFor(provider);
        int type = switch (meta.keyType()) {
            case "SECRET_KEY"  -> Cipher.SECRET_KEY;
            case "PRIVATE_KEY" -> Cipher.PRIVATE_KEY;
            case "PUBLIC_KEY"  -> Cipher.PUBLIC_KEY;
            default -> throw new CryptoOpException(Code.GENERAL, "알 수 없는 키 타입: " + meta.keyType());
        };
        try {
            Cipher c = Cipher.getInstance(spec.jceName(), provider);
            c.init(Cipher.UNWRAP_MODE, unwrapKey);
            return c.unwrap(wrapped, meta.algorithm(), type);
        } catch (Exception e) {
            throw new CryptoOpException(Code.GENERAL, "언래핑 실패: " + e.getMessage(), e);
        }
    }
}
