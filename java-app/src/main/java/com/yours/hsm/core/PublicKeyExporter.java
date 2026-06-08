package com.yours.hsm.core;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.algo.CryptoOpException.Code;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Base64;

/**
 * 토큰의 공개키를 표준 X.509 SubjectPublicKeyInfo(DER/PEM) 파일로 내보낸다.
 * <p>
 * 공개키는 비밀이 아니므로 래핑 없이 그대로 추출 가능하다({@code PublicKey.getEncoded()}
 * 가 X.509 인코딩을 반환). {@code ImportPublicKeyHarness} 의 역방향에 해당.
 * <p>JavaFX 미사용 — CLI/테스트에서도 쓸 수 있다.
 */
public final class PublicKeyExporter {

    private static final Logger logger = LoggerFactory.getLogger(PublicKeyExporter.class);

    private PublicKeyExporter() {}

    /** X.509 SubjectPublicKeyInfo (DER) 바이트열. */
    public static byte[] der(PublicKey key) throws CryptoOpException {
        byte[] enc = key.getEncoded();
        if (enc == null || enc.length == 0) {
            throw new CryptoOpException(Code.GENERAL,
                "공개키 인코딩을 얻을 수 없습니다 (algorithm=" + key.getAlgorithm() + ")");
        }
        return enc;
    }

    /** PEM 텍스트({@code -----BEGIN PUBLIC KEY-----} … base64 64열 … END). */
    public static String pem(PublicKey key) throws CryptoOpException {
        String b64 = Base64.getEncoder().encodeToString(der(key));
        StringBuilder sb = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END PUBLIC KEY-----\n");
        return sb.toString();
    }

    /**
     * 파일로 저장한다. 확장자가 {@code .pem} 이면 PEM 텍스트, 그 외(.der/.key 등)는 DER 바이너리.
     * @return 저장된 경로
     */
    public static Path write(Path file, PublicKey key) throws CryptoOpException {
        try {
            boolean pem = file.getFileName().toString().toLowerCase().endsWith(".pem");
            if (pem) {
                Files.writeString(file, pem(key), StandardCharsets.US_ASCII);
            } else {
                Files.write(file, der(key));
            }
            logger.info("공개키 내보내기: {} ({}, algorithm={})",
                file, pem ? "PEM" : "DER", key.getAlgorithm());
            return file;
        } catch (IOException e) {
            throw new CryptoOpException(Code.GENERAL, "공개키 파일 저장 실패: " + e.getMessage(), e);
        }
    }
}
