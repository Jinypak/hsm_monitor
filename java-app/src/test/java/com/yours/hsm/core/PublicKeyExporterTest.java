package com.yours.hsm.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;

import static org.junit.jupiter.api.Assertions.*;

class PublicKeyExporterTest {

    private static PublicKey rsaPublic() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair().getPublic();
    }

    @Test
    void der_roundTripsThroughX509Spec() throws Exception {
        PublicKey pub = rsaPublic();
        byte[] der = PublicKeyExporter.der(pub);

        // X.509 SubjectPublicKeyInfo 로 다시 파싱되어 동일한 키여야 함
        PublicKey parsed = KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(der));
        assertArrayEquals(pub.getEncoded(), parsed.getEncoded());
    }

    @Test
    void pem_hasHeaderFooterAndDecodesToDer() throws Exception {
        PublicKey pub = rsaPublic();
        String pem = PublicKeyExporter.pem(pub);

        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(pem.trim().endsWith("-----END PUBLIC KEY-----"));

        String b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s", "");
        assertArrayEquals(pub.getEncoded(), java.util.Base64.getDecoder().decode(b64));
    }

    @Test
    void write_pemExtension_writesText(@TempDir Path dir) throws Exception {
        Path out = PublicKeyExporter.write(dir.resolve("key.pem"), rsaPublic());
        assertTrue(Files.exists(out));
        String content = Files.readString(out);
        assertTrue(content.contains("BEGIN PUBLIC KEY"));
    }

    @Test
    void write_derExtension_writesBinary(@TempDir Path dir) throws Exception {
        PublicKey pub = rsaPublic();
        Path out = PublicKeyExporter.write(dir.resolve("key.der"), pub);
        assertArrayEquals(pub.getEncoded(), Files.readAllBytes(out));
    }
}
