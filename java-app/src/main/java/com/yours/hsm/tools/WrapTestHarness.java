package com.yours.hsm.tools;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/**
 * 동일한 ML-DSA-65 키 + AES-256 DEK 를 두 가지 방식으로 래핑해 비교한다.
 *
 * 출력 파일 (C:/Program Files/SafeNet/LunaClient/):
 *   shared_mldsa65_priv.der          공통 ML-DSA-65 개인키 PKCS#8 DER
 *   shared_dek.hex                   공통 AES-256 DEK (hex)
 *   java_mldsa65_wrapped.bin         SunJCE AESWrapPad 래핑 결과
 *   openssl_mldsa65_wrapped.bin      openssl enc -aes-256-wrap-pad -nosalt 결과
 *   openssl2_mldsa65_wrapped.bin     openssl enc -aes-256-wrap-pad (-nosalt 없음) 결과
 *
 * 실행: ./gradlew wrapTest
 */
public class WrapTestHarness {

    static final Path   OUT   = Path.of("C:/Program Files/SafeNet/LunaClient");
    static final String MLDSA = "ML-DSA-65";

    public static void main(String[] args) throws Exception {
        Files.createDirectories(OUT);

        // ── 공통 재료 생성 ────────────────────────────────────
        KeyPair pair = KeyPairGenerator.getInstance(MLDSA).generateKeyPair();
        byte[] privDer = pair.getPrivate().getEncoded();   // PKCS#8 DER

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey dek = kg.generateKey();
        String dekHex = HexFormat.of().formatHex(dek.getEncoded());

        write("shared_mldsa65_priv.der", privDer);
        write("shared_mldsa65_pub.der", pair.getPublic().getEncoded());
        writeStr("shared_dek.hex", dekHex);

        log("=== 공통 재료 ===");
        log("ML-DSA-65 개인키   : %d bytes (PKCS#8 DER)".formatted(privDer.length));
        log("AES-256 DEK        : %s".formatted(dekHex));

        // ── 방법 1: Java SunJCE AESWrapPad ─────────────────
        log("\n=== [JAVA] SunJCE AESWrapPad ===");
        javaWrap(pair, dek, dekHex, privDer);

        // ── 방법 2: OpenSSL (ProcessBuilder) ────────────────
        log("\n=== [OPENSSL] openssl enc -aes-256-wrap-pad ===");
        opensslWrap(dekHex, privDer);

        // ── 비교 요약 ─────────────────────────────────────
        log("\n=== 파일 크기 비교 ===");
        for (String name : new String[]{
                "java_mldsa65_wrapped.bin",
                "openssl_mldsa65_wrapped.bin",
                "openssl2_mldsa65_wrapped.bin"}) {
            Path f = OUT.resolve(name);
            if (Files.exists(f)) log("  %-40s : %d bytes".formatted(name, Files.size(f)));
        }

        // Java vs OpenSSL 바이트 비교
        Path jf = OUT.resolve("java_mldsa65_wrapped.bin");
        Path of = OUT.resolve("openssl_mldsa65_wrapped.bin");
        if (Files.exists(jf) && Files.exists(of)) {
            boolean same = Arrays.equals(Files.readAllBytes(jf), Files.readAllBytes(of));
            log("java vs openssl(-nosalt) 동일: " + same);
        }
    }

    // ── Java SunJCE ──────────────────────────────────────────
    static void javaWrap(KeyPair pair, SecretKey dek, String dekHex, byte[] privDer)
        throws Exception {

        var sun    = Security.getProvider("SunJCE");
        var privKey = KeyFactory.getInstance(MLDSA)
            .generatePrivate(new PKCS8EncodedKeySpec(privDer));

        Cipher wrapCipher = Cipher.getInstance("AESWrapPad", sun);
        wrapCipher.init(Cipher.WRAP_MODE, dek);
        byte[] wrapped = wrapCipher.wrap(privKey);

        write("java_mldsa65_wrapped.bin", wrapped);
        writeStr("java_dek.hex", dekHex);
        log("java_mldsa65_wrapped.bin : %d bytes".formatted(wrapped.length));
        log("첫 8바이트               : %s".formatted(hex8(wrapped)));

        // 라운드트립 검증
        Cipher unwrap = Cipher.getInstance("AESWrapPad", sun);
        unwrap.init(Cipher.UNWRAP_MODE, dek);
        var recovered = unwrap.unwrap(wrapped, MLDSA, Cipher.PRIVATE_KEY);
        boolean ok = Arrays.equals(privDer, recovered.getEncoded());
        log("Java 라운드트립          : " + (ok ? "✅ 성공" : "❌ 실패"));
    }

    // ── OpenSSL (ProcessBuilder) ─────────────────────────────
    static void opensslWrap(String dekHex, byte[] privDer) throws Exception {
        Path inFile = OUT.resolve("shared_mldsa65_priv.der");

        // 시도 1: -nosalt 포함 (사용자가 했던 방식)
        Path out1 = OUT.resolve("openssl_mldsa65_wrapped.bin");
        log("▶ openssl enc -aes-256-wrap-pad -K <dek> -nosalt");
        int rc1 = exec(out1, "openssl", "enc", "-aes-256-wrap-pad",
            "-K", dekHex, "-nosalt",
            "-in", inFile.toString(), "-out", out1.toString());
        if (rc1 == 0 && Files.exists(out1) && Files.size(out1) > 0) {
            byte[] b = Files.readAllBytes(out1);
            log("  출력: %d bytes, 첫 8바이트: %s".formatted(b.length, hex8(b)));
            roundtripOpenssl(dekHex, out1, "openssl_verify.der", "-nosalt");
        } else {
            log("  ❌ 래핑 실패 (rc=%d)".formatted(rc1));
        }

        // 시도 2: -nosalt 없음
        Path out2 = OUT.resolve("openssl2_mldsa65_wrapped.bin");
        log("▶ openssl enc -aes-256-wrap-pad -K <dek>  (-nosalt 없음)");
        int rc2 = exec(out2, "openssl", "enc", "-aes-256-wrap-pad",
            "-K", dekHex,
            "-in", inFile.toString(), "-out", out2.toString());
        if (rc2 == 0 && Files.exists(out2) && Files.size(out2) > 0) {
            byte[] b = Files.readAllBytes(out2);
            log("  출력: %d bytes, 첫 8바이트: %s".formatted(b.length, hex8(b)));
            roundtripOpenssl(dekHex, out2, "openssl2_verify.der");
        } else {
            log("  ❌ 래핑 실패 (rc=%d)".formatted(rc2));
        }
    }

    static void roundtripOpenssl(String dekHex, Path inFile, String outName, String... extra)
        throws Exception {
        Path outFile = OUT.resolve(outName);
        var cmd = new java.util.ArrayList<String>();
        cmd.addAll(java.util.List.of("openssl", "enc", "-d", "-aes-256-wrap-pad", "-K", dekHex));
        cmd.addAll(java.util.List.of(extra));
        cmd.addAll(java.util.List.of("-in", inFile.toString(), "-out", outFile.toString()));
        int rc = exec(outFile, cmd.toArray(new String[0]));
        boolean ok = rc == 0 && Files.exists(outFile) && Files.size(outFile) > 0;
        log("  라운드트립               : " + (ok
            ? "✅ 성공 (%d bytes)".formatted(Files.size(outFile))
            : "❌ 실패"));
    }

    // ── 유틸 ────────────────────────────────────────────────
    static int exec(Path ignored, String... cmd) throws Exception {
        var pb = new ProcessBuilder(cmd)
            .directory(OUT.toFile())
            .redirectErrorStream(true);
        var proc = pb.start();
        String out = new String(proc.getInputStream().readAllBytes()).trim();
        if (!out.isBlank()) log("  [stderr] " + out);
        return proc.waitFor();
    }

    static String hex8(byte[] b) {
        return HexFormat.of().formatHex(Arrays.copyOf(b, Math.min(8, b.length)));
    }

    static void write(String name, byte[] data) throws Exception {
        Files.write(OUT.resolve(name), data);
    }

    static void writeStr(String name, String text) throws Exception {
        Files.writeString(OUT.resolve(name), text);
    }

    static void log(String msg) { System.out.println(msg); }
}
