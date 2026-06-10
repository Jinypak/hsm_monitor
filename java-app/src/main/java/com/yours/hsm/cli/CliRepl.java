package com.yours.hsm.cli;

import com.yours.hsm.algo.*;
import com.yours.hsm.core.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

/**
 * 대화형 REPL — {@code LunaSession} 을 받아 명령을 처리한다.
 * <p>JavaFX 의존 없음.
 */
final class CliRepl {

    private static final String PROMPT = "hsm> ";
    private final LunaSession session;

    CliRepl(LunaSession session) {
        this.session = session;
    }

    void run(BufferedReader in) throws IOException {
        System.out.print(PROMPT);
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (!line.isEmpty()) {
                if (!dispatch(line.split("\\s+", 2))) return;
            }
            System.out.print(PROMPT);
        }
    }

    /** @return false = 종료 */
    private boolean dispatch(String[] parts) {
        String cmd  = parts[0].toLowerCase();
        String rest = parts.length > 1 ? parts[1] : "";
        try {
            switch (cmd) {
                case "help",  "h"    -> printHelp();
                case "keys",  "ls"   -> cmdKeys();
                case "algolist"      -> cmdAlgoList();
                case "sign"          -> cmdSign(rest);
                case "verify"        -> cmdVerify(rest);
                case "encrypt", "enc"-> cmdEncrypt(rest);
                case "decrypt", "dec"-> cmdDecrypt(rest);
                case "mac"           -> cmdMac(rest);
                case "hash"          -> cmdHash(rest);
                case "pqc"           -> cmdPqc(rest);
                case "genkey"        -> cmdGenKey(rest);
                case "export-pub"    -> cmdExportPub(rest);
                case "quit", "exit", "q" -> { println("Disconnected."); return false; }
                default -> println("Unknown command: " + cmd + "  (type 'help')");
            }
        } catch (CryptoOpException e) {
            err("[FAIL] " + e.getMessage());
        } catch (Exception e) {
            err("[ERROR] " + e.getMessage());
        }
        return true;
    }

    // ── keys ─────────────────────────────────────────────────────────────
    private void cmdKeys() throws CryptoOpException {
        List<KeyCatalog.KeyEntry> keys = new KeyCatalog(session).list();
        if (keys.isEmpty()) { println("(no keys on token)"); return; }
        println(String.format("  %-30s %-8s %-10s %s", "alias", "kind", "algo", "bits"));
        println("  " + "-".repeat(60));
        for (var e : keys)
            println(String.format("  %-30s %-8s %-10s %s",
                e.alias(), e.kind(), e.algorithm(),
                e.keyBits() > 0 ? e.keyBits() : "-"));
        println("  total: " + keys.size());
    }

    // ── algolist ─────────────────────────────────────────────────────────
    private void cmdAlgoList() {
        ProviderProbe probe = ProviderProbe.of(session.provider());
        int ok = 0;
        for (AlgoSpec s : AlgoCatalog.all()) {
            boolean sup = probe.supports(s);
            if (sup) ok++;
            System.out.printf("  [%s] %-22s %-12s %s%n",
                sup ? "OK" : "  ", s.id(), s.op(), s.jceName());
        }
        println("  -> " + ok + " / " + AlgoCatalog.all().size() + " available");
    }

    // ── sign <algo> <key> <message> ───────────────────────────────────────
    private void cmdSign(String rest) throws Exception {
        String[] a = rest.split("\\s+", 3);
        requireArgs(a, 3, "sign <algo> <key> <message>");
        AlgoSpec spec = findSpec(a[0]);
        KeyPair kp = loadKeyPair(a[1]);
        byte[] msg = a[2].getBytes(StandardCharsets.UTF_8);
        OpResult r = new SignOp(session.provider(), spec, kp.getPrivate()).execute(msg);
        if (!r.ok()) { err("[FAIL] " + r.errorMsg().orElse("?")); return; }
        println("algo   : " + spec.jceName());
        println("key    : " + a[1]);
        println("sigLen : " + r.output().orElseThrow().length + " bytes");
        println("time   : " + String.format("%.2f ms", r.durationMs()));
        println("sig    : " + Base64.getEncoder().encodeToString(r.output().orElseThrow()));
    }

    // ── verify <algo> <key> <message> <sig-base64> ────────────────────────
    private void cmdVerify(String rest) throws Exception {
        String[] a = rest.split("\\s+", 4);
        requireArgs(a, 4, "verify <algo> <key> <message> <sig-base64>");
        AlgoSpec spec = findSpec(a[0]);
        KeyPair kp = loadKeyPair(a[1]);
        byte[] msg = a[2].getBytes(StandardCharsets.UTF_8);
        byte[] sig = Base64.getDecoder().decode(a[3]);
        boolean ok = new Verifier(null).verify(spec, kp.getPublic(), msg, sig);
        println("verify : " + (ok ? "PASS ✓" : "FAIL ✗"));
    }

    // ── encrypt <algo> <key> <text> ───────────────────────────────────────
    private void cmdEncrypt(String rest) throws Exception {
        String[] a = rest.split("\\s+", 3);
        requireArgs(a, 3, "encrypt <algo> <key> <text>");
        AlgoSpec spec = findSpec(a[0]);
        OpResult r = new EncryptOp(session.provider(), spec, resolveEncKey(spec, a[1], true),
            Cipher.ENCRYPT_MODE, null).execute(a[2].getBytes(StandardCharsets.UTF_8));
        if (!r.ok()) { err("[FAIL] " + r.errorMsg().orElse("?")); return; }
        println("ciphertext (base64): " + Base64.getEncoder().encodeToString(r.output().orElseThrow()));
        println("time: " + String.format("%.2f ms", r.durationMs()));
    }

    // ── decrypt <algo> <key> <ciphertext-base64> ─────────────────────────
    private void cmdDecrypt(String rest) throws Exception {
        String[] a = rest.split("\\s+", 3);
        requireArgs(a, 3, "decrypt <algo> <key> <ciphertext-base64>");
        AlgoSpec spec = findSpec(a[0]);
        byte[] ct = Base64.getDecoder().decode(a[2]);
        OpResult r = new EncryptOp(session.provider(), spec, resolveEncKey(spec, a[1], false),
            Cipher.DECRYPT_MODE, null).execute(ct);
        if (!r.ok()) { err("[FAIL] " + r.errorMsg().orElse("?")); return; }
        println("plaintext: " + new String(r.output().orElseThrow(), StandardCharsets.UTF_8));
        println("time: " + String.format("%.2f ms", r.durationMs()));
    }

    // ── mac <algo> <key> <text> ───────────────────────────────────────────
    private void cmdMac(String rest) throws Exception {
        String[] a = rest.split("\\s+", 3);
        requireArgs(a, 3, "mac <algo> <key> <text>");
        AlgoSpec spec = findSpec(a[0]);
        SecretKey key = loadSecretKey(a[1]);
        OpResult r = new MacOp(session.provider(), spec, key)
            .execute(a[2].getBytes(StandardCharsets.UTF_8));
        if (!r.ok()) { err("[FAIL] " + r.errorMsg().orElse("?")); return; }
        println("mac (hex): " + toHex(r.output().orElseThrow()));
        println("time: " + String.format("%.2f ms", r.durationMs()));
    }

    // ── hash <algo> <text> ────────────────────────────────────────────────
    private void cmdHash(String rest) throws Exception {
        String[] a = rest.split("\\s+", 2);
        requireArgs(a, 2, "hash <algo> <text>");
        AlgoSpec spec = findSpec(a[0]);
        OpResult r = new DigestOp(session.provider(), spec)
            .execute(a[1].getBytes(StandardCharsets.UTF_8));
        if (!r.ok()) { err("[FAIL] " + r.errorMsg().orElse("?")); return; }
        println("hash (hex): " + toHex(r.output().orElseThrow()));
        println("time: " + String.format("%.2f ms", r.durationMs()));
    }

    // ── pqc <algo> <key> [message] ────────────────────────────────────────
    private void cmdPqc(String rest) throws Exception {
        String[] a = rest.split("\\s+", 3);
        requireArgs(a, 2, "pqc <algo> <key> [message]");
        String paramSet = a[0];
        String keyAlias = a[1];
        byte[] msg = a.length > 2 ? a[2].getBytes(StandardCharsets.UTF_8)
                                  : "HSM CLI PQC test".getBytes(StandardCharsets.UTF_8);
        boolean isKem = paramSet.toUpperCase().contains("KEM");

        KeyCatalog cat = new KeyCatalog(session);
        KeyCatalog.KeyEntry entry = cat.findByAlias(keyAlias)
            .orElseThrow(() -> new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                "Key not found: " + keyAlias));
        PublicKey  pub  = cat.asPublicKey(entry).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "No public key: " + keyAlias));
        PrivateKey priv = cat.asPrivateKey(entry).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "No private key: " + keyAlias));
        KeyPair kp = new KeyPair(pub, priv);

        PqcService pqc = new PqcService(session.provider());
        if (isKem) {
            PqcService.KemResult r = pqc.kemRoundtrip(kp);
            println("algo         : " + kp.getPublic().getAlgorithm());
            println("encapsulation: " + r.encapsulation().length + " bytes");
            println("enc time     : " + String.format("%.2f ms", r.encMs()));
            println("dec time     : " + String.format("%.2f ms", r.decMs()));
            println("secret match : " + (r.match() ? "PASS ✓" : "FAIL ✗") + " (HMAC fingerprint)");
        } else {
            PqcService.SignResult r = pqc.signVerify(kp, msg);
            println("algo     : " + kp.getPublic().getAlgorithm());
            println("sig len  : " + r.signature().length + " bytes");
            println("sign     : " + String.format("%.2f ms", r.signMs()));
            println("verify   : " + String.format("%.2f ms", r.verifyMs()));
            println("verified : " + (r.verified() ? "PASS ✓" : "FAIL ✗"));
        }
    }

    // ── genkey <algo> <label> [size|curve] ───────────────────────────────
    private void cmdGenKey(String rest) throws Exception {
        String[] a = rest.split("\\s+", 3);
        requireArgs(a, 2, "genkey <algo> <label> [size|curve|paramset]");
        String algo  = a[0].toUpperCase();
        String alias = a[1];
        String param = a.length > 2 ? a[2] : null;
        KeyManager mgr = new KeyManager(session);
        switch (algo) {
            case "AES"    -> mgr.generateAes(alias, param != null ? Integer.parseInt(param) : 256);
            case "RSA"    -> mgr.generateRsa(alias, param != null ? Integer.parseInt(param) : 2048);
            case "EC"     -> mgr.generateEc(alias, param != null ? param : "secp256r1");
            case "DES3"   -> mgr.generateSecret("DESede", alias, 168);
            case "ARIA"   -> mgr.generateSecret("ARIA", alias, param != null ? Integer.parseInt(param) : 256);
            case "ML-DSA", "MLDSA" -> mgr.generateMlDsa(alias, param != null ? param : "ML-DSA-65");
            case "ML-KEM", "MLKEM" -> mgr.generateMlKem(alias, param != null ? param : "ML-KEM-768");
            default -> { err("Unknown algo: " + algo + " (AES/RSA/EC/DES3/ARIA/ML-DSA/ML-KEM)"); return; }
        }
        println("Generated: " + alias + " (" + algo + ")");
    }

    // ── export-pub <key> <file.pem> ───────────────────────────────────────
    private void cmdExportPub(String rest) throws Exception {
        String[] a = rest.split("\\s+", 2);
        requireArgs(a, 2, "export-pub <key> <file.pem>");
        KeyCatalog cat = new KeyCatalog(session);
        KeyCatalog.KeyEntry entry = cat.findByAlias(a[0])
            .orElseThrow(() -> new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                "Key not found: " + a[0]));
        PublicKey pub = cat.asPublicKey(entry).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "No public key: " + a[0]));
        java.nio.file.Path out = PublicKeyExporter.write(java.nio.file.Path.of(a[1]), pub);
        println("Exported: " + out.toAbsolutePath());
    }

    // ── help ─────────────────────────────────────────────────────────────
    private void printHelp() {
        println("");
        println("  keys                                  List token keys");
        println("  algolist                              Show algorithm availability");
        println("  sign     <algo> <key> <msg>           Sign message");
        println("  verify   <algo> <key> <msg> <sig-b64> Verify signature");
        println("  encrypt  <algo> <key> <text>          Encrypt (output: base64)");
        println("  decrypt  <algo> <key> <ct-base64>     Decrypt");
        println("  mac      <algo> <key> <text>          Compute MAC");
        println("  hash     <algo> <text>                Compute hash (no key needed)");
        println("  pqc      <paramset> <key> [msg]       ML-DSA sign/verify or ML-KEM encap");
        println("  genkey   <algo> <label> [size|curve]  Generate key on token");
        println("  export-pub <key> <file.pem>           Export public key to PEM/DER");
        println("  quit / exit                           Disconnect and exit");
        println("");
        println("  Examples:");
        println("    keys");
        println("    sign SHA256withRSA mykey 'hello world'");
        println("    encrypt AES_GCM myaes 'secret data'");
        println("    decrypt AES_GCM myaes <base64>");
        println("    mac HmacSHA256 myaes 'data'");
        println("    hash SHA3-256 'data'");
        println("    pqc ML-DSA-65 mymldsa 'sign this'");
        println("    pqc ML-KEM-768 mymlkem");
        println("    genkey RSA myrsa2 4096");
        println("    genkey ML-DSA mymldsa ML-DSA-65");
        println("    export-pub myrsa-pub /tmp/pub.pem");
        println("");
    }

    // ── helpers ───────────────────────────────────────────────────────────
    private AlgoSpec findSpec(String id) throws CryptoOpException {
        // id 또는 jceName 으로 검색
        return AlgoCatalog.all().stream()
            .filter(s -> s.id().equalsIgnoreCase(id) || s.jceName().equalsIgnoreCase(id))
            .findFirst()
            .orElseThrow(() -> new CryptoOpException(CryptoOpException.Code.MECH_NOT_SUPPORTED,
                "Unknown algo: " + id + "  (try 'algolist')"));
    }

    private KeyPair loadKeyPair(String alias) throws CryptoOpException {
        KeyCatalog cat = new KeyCatalog(session);
        KeyCatalog.KeyEntry e = cat.findByAlias(alias)
            .orElseThrow(() -> new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                "Key not found: " + alias));
        PublicKey  pub  = cat.asPublicKey(e).orElse(null);
        PrivateKey priv = cat.asPrivateKey(e).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "No private key: " + alias));
        return new KeyPair(pub, priv);
    }

    private SecretKey loadSecretKey(String alias) throws CryptoOpException {
        KeyCatalog cat = new KeyCatalog(session);
        KeyCatalog.KeyEntry e = cat.findByAlias(alias)
            .orElseThrow(() -> new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                "Key not found: " + alias));
        return cat.asSecretKey(e).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND, "Not a secret key: " + alias));
    }

    private java.security.Key resolveEncKey(AlgoSpec spec, String alias, boolean encrypt)
        throws CryptoOpException {
        boolean sym = switch (spec.family()) {
            case AES, ARIA, SM4, DES, DES3, RC, CAST -> true;
            default -> false;
        };
        if (sym) return loadSecretKey(alias);
        return encrypt ? loadKeyPair(alias).getPublic() : loadKeyPair(alias).getPrivate();
    }

    private static void requireArgs(String[] a, int n, String usage) throws CryptoOpException {
        if (a.length < n || a[0].isEmpty())
            throw new CryptoOpException(CryptoOpException.Code.GENERAL, "Usage: " + usage);
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static void println(String s) { System.out.println(s); }
    private static void err(String s)     { System.err.println(s); }
}
