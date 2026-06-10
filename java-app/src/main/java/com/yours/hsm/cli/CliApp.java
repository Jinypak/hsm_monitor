package com.yours.hsm.cli;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.core.LunaSession;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

/**
 * HSM Monitor CLI — Linux headless 환경 전용.
 * <p>실행: {@code ./vision cli}
 * <p>헬스체크 → 슬롯/PIN 대화형 입력 → REPL 시작.
 */
public final class CliApp {

    public static void main(String[] args) throws Exception {
        printBanner();

        // ── 헬스체크 ───────────────────────────────────────────────
        if (!healthCheck()) {
            System.err.println("\n[ABORT] Health check failed. Check Luna client installation.");
            System.exit(1);
        }

        // ── 슬롯 / PIN 대화형 입력 ─────────────────────────────────
        Console console = System.console();
        BufferedReader reader = console == null
            ? new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))
            : null;

        int    slot = readSlot(console, reader);
        char[] pin  = readPin(console, reader);

        // ── 연결 ──────────────────────────────────────────────────
        System.out.println("\nConnecting to slot " + slot + "...");
        try (LunaSession session = LunaSession.connect(slot, pin)) {
            java.util.Arrays.fill(pin, '\0'); // PIN 메모리 즉시 소거
            System.out.println("[OK] Connected: " + session.tokenLabel()
                + "  |  type 'help' for commands\n");
            new CliRepl(session).run(
                console != null
                    ? new BufferedReader(console.reader())
                    : reader);
        } catch (CryptoOpException e) {
            System.err.println("[ERROR] " + e.getMessage());
            System.exit(1);
        }
    }

    // ── 헬스체크 ───────────────────────────────────────────────────
    private static boolean healthCheck() {
        System.out.println("Health check...");
        boolean ok = true;

        // 1) LunaProvider 로드 가능 여부
        try {
            Provider luna = Security.getProvider("LunaProvider");
            if (luna == null) {
                Class<?> cls = Class.forName("com.safenetinc.luna.provider.LunaProvider");
                luna = (Provider) cls.getDeclaredConstructor().newInstance();
                Security.addProvider(luna);
            }
            System.out.printf("  [OK] LunaProvider v%s%n", luna.getVersionStr());
        } catch (Throwable t) {
            System.err.println("  [FAIL] LunaProvider not found: " + t.getMessage());
            ok = false;
        }

        // 2) 네이티브 라이브러리 존재 확인
        String[] candidates = {
            System.getProperty("java.library.path", "").split(":")[0] + "/libLunaAPI.so",
            "/usr/jsp/lib/libLunaAPI.so",
            "/usr/lib/libLunaAPI.so",
            "/usr/local/lib/libLunaAPI.so"
        };
        boolean libFound = false;
        for (String path : candidates) {
            if (Files.exists(Path.of(path))) {
                System.out.println("  [OK] Native library: " + path);
                libFound = true;
                break;
            }
        }
        if (!libFound) {
            System.err.println("  [WARN] libLunaAPI.so not found in common paths");
            System.err.println("         Set -Djava.library.path=<dir> if in a custom location");
            // WARN 수준 — 실제 로드는 JVM이 처리하므로 abort 하지 않음
        }

        return ok;
    }

    // ── 입력 헬퍼 ─────────────────────────────────────────────────
    private static int readSlot(Console console, BufferedReader reader) throws Exception {
        while (true) {
            String input = prompt(console, reader, "Slot [0]: ").trim();
            if (input.isEmpty()) return 0;
            try {
                int v = Integer.parseInt(input);
                if (v >= 0) return v;
            } catch (NumberFormatException ignored) {}
            System.err.println("  Invalid slot number. Please enter a non-negative integer.");
        }
    }

    private static char[] readPin(Console console, BufferedReader reader) throws Exception {
        if (console != null) {
            char[] pin = console.readPassword("PIN: ");
            if (pin != null && pin.length > 0) return pin;
            System.err.println("  PIN cannot be empty.");
            return readPin(console, null);
        }
        // fallback (no tty — PIN visible)
        System.err.println("  [WARN] No TTY detected — PIN will be visible");
        System.out.print("PIN: ");
        System.out.flush();
        String line = reader.readLine();
        if (line == null || line.isEmpty()) {
            System.err.println("  PIN cannot be empty.");
            return readPin(null, reader);
        }
        return line.toCharArray();
    }

    private static String prompt(Console console, BufferedReader reader, String msg) throws Exception {
        if (console != null) return console.readLine(msg);
        System.out.print(msg);
        System.out.flush();
        String line = reader.readLine();
        return line == null ? "" : line;
    }

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════╗");
        System.out.println("║   HSM Monitor CLI                ║");
        System.out.println("║   Thales Luna HSM                ║");
        System.out.println("╚══════════════════════════════════╝");
        System.out.println();
    }
}
