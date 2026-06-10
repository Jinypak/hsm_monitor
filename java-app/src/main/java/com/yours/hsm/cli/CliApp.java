package com.yours.hsm.cli;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.core.LunaSession;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

/**
 * HSM Monitor CLI — Linux headless 환경 전용.
 * <p>실행: {@code ./vision cli}
 * <p>메인 메뉴 → 0(헬스 체크) / 1(파티션 접속 → PIN 입력 → REPL)
 */
public final class CliApp {

    private static final BufferedReader IN =
        new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    public static void main(String[] args) throws Exception {
        printBanner();
        mainMenu();
    }

    // ── 메인 메뉴 ──────────────────────────────────────────────
    private static void mainMenu() throws Exception {
        while (true) {
            System.out.println();
            System.out.println("  0. Health check");
            System.out.println("  1. Connect to partition");
            System.out.println("  q. Quit");
            System.out.print("\nSelect: ");
            System.out.flush();

            String input = readLine();
            switch (input) {
                case "0" -> healthCheck();
                case "1" -> connectMenu();
                case "q", "quit", "exit" -> { System.out.println("Bye."); return; }
                default  -> System.out.println("  Invalid selection.");
            }
        }
    }

    // ── 접속 메뉴 ──────────────────────────────────────────────
    private static void connectMenu() throws Exception {
        System.out.print("  Slot [0]: ");
        System.out.flush();
        String slotInput = readLine().trim();
        int slot;
        try {
            slot = slotInput.isEmpty() ? 0 : Integer.parseInt(slotInput);
        } catch (NumberFormatException e) {
            System.out.println("  Invalid slot number.");
            return;
        }

        System.out.print("  PIN: ");
        System.out.flush();
        String pin = readLine().trim();
        if (pin.isEmpty()) {
            System.out.println("  PIN cannot be empty.");
            return;
        }

        System.out.println("\nConnecting to slot " + slot + "...");
        try (LunaSession session = LunaSession.connect(slot, pin.toCharArray())) {
            pin = null; // PIN 참조 즉시 해제
            System.out.println("[OK] Connected: " + session.tokenLabel()
                + "  |  type 'help' for commands\n");
            new CliRepl(session).run(IN);
        } catch (CryptoOpException e) {
            System.err.println("[ERROR] " + e.getMessage());
        }
    }

    // ── 헬스 체크 ─────────────────────────────────────────────
    private static void healthCheck() {
        System.out.println("\nHealth check...");

        // 1) LunaProvider
        try {
            Provider luna = Security.getProvider("LunaProvider");
            if (luna == null) {
                Class<?> cls = Class.forName("com.safenetinc.luna.provider.LunaProvider");
                luna = (Provider) cls.getDeclaredConstructor().newInstance();
                Security.addProvider(luna);
            }
            System.out.printf("  [OK] LunaProvider v%s%n", luna.getVersionStr());
        } catch (Throwable t) {
            System.err.println("  [FAIL] LunaProvider: " + t.getMessage());
        }

        // 2) 네이티브 라이브러리
        String[] candidates = {
            System.getProperty("java.library.path", "").split(":")[0] + "/libLunaAPI.so",
            "/usr/safenet/lunaclient/jsp/lib/libLunaAPI.so",
            "/usr/lib/libLunaAPI.so"
        };
        boolean found = false;
        for (String p : candidates) {
            if (Files.exists(Path.of(p))) {
                System.out.println("  [OK] Native library: " + p);
                found = true;
                break;
            }
        }
        if (!found) {
            System.err.println("  [WARN] libLunaAPI.so not found in common paths");
        }
    }

    // ── 공통 ─────────────────────────────────────────────────
    private static String readLine() throws Exception {
        String line = IN.readLine();
        return line == null ? "" : line;
    }

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════╗");
        System.out.println("║   HSM Monitor CLI                ║");
        System.out.println("║   Thales Luna HSM                ║");
        System.out.println("╚══════════════════════════════════╝");
    }
}
