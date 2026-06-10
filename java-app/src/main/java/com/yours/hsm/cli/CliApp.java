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

        String pin = readPin().trim();
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

    /**
     * PIN 을 입력받되 화면에는 {@code *} 로 마스킹한다.
     * <p>Gradle 경유 실행 시 {@code System.console()} 이 null 이므로,
     * Linux/macOS 에서는 {@code stty} 로 터미널 에코를 끄고 글자마다 {@code *} 를 출력한다.
     * TTY 가 없거나(파이프/CI) Windows 면 마스킹 없이 평문 입력으로 폴백한다.
     */
    private static String readPin() throws Exception {
        // 1) 진짜 콘솔이 있으면 readPassword (직접 java 실행 등)
        java.io.Console console = System.console();
        if (console != null) {
            char[] p = console.readPassword("  PIN: ");
            return p == null ? "" : new String(p);
        }

        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");

        // 2) Linux/macOS: stty 로 에코 끄고 글자마다 '*' 출력
        if (!isWindows && sttyAvailable()) {
            try {
                stty("-echo -icanon min 1");
                System.out.print("  PIN: ");
                System.out.flush();
                StringBuilder sb = new StringBuilder();
                int ch;
                while ((ch = IN.read()) != -1) {
                    if (ch == '\n' || ch == '\r') break;
                    if (ch == 127 || ch == 8) {           // Backspace/DEL
                        if (sb.length() > 0) {
                            sb.deleteCharAt(sb.length() - 1);
                            System.out.print("\b \b");
                            System.out.flush();
                        }
                        continue;
                    }
                    sb.append((char) ch);
                    System.out.print('*');
                    System.out.flush();
                }
                System.out.println(); // 사용자 Enter 는 에코 안 됨 → 줄바꿈 수동
                return sb.toString();
            } finally {
                stty("echo icanon");   // 터미널 모드 복원
            }
        }

        // 3) 폴백 — 평문(보임)
        System.out.print("  PIN (visible): ");
        System.out.flush();
        return readLine();
    }

    private static boolean sttyAvailable() {
        try {
            // stty 존재 + /dev/tty 접근(제어 터미널 보유) 둘 다 확인.
            // Gradle 데몬 등 터미널이 없는 환경이면 false → 평문 폴백(에러 스팸 방지).
            return new ProcessBuilder("sh", "-c", "stty -a < /dev/tty >/dev/null 2>&1")
                .start().waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static void stty(String flags) throws Exception {
        new ProcessBuilder("sh", "-c", "stty " + flags + " < /dev/tty")
            .inheritIO().start().waitFor();
    }

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════╗");
        System.out.println("║   HSM Monitor CLI                ║");
        System.out.println("║   Thales Luna HSM                ║");
        System.out.println("╚══════════════════════════════════╝");
    }
}
