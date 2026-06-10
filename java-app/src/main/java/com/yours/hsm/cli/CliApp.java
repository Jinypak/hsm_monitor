package com.yours.hsm.cli;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.core.LunaSession;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * HSM Monitor CLI — Linux headless 환경 전용.
 * <p>실행: {@code ./vision cli -s <slot> -p <pin>}
 * <p>연결 후 대화형 명령을 입력한다. {@code help} 로 명령 목록 확인.
 */
public final class CliApp {

    public static void main(String[] args) throws Exception {
        int    slot = 0;
        String pin  = null;

        for (int i = 0; i < args.length - 1; i++) {
            if ("-s".equals(args[i]) || "--slot".equals(args[i])) slot = Integer.parseInt(args[i + 1]);
            if ("-p".equals(args[i]) || "--pin".equals(args[i]))  pin  = args[i + 1];
        }

        if (pin == null) {
            System.err.println("Usage: vision cli -s <slot> -p <pin>");
            System.exit(1);
        }

        System.out.println("HSM Monitor CLI — connecting to slot " + slot + "...");
        try (LunaSession session = LunaSession.connect(slot, pin.toCharArray())) {
            System.out.println("Connected: " + session.tokenLabel()
                + "  |  type 'help' for commands");
            new CliRepl(session).run(
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)));
        } catch (CryptoOpException e) {
            System.err.println("[ERROR] " + e.getMessage());
            System.exit(1);
        }
    }
}
