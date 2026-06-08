package com.yours.hsm;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** 사용 매뉴얼 리소스가 존재하고 주제(# 헤더)가 충분히 들어있는지 검증. */
class ManualResourceTest {

    @Test
    void manual_existsAndHasTopics() throws Exception {
        InputStream in = getClass().getResourceAsStream("/manual/manual.md");
        assertNotNull(in, "/manual/manual.md 리소스가 존재해야 함");

        int topics = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("# ")) topics++;
            }
        }
        assertTrue(topics >= 8, "매뉴얼 주제가 8개 이상이어야 함 (실제: " + topics + ")");
    }
}
