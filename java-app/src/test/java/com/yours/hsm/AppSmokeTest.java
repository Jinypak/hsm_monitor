package com.yours.hsm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AppSmokeTest {

    @Test
    void fxmlResourceExists() {
        assertNotNull(
            getClass().getResource("/fxml/main.fxml"),
            "main.fxml 이 classpath 에서 로드 가능해야 함"
        );
    }

    @Test
    void cssResourceExists() {
        assertNotNull(
            getClass().getResource("/css/dark.css"),
            "dark.css 가 classpath 에서 로드 가능해야 함"
        );
    }

    @Test
    void log4jConfigExists() {
        assertNotNull(
            getClass().getResource("/log4j2.xml"),
            "log4j2.xml 이 classpath 에서 로드 가능해야 함"
        );
    }

    @Test
    void placeholder() {
        assertEquals(2, 1 + 1);
    }
}
