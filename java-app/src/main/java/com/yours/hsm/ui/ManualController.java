package com.yours.hsm.ui;

import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 사용 매뉴얼 탭 — 리소스({@code /manual/manual.md})를 주제별로 나눠
 * 좌측 목록 + 우측 본문으로 보여준다. HSM 연결 불필요(정적 도움말).
 * <p>
 * 형식: 라인 머리의 {@code # 제목} 이 새 주제를 시작하고, 다음 {@code # } 전까지가 본문.
 */
public final class ManualController {

    private static final Logger logger = LoggerFactory.getLogger(ManualController.class);

    @FXML private ListView<String> topicList;
    @FXML private TextArea         contentArea;

    /** 제목 → 본문 (목록 순서 유지). */
    private final List<String> titles  = new ArrayList<>();
    private final List<String> bodies  = new ArrayList<>();

    @FXML
    public void initialize() {
        load();
        topicList.getItems().setAll(titles);
        topicList.getSelectionModel().selectedIndexProperty().addListener((o, a, b) -> {
            int i = b.intValue();
            contentArea.setText(i >= 0 && i < bodies.size() ? bodies.get(i) : "");
            contentArea.positionCaret(0);
        });
        if (!titles.isEmpty()) topicList.getSelectionModel().selectFirst();
    }

    private void load() {
        InputStream in = getClass().getResourceAsStream("/manual/manual.md");
        if (in == null) {
            logger.warn("매뉴얼 리소스를 찾을 수 없습니다: /manual/manual.md");
            titles.add("매뉴얼 없음");
            bodies.add("매뉴얼 리소스를 불러오지 못했습니다.");
            return;
        }
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder body = new StringBuilder();
            String title = null;
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("# ")) {
                    if (title != null) { titles.add(title); bodies.add(body.toString().strip()); }
                    title = line.substring(2).strip();
                    body.setLength(0);
                } else {
                    body.append(line).append('\n');
                }
            }
            if (title != null) { titles.add(title); bodies.add(body.toString().strip()); }
            logger.info("매뉴얼 로드: {}개 주제", titles.size());
        } catch (IOException e) {
            logger.warn("매뉴얼 로드 실패", e);
            if (titles.isEmpty()) { titles.add("오류"); bodies.add("매뉴얼 로드 실패: " + e.getMessage()); }
        }
    }
}
