package com.yours.hsm.ui;

import com.yours.hsm.algo.AlgoCatalog;
import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.algo.OpResult;
import com.yours.hsm.core.*;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.DirectoryChooser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public final class SignVerifyController {

    private static final Logger logger = LoggerFactory.getLogger(SignVerifyController.class);
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    @FXML private ComboBox<AlgoSpec>           mechCombo;
    @FXML private ComboBox<KeyCatalog.KeyEntry> keyCombo;
    @FXML private Slider    rateSlider;
    @FXML private Label     rateLabel;
    @FXML private CheckBox  extVerifyCheck;
    @FXML private Button    startBtn;
    @FXML private Button    stopBtn;
    @FXML private Button    saveJsonBtn;
    @FXML private Button    saveCsvBtn;
    @FXML private Label     totalLabel;
    @FXML private Label     passLabel;
    @FXML private Label     failLabel;
    @FXML private Label     rateValueLabel;
    @FXML private Label     avgSignLabel;
    @FXML private Label     avgVerifyLabel;
    @FXML private Label     elapsedLabel;
    @FXML private TextArea  logArea;

    private SessionHolder sessionHolder;
    private SignWorkload  workload;

    // 전체 SIGN 후보(RSA/EC/EdDSA/DSA…). 연결되면 ProviderProbe 가용 항목으로 좁힘.
    private static final List<AlgoSpec> ALL_SIGN = AlgoCatalog.by(AlgoSpec.Op.SIGN);

    @FXML
    public void initialize() {
        mechCombo.setConverter(new javafx.util.StringConverter<>() {
            public String toString(AlgoSpec s)   { return s == null ? "" : s.id() + " — " + s.jceName(); }
            public AlgoSpec fromString(String s) { return null; }
        });
        setMechs(ALL_SIGN);

        rateSlider.valueProperty().addListener((obs, o, n) ->
            rateLabel.setText(String.format("%.1f", n.doubleValue())));
    }

    private void setMechs(List<AlgoSpec> specs) {
        AlgoSpec prev = mechCombo.getValue();
        mechCombo.getItems().setAll(specs);
        if (prev != null && specs.contains(prev)) mechCombo.getSelectionModel().select(prev);
        else if (!specs.isEmpty())                mechCombo.getSelectionModel().selectFirst();
    }

    void setSessionHolder(SessionHolder holder) {
        this.sessionHolder = holder;
        holder.sessionProperty().addListener((obs, o, session) -> {
            boolean hasSession = session != null;
            startBtn.setDisable(!hasSession);
            setMechs(hasSession ? MechanismAvailability.filter(session, ALL_SIGN) : ALL_SIGN);
            if (hasSession) {
                refreshKeys(session);
            } else {
                keyCombo.getItems().clear();
                stopWorkload();
            }
        });
        // 다른 탭에서 키가 추가/삭제되면 콤보 갱신
        holder.keysVersionProperty().addListener((obs, o, n) -> {
            LunaSession s = holder.getSession();
            if (s != null) refreshKeys(s);
        });
    }

    /** 서명 가능한 키(KEYPAIR/PRIVATE)만 콤보에 로드 — 선택 유지. */
    private void refreshKeys(LunaSession session) {
        try {
            List<KeyCatalog.KeyEntry> keys = new KeyCatalog(session).list().stream()
                .filter(e -> e.kind() == KeyCatalog.KeyKind.KEYPAIR
                          || e.kind() == KeyCatalog.KeyKind.PRIVATE)
                .toList();
            KeyCatalog.KeyEntry prev = keyCombo.getValue();
            keyCombo.setConverter(new javafx.util.StringConverter<>() {
                public String toString(KeyCatalog.KeyEntry e) { return e == null ? "" : e.toString(); }
                public KeyCatalog.KeyEntry fromString(String s) { return null; }
            });
            keyCombo.getItems().setAll(keys);
            KeyCatalog.KeyEntry match = prev == null ? null : keys.stream()
                .filter(e -> e.alias().equals(prev.alias())).findFirst().orElse(null);
            if (match != null) keyCombo.getSelectionModel().select(match);
            else if (!keys.isEmpty()) keyCombo.getSelectionModel().selectFirst();
        } catch (Exception e) {
            logger.warn("키 목록 로드 실패", e);
        }
    }

    @FXML
    void onStart() {
        LunaSession session = sessionHolder == null ? null : sessionHolder.getSession();
        if (session == null) { showError("먼저 HSM에 연결하세요."); return; }

        AlgoSpec spec = mechCombo.getValue();
        KeyCatalog.KeyEntry key = keyCombo.getValue();
        if (spec == null || key == null) { showError("메커니즘과 키를 선택하세요."); return; }

        workload = new SignWorkload(session, spec, key);
        SignWorkload.WorkloadConfig cfg = new SignWorkload.WorkloadConfig(
            rateSlider.getValue(), extVerifyCheck.isSelected());

        workload.start(cfg, new SignWorkload.Listener() {
            public void onResult(int seq, OpResult r) {
                Platform.runLater(() -> appendLog(seq, r));
            }
            public void onStats(MetricsSnapshot s) {
                Platform.runLater(() -> updateStats(s));
            }
            public void onError(Throwable t) {
                Platform.runLater(() -> {
                    appendLogLine("[오류] " + t.getMessage(), true);
                    stopWorkload();
                });
            }
        });

        startBtn.setDisable(true);
        stopBtn.setDisable(false);
        saveJsonBtn.setDisable(true);
        saveCsvBtn.setDisable(true);
        logArea.clear();
        appendLogLine("[시작] " + spec.id() + " · " + key.alias(), false);
    }

    @FXML
    void onStop() {
        stopWorkload();
    }

    @FXML
    void onSaveJson() {
        if (workload == null) return;
        saveFile(false);
    }

    @FXML
    void onSaveCsv() {
        if (workload == null) return;
        saveFile(true);
    }

    @FXML
    void onClearLog() {
        logArea.clear();
    }

    private void stopWorkload() {
        if (workload != null) {
            workload.stop();
            // workload 참조는 유지한다 — 저장 시 recorder()/collector() 에 접근해야 함.
            // 다음 onStart() 에서 새 인스턴스로 교체된다.
        }
        startBtn.setDisable(false);
        stopBtn.setDisable(true);
        // 실제 실행 기록이 있을 때만 저장 버튼 활성화 (한 번도 안 돌렸으면 저장할 것이 없음)
        boolean hasRun = workload != null;
        saveJsonBtn.setDisable(!hasRun);
        saveCsvBtn.setDisable(!hasRun);
    }

    private void appendLog(int seq, OpResult r) {
        String icon = r.ok() ? "✓" : "✗";
        String time = LocalTime.now().format(TIME_FMT);
        String line = "[%s] #%04d %s %.2fms".formatted(
            time, seq, icon, r.durationMs());
        r.errorMsg().ifPresent(m -> { });
        appendLogLine(line, !r.ok());
    }

    private void appendLogLine(String line, boolean isError) {
        logArea.appendText(line + "\n");
        if (logArea.getText().length() > 200_000) {
            logArea.setText(logArea.getText().substring(50_000));
        }
    }

    private void updateStats(MetricsSnapshot s) {
        totalLabel.setText(String.valueOf(s.total()));
        passLabel .setText(String.valueOf(s.pass()));
        failLabel .setText(String.valueOf(s.fail()));
        rateValueLabel.setText(String.format("%.1f", s.rate()));
        avgSignLabel  .setText(String.format("%.2fms", s.avgSignMs()));
        avgVerifyLabel.setText(String.format("%.2fms", s.avgVerifyMs()));
        elapsedLabel  .setText(s.elapsed().toSeconds() + "s");
    }

    private void saveFile(boolean csv) {
        if (workload == null) return;
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("저장 폴더 선택");
        File dir = chooser.showDialog(logArea.getScene().getWindow());
        if (dir == null) return;

        Thread.ofVirtual().start(() -> {
            try {
                MetricsSnapshot snap = workload.collector().snapshot();
                Path out = csv
                    ? workload.recorder().saveCsv(dir.toPath(), snap)
                    : workload.recorder().saveJson(dir.toPath(), snap);
                Platform.runLater(() -> appendLogLine("[저장] " + out.getFileName(), false));
            } catch (Exception e) {
                Platform.runLater(() -> showError("저장 실패: " + e.getMessage()));
            }
        });
    }

    private void showError(String msg) {
        Alert a = new Alert(Alert.AlertType.ERROR, msg, ButtonType.OK);
        a.setTitle("오류"); a.setHeaderText(null); a.showAndWait();
    }
}
