package com.yours.hsm.ui;

import com.yours.hsm.algo.*;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.LunaSession;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * MAC · 해시 단발 실행 탭.
 * MAC(HMAC/CMAC/GMAC)은 {@link MacOp} + SecretKey, 해시(DIGEST)는 {@link DigestOp}(키 불필요).
 */
public final class MacDigestController {

    private static final Logger logger = LoggerFactory.getLogger(MacDigestController.class);

    @FXML private ComboBox<AlgoSpec>            mechCombo;
    @FXML private ComboBox<KeyCatalog.KeyEntry> keyCombo;
    @FXML private TextArea inputArea;
    @FXML private TextArea outputArea;
    @FXML private Label    infoLabel;
    @FXML private Button   computeBtn;
    @FXML private Button   clearBtn;

    private SessionHolder sessionHolder;

    // MAC + DIGEST 후보(미연결 시 표시). 연결되면 가용 항목으로 좁힘.
    private static final List<AlgoSpec> ALL_MECHS = buildAll();

    private static List<AlgoSpec> buildAll() {
        List<AlgoSpec> all = new ArrayList<>(AlgoCatalog.by(AlgoSpec.Op.MAC));
        all.addAll(AlgoCatalog.by(AlgoSpec.Op.DIGEST));
        return List.copyOf(all);
    }

    @FXML
    public void initialize() {
        mechCombo.setConverter(new javafx.util.StringConverter<>() {
            public String toString(AlgoSpec s) {
                if (s == null) return "";
                String kind = s.op() == AlgoSpec.Op.MAC ? "MAC" : "해시";
                return "[" + kind + "] " + s.id() + " — " + s.jceName();
            }
            public AlgoSpec fromString(String s) { return null; }
        });
        keyCombo.setConverter(new javafx.util.StringConverter<>() {
            public String toString(KeyCatalog.KeyEntry e) { return e == null ? "" : e.toString(); }
            public KeyCatalog.KeyEntry fromString(String s) { return null; }
        });
        setMechs(ALL_MECHS);

        // 메커니즘 선택에 따라 키 콤보 활성/비활성
        mechCombo.valueProperty().addListener((o, a, b) -> updateKeyEnabled(b));
    }

    private void setMechs(List<AlgoSpec> specs) {
        AlgoSpec prev = mechCombo.getValue();
        mechCombo.getItems().setAll(specs);
        if (prev != null && specs.contains(prev)) mechCombo.getSelectionModel().select(prev);
        else if (!specs.isEmpty())                mechCombo.getSelectionModel().selectFirst();
        updateKeyEnabled(mechCombo.getValue());
    }

    private void updateKeyEnabled(AlgoSpec spec) {
        boolean needsKey = spec != null && spec.op() == AlgoSpec.Op.MAC;
        keyCombo.setDisable(!needsKey);
    }

    void setSessionHolder(SessionHolder holder) {
        this.sessionHolder = holder;
        holder.sessionProperty().addListener((obs, o, session) -> {
            boolean has = session != null;
            computeBtn.setDisable(!has);
            if (has) {
                setMechs(MechanismAvailability.filter(session, ALL_MECHS));
                refreshKeys(session);
            } else {
                setMechs(ALL_MECHS);
                keyCombo.getItems().clear();
            }
        });
        holder.keysVersionProperty().addListener((obs, o, n) -> {
            LunaSession s = holder.getSession();
            if (s != null) refreshKeys(s);
        });
    }

    @FXML
    void onCompute() {
        LunaSession session = session();
        if (session == null) return;

        AlgoSpec spec = mechCombo.getValue();
        if (spec == null) { showError("메커니즘을 선택하세요."); return; }

        byte[] input = inputArea.getText().getBytes(StandardCharsets.UTF_8);
        boolean isMac = spec.op() == AlgoSpec.Op.MAC;
        KeyCatalog.KeyEntry keyEntry = keyCombo.getValue();
        if (isMac && keyEntry == null) { showError("MAC 연산에는 키가 필요합니다."); return; }

        Thread.ofVirtual().start(() -> {
            try {
                OpResult r;
                if (isMac) {
                    SecretKey key = new KeyCatalog(session).asSecretKey(keyEntry).orElseThrow(() ->
                        new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                            "대칭키를 찾을 수 없습니다: " + keyEntry.alias()));
                    r = new MacOp(session.provider(), spec, key).execute(input);
                } else {
                    r = new DigestOp(session.provider(), spec).execute(input);
                }
                byte[] out = r.output().orElseThrow();
                String hex = toHex(out);
                Platform.runLater(() -> {
                    outputArea.setText(hex);
                    infoLabel.setText("%s · %d bytes · %.2fms"
                        .formatted(spec.jceName(), out.length, r.durationMs()));
                    logger.info("MAC/해시 완료: spec={} bytes={}", spec.id(), out.length);
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError((isMac ? "MAC" : "해시") + " 실패: " + e.getMessage()));
            }
        });
    }

    @FXML
    void onClear() {
        inputArea.clear();
        outputArea.clear();
        infoLabel.setText("");
    }

    private void refreshKeys(LunaSession session) {
        Thread.ofVirtual().start(() -> {
            try {
                List<KeyCatalog.KeyEntry> secrets = new KeyCatalog(session).list().stream()
                    .filter(e -> e.kind() == KeyCatalog.KeyKind.SECRET)
                    .toList();
                Platform.runLater(() -> {
                    KeyCatalog.KeyEntry prev = keyCombo.getValue();
                    keyCombo.getItems().setAll(secrets);
                    KeyCatalog.KeyEntry match = prev == null ? null : secrets.stream()
                        .filter(e -> e.alias().equals(prev.alias())).findFirst().orElse(null);
                    if (match != null) keyCombo.getSelectionModel().select(match);
                    else if (!secrets.isEmpty()) keyCombo.getSelectionModel().selectFirst();
                });
            } catch (Exception e) {
                logger.warn("키 목록 로드 실패", e);
            }
        });
    }

    private LunaSession session() {
        if (sessionHolder == null || sessionHolder.getSession() == null) {
            showError("먼저 HSM에 연결하세요.");
            return null;
        }
        return sessionHolder.getSession();
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private void showError(String msg) {
        Alert a = new Alert(Alert.AlertType.ERROR, msg, ButtonType.OK);
        a.setTitle("오류"); a.setHeaderText(null); a.showAndWait();
    }
}
