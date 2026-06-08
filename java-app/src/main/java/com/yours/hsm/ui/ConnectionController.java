package com.yours.hsm.ui;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.config.AppConfig;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.LunaSession;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public final class ConnectionController {

    private static final Logger logger = LoggerFactory.getLogger(ConnectionController.class);

    @FXML private TextField     slotField;
    @FXML private PasswordField pinField;
    @FXML private Button        connectBtn;
    @FXML private Button        disconnectBtn;
    @FXML private Button        refreshBtn;
    @FXML private Label         connectStatus;
    @FXML private TableView<KeyCatalog.KeyEntry> keyTable;
    @FXML private TableColumn<KeyCatalog.KeyEntry, String>  aliasCol;
    @FXML private TableColumn<KeyCatalog.KeyEntry, String>  kindCol;
    @FXML private TableColumn<KeyCatalog.KeyEntry, String>  algoCol;
    @FXML private TableColumn<KeyCatalog.KeyEntry, Integer> bitsCol;
    @FXML private Label keyCountLabel;

    private LunaSession   session;
    private SessionHolder sessionHolder;

    @FXML
    public void initialize() {
        aliasCol.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().alias()));
        kindCol .setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().kind().name()));
        algoCol .setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().algorithm()));
        bitsCol .setCellValueFactory(d -> new javafx.beans.property.SimpleObjectProperty<>(d.getValue().keyBits()));

        AppConfig cfg = AppConfig.load();
        slotField.setText(String.valueOf(cfg.defaultSlot()));
    }

    void setSessionHolder(SessionHolder holder) {
        this.sessionHolder = holder;
    }

    @FXML
    void onConnect() {
        int slot;
        try {
            slot = Integer.parseInt(slotField.getText().trim());
        } catch (NumberFormatException e) {
            showError("슬롯 번호가 올바르지 않습니다.");
            return;
        }
        char[] pin = pinField.getText().toCharArray();
        if (pin.length == 0) {
            showError("PIN을 입력하세요.");
            return;
        }

        connectBtn.setDisable(true);
        connectStatus.setText("● 연결 중...");
        connectStatus.getStyleClass().setAll("status", "status-disconnected");

        final int finalSlot = slot;
        Thread.ofVirtual().start(() -> {
            try {
                LunaSession s = LunaSession.connect(finalSlot, pin);
                Platform.runLater(() -> onConnectSuccess(s));
            } catch (CryptoOpException e) {
                Platform.runLater(() -> onConnectFail(e));
            } finally {
                java.util.Arrays.fill(pin, '\0');
            }
        });
    }

    @FXML
    void onDisconnect() {
        if (session != null) {
            session.close();
            session = null;
            if (sessionHolder != null) sessionHolder.setSession(null);
        }
        keyTable.getItems().clear();
        keyCountLabel.setText("");
        connectBtn.setDisable(false);
        disconnectBtn.setDisable(true);
        refreshBtn.setDisable(true);
        connectStatus.setText("● 미연결");
        connectStatus.getStyleClass().setAll("status", "status-disconnected");
        logger.info("HSM 연결 해제");
    }

    @FXML
    void onRefresh() {
        if (session != null) loadKeyList(session);
    }

    private void onConnectSuccess(LunaSession s) {
        session = s;
        if (sessionHolder != null) sessionHolder.setSession(s);
        connectStatus.setText("● 연결됨: " + s.tokenLabel() + " (슬롯 " + s.slot() + ")");
        connectStatus.getStyleClass().setAll("status", "status-connected");
        connectBtn.setDisable(false);
        disconnectBtn.setDisable(false);
        refreshBtn.setDisable(false);
        logger.info("HSM 연결 성공: {}", s.tokenLabel());
        loadKeyList(s);
    }

    private void onConnectFail(CryptoOpException e) {
        connectBtn.setDisable(false);
        connectStatus.setText("● 연결 실패");
        connectStatus.getStyleClass().setAll("status", "status-disconnected");
        showError(e.getMessage());
        logger.error("HSM 연결 실패", e);
    }

    private void loadKeyList(LunaSession s) {
        Thread.ofVirtual().start(() -> {
            try {
                List<KeyCatalog.KeyEntry> entries = new KeyCatalog(s).list();
                Platform.runLater(() -> {
                    keyTable.getItems().setAll(entries);
                    keyCountLabel.setText("총 " + entries.size() + "개 키");
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("키 목록 조회 실패: " + e.getMessage()));
            }
        });
    }

    private void showError(String msg) {
        Alert alert = new Alert(Alert.AlertType.ERROR, msg, ButtonType.OK);
        alert.setTitle("오류");
        alert.setHeaderText(null);
        alert.showAndWait();
    }

    public LunaSession getSession() { return session; }
}
