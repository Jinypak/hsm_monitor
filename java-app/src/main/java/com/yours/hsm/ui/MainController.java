package com.yours.hsm.ui;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TabPane;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class MainController {

    private static final Logger logger = LoggerFactory.getLogger(MainController.class);

    @FXML private TabPane tabs;
    @FXML private Label   connectionStatus;

    // fx:include 로드된 sub-controller는 "<fx:id>Controller" 명명 규칙으로 주입됨
    @FXML private ConnectionController        connectionContentController;
    @FXML private MechanismExplorerController explorerContentController;
    @FXML private SignVerifyController        signVerifyContentController;
    @FXML private EncryptController           encryptContentController;
    @FXML private MacDigestController         macDigestContentController;
    @FXML private PqcController               pqcContentController;
    @FXML private KeyManagementController     keyMgmtContentController;

    @FXML
    public void initialize() {
        logger.info("MainController 초기화");

        SessionHolder holder = new SessionHolder();

        // 각 컨트롤러에 공유 세션 홀더 주입
        connectionContentController.setSessionHolder(holder);
        explorerContentController  .setSessionHolder(holder);
        signVerifyContentController.setSessionHolder(holder);
        encryptContentController   .setSessionHolder(holder);
        macDigestContentController .setSessionHolder(holder);
        pqcContentController        .setSessionHolder(holder);
        keyMgmtContentController    .setSessionHolder(holder);

        // 연결 상태 헤더 라벨을 SessionHolder에 바인딩
        holder.sessionProperty().addListener((obs, o, session) -> {
            if (session != null) {
                connectionStatus.setText("● 연결됨: " + session.tokenLabel());
                connectionStatus.getStyleClass().setAll("status", "status-connected");
            } else {
                connectionStatus.setText("● 미연결");
                connectionStatus.getStyleClass().setAll("status", "status-disconnected");
            }
        });

        connectionStatus.setText("● 미연결");
        connectionStatus.getStyleClass().setAll("status", "status-disconnected");
    }
}
