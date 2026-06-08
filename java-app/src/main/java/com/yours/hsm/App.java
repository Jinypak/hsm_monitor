package com.yours.hsm;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class App extends Application {

    private static final Logger logger = LoggerFactory.getLogger(App.class);

    @Override
    public void start(Stage stage) throws Exception {
        logger.info("HSM Monitor 기동 — JDK {}", System.getProperty("java.version"));

        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/main.fxml"));
        Parent root = loader.load();

        Scene scene = new Scene(root, 1000, 680);
        scene.getStylesheets().add(
            getClass().getResource("/css/dark.css").toExternalForm()
        );

        stage.setTitle("HSM Sign/Verify Monitor  " + BuildInfo.label());
        logger.info("애플리케이션 시작 — {}", BuildInfo.label());
        stage.setMinWidth(860);
        stage.setMinHeight(600);
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
