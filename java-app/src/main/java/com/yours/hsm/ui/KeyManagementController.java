package com.yours.hsm.ui;

import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.config.AppConfig;
import com.yours.hsm.core.KeyAttribute;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.KeyManager;
import com.yours.hsm.core.KeyUnwrapper;
import com.yours.hsm.core.KeyWrapper;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.PublicKeyExporter;
import javafx.application.Platform;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.FlowPane;
import javafx.stage.FileChooser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public final class KeyManagementController {

    private static final Logger logger = LoggerFactory.getLogger(KeyManagementController.class);

    private enum Algo { AES, RSA, EC, DES3, ARIA, ML_DSA, ML_KEM }

    @FXML private ComboBox<Algo>     algoCombo;
    @FXML private ComboBox<String>   sizeCombo;
    @FXML private TextField          newAliasField;
    @FXML private Button             generateBtn;

    @FXML private Label              keyCountLabel;
    @FXML private Button             refreshBtn;
    @FXML private Button             exportPubBtn;
    @FXML private Button             relabelBtn;
    @FXML private Button             deleteBtn;
    @FXML private TableView<KeyCatalog.KeyEntry>            keyTable;
    @FXML private TableColumn<KeyCatalog.KeyEntry, String>  aliasCol;
    @FXML private TableColumn<KeyCatalog.KeyEntry, String>  kindCol;
    @FXML private TableColumn<KeyCatalog.KeyEntry, String>  algoCol;
    @FXML private TableColumn<KeyCatalog.KeyEntry, Integer> bitsCol;

    @FXML private Label              attrTargetLabel;
    @FXML private Button             applyAttrBtn;
    @FXML private FlowPane           attrPane;

    @FXML private ComboBox<KeyCatalog.KeyEntry> wrapKeyCombo;
    @FXML private Label              wrapTargetLabel;
    @FXML private Button             wrapExportBtn;
    @FXML private Label              wrapStatusLabel;

    @FXML private ComboBox<KeyCatalog.KeyEntry> unwrapKeyCombo;
    @FXML private TextField          unwrapFileField;
    @FXML private Button             chooseFileBtn;
    @FXML private TextField          unwrapAliasField;
    @FXML private Button             unwrapImportBtn;
    @FXML private Label              unwrapStatusLabel;

    private SessionHolder sessionHolder;
    private final Map<KeyAttribute, CheckBox> attrChecks = new EnumMap<>(KeyAttribute.class);

    @FXML
    public void initialize() {
        algoCombo.setItems(FXCollections.observableArrayList(Algo.values()));
        algoCombo.getSelectionModel().selectedItemProperty().addListener((o, p, n) -> refreshSizes(n));
        algoCombo.getSelectionModel().selectFirst();

        aliasCol.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().alias()));
        kindCol .setCellValueFactory(d -> new SimpleStringProperty(d.getValue().kind().name()));
        algoCol .setCellValueFactory(d -> new SimpleStringProperty(d.getValue().algorithm()));
        bitsCol .setCellValueFactory(d -> new SimpleObjectProperty<>(d.getValue().keyBits()));

        keyTable.getSelectionModel().selectedItemProperty().addListener((o, p, n) -> onSelectKey(n));

        var keyConverter = new javafx.util.StringConverter<KeyCatalog.KeyEntry>() {
            public String toString(KeyCatalog.KeyEntry e)   { return e == null ? "" : e.toString(); }
            public KeyCatalog.KeyEntry fromString(String s) { return null; }
        };
        wrapKeyCombo.setConverter(keyConverter);
        unwrapKeyCombo.setConverter(keyConverter);

        // 속성 체크박스 구성
        for (KeyAttribute attr : KeyAttribute.values()) {
            CheckBox cb = new CheckBox(attr.label());
            cb.setTooltip(new Tooltip(attr.description()));
            cb.setDisable(true);
            attrChecks.put(attr, cb);
            attrPane.getChildren().add(cb);
        }

        setControlsEnabled(false);
    }

    void setSessionHolder(SessionHolder holder) {
        this.sessionHolder = holder;
        holder.sessionProperty().addListener((obs, o, session) -> {
            boolean has = session != null;
            setControlsEnabled(has);
            if (has) loadKeys();
            else {
                keyTable.getItems().clear();
                keyCountLabel.setText("");
                wrapKeyCombo.getItems().clear();
                unwrapKeyCombo.getItems().clear();
                clearAttributes();
            }
        });
    }

    private void refreshSizes(Algo algo) {
        if (algo == null) return;
        List<String> opts;
        String def;
        switch (algo) {
            case AES  -> { opts = strs(KeyManager.AES_SIZES); def = "256"; }
            case RSA  -> { opts = strs(KeyManager.RSA_SIZES); def = "2048"; }
            case EC     -> { opts = KeyManager.EC_CURVES;        def = "secp256r1"; }
            case DES3   -> { opts = List.of("168");              def = "168"; }
            case ARIA   -> { opts = List.of("128", "192", "256"); def = "256"; }
            case ML_DSA -> { opts = KeyManager.ML_DSA_SETS;      def = "ML-DSA-65"; }
            case ML_KEM -> { opts = KeyManager.ML_KEM_SETS;      def = "ML-KEM-768"; }
            default     -> { opts = List.of();                   def = null; }
        }
        sizeCombo.setItems(FXCollections.observableArrayList(opts));
        if (def != null) sizeCombo.getSelectionModel().select(def);
    }

    private static List<String> strs(List<Integer> ints) {
        return ints.stream().map(String::valueOf).toList();
    }

    // ── 생성 ─────────────────────────────────────────
    @FXML
    void onGenerate() {
        LunaSession session = session();
        if (session == null) return;

        Algo algo    = algoCombo.getValue();
        String param = sizeCombo.getValue();
        String alias = newAliasField.getText() == null ? "" : newAliasField.getText().trim();
        if (algo == null || param == null) { showError("알고리즘과 키 길이/곡선을 선택하세요."); return; }
        if (alias.isBlank()) { showError("라벨(alias)을 입력하세요."); return; }

        generateBtn.setDisable(true);
        Thread.ofVirtual().start(() -> {
            try {
                KeyManager mgr = new KeyManager(session);
                switch (algo) {
                    case AES    -> mgr.generateAes(alias, Integer.parseInt(param));
                    case RSA    -> mgr.generateRsa(alias, Integer.parseInt(param));
                    case EC     -> mgr.generateEc(alias, param);
                    case DES3   -> mgr.generateSecret("DESede", alias, Integer.parseInt(param));
                    case ARIA   -> mgr.generateSecret("ARIA", alias, Integer.parseInt(param));
                    case ML_DSA -> mgr.generateMlDsa(alias, param);
                    case ML_KEM -> mgr.generateMlKem(alias, param);
                }
                Platform.runLater(() -> {
                    newAliasField.clear();
                    showInfo(algo + " 키 생성 완료: " + alias);
                    loadKeys();
                    notifyKeysChanged();
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("키 생성 실패: " + e.getMessage()));
            } finally {
                Platform.runLater(() -> generateBtn.setDisable(false));
            }
        });
    }

    // ── 목록 ─────────────────────────────────────────
    @FXML
    void onRefresh() { if (session() != null) loadKeys(); }

    private void loadKeys() {
        LunaSession session = sessionHolder == null ? null : sessionHolder.getSession();
        if (session == null) return;
        Thread.ofVirtual().start(() -> {
            try {
                List<KeyCatalog.KeyEntry> entries = new KeyCatalog(session).list();
                List<KeyCatalog.KeyEntry> aesKeys = entries.stream()
                    .filter(e -> e.kind() == KeyCatalog.KeyKind.SECRET)
                    .toList();
                Platform.runLater(() -> {
                    keyTable.getItems().setAll(entries);
                    keyCountLabel.setText("총 " + entries.size() + "개");
                    wrapKeyCombo.getItems().setAll(aesKeys);
                    unwrapKeyCombo.getItems().setAll(aesKeys);
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("키 목록 조회 실패: " + e.getMessage()));
            }
        });
    }

    // ── 선택 / 속성 로드 ──────────────────────────────
    private void onSelectKey(KeyCatalog.KeyEntry entry) {
        boolean has = entry != null;
        relabelBtn.setDisable(!has);
        deleteBtn.setDisable(!has);
        applyAttrBtn.setDisable(!has);
        wrapExportBtn.setDisable(!has);
        // 공개키 내보내기는 비대칭(키쌍/공개키/개인키) 엔트리에서 의미 있음 — 짝 공개키를 자동 탐색
        boolean asymmetric = has && entry.kind() != KeyCatalog.KeyKind.SECRET;
        exportPubBtn.setDisable(!asymmetric);
        wrapTargetLabel.setText(has ? entry.toString() : "— 위 목록에서 키를 선택하세요");
        if (!has) { clearAttributes(); return; }

        attrTargetLabel.setText(entry.alias());
        LunaSession session = sessionHolder.getSession();
        Thread.ofVirtual().start(() -> {
            try {
                Map<KeyAttribute, Boolean> attrs = new KeyManager(session).attributes(entry.alias());
                Platform.runLater(() -> applyAttrToUi(attrs));
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("속성 조회 실패: " + e.getMessage()));
            }
        });
    }

    private void applyAttrToUi(Map<KeyAttribute, Boolean> attrs) {
        for (KeyAttribute attr : KeyAttribute.values()) {
            CheckBox cb = attrChecks.get(attr);
            if (attrs.containsKey(attr)) {
                cb.setSelected(attrs.get(attr));
                cb.setDisable(false);
            } else {
                cb.setSelected(false);
                cb.setDisable(true); // 이 키에 없는 속성
            }
        }
    }

    private void clearAttributes() {
        attrTargetLabel.setText("— 키를 선택하세요");
        attrChecks.values().forEach(cb -> { cb.setSelected(false); cb.setDisable(true); });
    }

    // ── 래핑 / 내보내기 ───────────────────────────────
    @FXML
    void onWrapAndExport() {
        KeyCatalog.KeyEntry target  = keyTable.getSelectionModel().getSelectedItem();
        KeyCatalog.KeyEntry wrapKey = wrapKeyCombo.getValue();
        LunaSession session = session();
        if (session == null) return;
        if (target == null)  { showError("래핑 대상을 목록에서 선택하세요."); return; }
        if (wrapKey == null) { showError("래핑 키(AES)를 선택하세요."); return; }

        Path lunaRoot = Path.of(AppConfig.load().lunaLibPath());

        wrapExportBtn.setDisable(true);
        wrapStatusLabel.setText("래핑 중...");
        Thread.ofVirtual().start(() -> {
            try {
                KeyWrapper wrapper = new KeyWrapper(session);
                byte[] wrapped = wrapper.wrap(wrapKey, target);
                Path out = wrapper.export(wrapped, wrapper.metadataFor(wrapKey, target), lunaRoot);
                Platform.runLater(() -> {
                    wrapStatusLabel.setText("내보냄: " + out);
                    showInfo("래핑 키를 내보냈습니다:\n" + out);
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> {
                    wrapStatusLabel.setText("실패");
                    showError("래핑/내보내기 실패: " + e.getMessage());
                });
            } finally {
                Platform.runLater(() -> wrapExportBtn.setDisable(false));
            }
        });
    }

    // ── 언래핑 / 가져오기 ─────────────────────────────
    @FXML
    void onChooseFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("래핑된 키 파일 선택");
        chooser.getExtensionFilters().addAll(
            new FileChooser.ExtensionFilter("래핑 키 (*.key)", "*.key"),
            new FileChooser.ExtensionFilter("모든 파일", "*.*"));
        File initial = Path.of(AppConfig.load().lunaLibPath()).toFile();
        if (initial.isDirectory()) chooser.setInitialDirectory(initial);

        File f = chooser.showOpenDialog(unwrapFileField.getScene().getWindow());
        if (f != null) unwrapFileField.setText(f.getAbsolutePath());
    }

    @FXML
    void onUnwrapImport() {
        LunaSession session = session();
        if (session == null) return;

        KeyCatalog.KeyEntry unwrapKey = unwrapKeyCombo.getValue();
        String file     = unwrapFileField.getText()  == null ? "" : unwrapFileField.getText().trim();
        String newAlias = unwrapAliasField.getText() == null ? "" : unwrapAliasField.getText().trim();
        if (unwrapKey == null)  { showError("언래핑 키(AES)를 선택하세요."); return; }
        if (file.isBlank())     { showError("래핑된 .key 파일을 선택하세요."); return; }
        if (newAlias.isBlank()) { showError("복원할 키의 새 라벨을 입력하세요."); return; }

        Path keyFile = Path.of(file);
        unwrapImportBtn.setDisable(true);
        unwrapStatusLabel.setText("언래핑 중...");
        Thread.ofVirtual().start(() -> {
            try {
                var recovered = new KeyUnwrapper(session).unwrapAndStore(unwrapKey, keyFile, newAlias);
                Platform.runLater(() -> {
                    unwrapStatusLabel.setText("복원 완료: " + recovered.getAlgorithm() + " → " + newAlias);
                    unwrapAliasField.clear();
                    showInfo("키를 언래핑하여 토큰에 저장했습니다: " + newAlias);
                    loadKeys();
                    notifyKeysChanged();
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> {
                    unwrapStatusLabel.setText("실패");
                    showError("언래핑 실패: " + e.getMessage());
                });
            } finally {
                Platform.runLater(() -> unwrapImportBtn.setDisable(false));
            }
        });
    }

    // ── 속성 적용 ─────────────────────────────────────
    @FXML
    void onApplyAttributes() {
        KeyCatalog.KeyEntry entry = keyTable.getSelectionModel().getSelectedItem();
        LunaSession session = session();
        if (entry == null || session == null) return;

        Map<KeyAttribute, Boolean> desired = new EnumMap<>(KeyAttribute.class);
        for (KeyAttribute attr : KeyAttribute.values()) {
            CheckBox cb = attrChecks.get(attr);
            if (!cb.isDisabled()) desired.put(attr, cb.isSelected());
        }

        applyAttrBtn.setDisable(true);
        Thread.ofVirtual().start(() -> {
            try {
                KeyManager mgr = new KeyManager(session);
                Map<KeyAttribute, Boolean> current = mgr.attributes(entry.alias());
                int changed = 0;
                for (Map.Entry<KeyAttribute, Boolean> e : desired.entrySet()) {
                    if (!e.getValue().equals(current.get(e.getKey()))) {
                        mgr.setAttribute(entry.alias(), e.getKey(), e.getValue());
                        changed++;
                    }
                }
                final int n = changed;
                Platform.runLater(() -> {
                    showInfo(n == 0 ? "변경된 속성이 없습니다." : n + "개 속성을 변경했습니다.");
                    onSelectKey(entry); // 재조회로 동기화
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("속성 변경 실패: " + e.getMessage()));
            } finally {
                Platform.runLater(() -> applyAttrBtn.setDisable(false));
            }
        });
    }

    // ── 공개키 내보내기 ───────────────────────────────
    @FXML
    void onExportPublicKey() {
        KeyCatalog.KeyEntry entry = keyTable.getSelectionModel().getSelectedItem();
        LunaSession session = session();
        if (entry == null || session == null) return;

        FileChooser chooser = new FileChooser();
        chooser.setTitle("공개키 내보내기");
        chooser.setInitialFileName(entry.alias() + ".pem");
        chooser.getExtensionFilters().addAll(
            new FileChooser.ExtensionFilter("PEM (*.pem)", "*.pem"),
            new FileChooser.ExtensionFilter("DER (*.der)", "*.der"));
        File target = chooser.showSaveDialog(keyTable.getScene().getWindow());
        if (target == null) return;

        exportPubBtn.setDisable(true);
        Thread.ofVirtual().start(() -> {
            try {
                var pub = new KeyCatalog(session).asPublicKey(entry).orElseThrow(() ->
                    new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                        "공개키를 찾을 수 없습니다: " + entry.alias()
                        + " (키쌍이면 인증서 또는 '" + entry.alias() + "-pub' 별칭 필요)"));
                Path out = PublicKeyExporter.write(target.toPath(), pub);
                Platform.runLater(() -> showInfo("공개키를 내보냈습니다:\n" + out));
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("공개키 내보내기 실패: " + e.getMessage()));
            } finally {
                Platform.runLater(() -> exportPubBtn.setDisable(false));
            }
        });
    }

    // ── 라벨 변경 ─────────────────────────────────────
    @FXML
    void onRelabel() {
        KeyCatalog.KeyEntry entry = keyTable.getSelectionModel().getSelectedItem();
        LunaSession session = session();
        if (entry == null || session == null) return;

        TextInputDialog dialog = new TextInputDialog(entry.alias());
        dialog.setTitle("라벨 변경");
        dialog.setHeaderText(null);
        dialog.setContentText("새 라벨:");
        var result = dialog.showAndWait();
        if (result.isEmpty()) return;
        String newAlias = result.get().trim();

        Thread.ofVirtual().start(() -> {
            try {
                new KeyManager(session).relabel(entry.alias(), newAlias);
                Platform.runLater(() -> { showInfo("라벨 변경 완료: " + newAlias); loadKeys(); notifyKeysChanged(); });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("라벨 변경 실패: " + e.getMessage()));
            }
        });
    }

    // ── 삭제 ─────────────────────────────────────────
    @FXML
    void onDelete() {
        KeyCatalog.KeyEntry entry = keyTable.getSelectionModel().getSelectedItem();
        LunaSession session = session();
        if (entry == null || session == null) return;

        Alert confirm = new Alert(Alert.AlertType.WARNING,
            "키 '" + entry.alias() + "' 를 토큰에서 영구 삭제합니다.\n이 작업은 되돌릴 수 없습니다. 계속할까요?",
            ButtonType.OK, ButtonType.CANCEL);
        confirm.setTitle("키 삭제 확인");
        confirm.setHeaderText(null);
        if (confirm.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;

        Thread.ofVirtual().start(() -> {
            try {
                new KeyManager(session).delete(entry.alias());
                Platform.runLater(() -> { showInfo("키 삭제 완료: " + entry.alias()); loadKeys(); notifyKeysChanged(); });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> showError("키 삭제 실패: " + e.getMessage()));
            }
        });
    }

    // ── 공통 ─────────────────────────────────────────
    private void setControlsEnabled(boolean enabled) {
        generateBtn.setDisable(!enabled);
        refreshBtn.setDisable(!enabled);
        if (!enabled) {
            relabelBtn.setDisable(true);
            deleteBtn.setDisable(true);
            applyAttrBtn.setDisable(true);
            wrapExportBtn.setDisable(true);
            exportPubBtn.setDisable(true);
        }
        chooseFileBtn.setDisable(!enabled);
        unwrapImportBtn.setDisable(!enabled);
    }

    private LunaSession session() {
        if (sessionHolder == null || sessionHolder.getSession() == null) {
            showError("먼저 HSM에 연결하세요.");
            return null;
        }
        return sessionHolder.getSession();
    }

    /** 다른 탭(암복호화·MAC·서명)의 키 콤보 갱신을 유발. */
    private void notifyKeysChanged() {
        if (sessionHolder != null) sessionHolder.notifyKeysChanged();
    }

    private void showInfo(String msg) {
        Alert a = new Alert(Alert.AlertType.INFORMATION, msg, ButtonType.OK);
        a.setTitle("알림"); a.setHeaderText(null); a.showAndWait();
    }

    private void showError(String msg) {
        Alert a = new Alert(Alert.AlertType.ERROR, msg, ButtonType.OK);
        a.setTitle("오류"); a.setHeaderText(null); a.showAndWait();
    }
}
