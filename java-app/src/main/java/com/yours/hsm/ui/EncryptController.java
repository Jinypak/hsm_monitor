package com.yours.hsm.ui;

import com.yours.hsm.algo.*;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.MetricsCollector;
import com.yours.hsm.core.MetricsSnapshot;
import com.yours.hsm.core.Recorder;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.DirectoryChooser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public final class EncryptController {

    private static final Logger logger = LoggerFactory.getLogger(EncryptController.class);

    @FXML private ComboBox<AlgoSpec>           mechCombo;
    @FXML private ComboBox<KeyCatalog.KeyEntry> keyCombo;
    @FXML private TextArea  plaintextArea;
    @FXML private TextArea  ciphertextArea;
    @FXML private TextArea  decryptedArea;
    @FXML private CheckBox  privKeyEncryptCheck;
    @FXML private Label     roundtripStatus;
    @FXML private Button    encryptBtn;
    @FXML private Button    decryptBtn;
    @FXML private Button    roundtripBtn;
    @FXML private Button    saveJsonBtn;
    @FXML private Button    saveCsvBtn;
    @FXML private Button    clearLogBtn;

    private SessionHolder sessionHolder;

    // 암복호화 연산 로그 — JSON/CSV 저장용
    private static final List<String> CSV_EXTRA_COLS = List.of("op", "mech");
    private final Recorder         recorder = new Recorder();
    private final MetricsCollector metrics  = new MetricsCollector();
    private final AtomicInteger    seq      = new AtomicInteger(0);

    // 전체 ENC 후보(미연결 시 표시). 연결되면 ProviderProbe 가용 항목으로 좁힘.
    private static final List<AlgoSpec> ALL_ENC =
        AlgoCatalog.by(AlgoSpec.Op.ENC);

    @FXML
    public void initialize() {
        mechCombo.setConverter(new javafx.util.StringConverter<>() {
            public String toString(AlgoSpec s)   { return s == null ? "" : s.id() + " — " + s.jceName(); }
            public AlgoSpec fromString(String s) { return null; }
        });
        setMechs(ALL_ENC);
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
            boolean has = session != null;
            encryptBtn.setDisable(!has);
            decryptBtn.setDisable(!has);
            roundtripBtn.setDisable(!has);
            if (has) {
                setMechs(MechanismAvailability.filter(session, ALL_ENC));
                refreshKeys(session);
            } else {
                setMechs(ALL_ENC);
                keyCombo.getItems().clear();
            }
        });
        // 다른 탭에서 키가 추가/삭제되면 콤보 갱신
        holder.keysVersionProperty().addListener((obs, o, n) -> {
            LunaSession s = holder.getSession();
            if (s != null) refreshKeys(s);
        });
    }

    @FXML
    void onEncrypt() {
        LunaSession session = session();
        if (session == null) return;

        AlgoSpec spec = mechCombo.getValue();
        KeyCatalog.KeyEntry keyEntry = keyCombo.getValue();
        if (spec == null || keyEntry == null) { showError("메커니즘과 키를 선택하세요."); return; }

        byte[] plain = plaintextArea.getText().getBytes(StandardCharsets.UTF_8);
        Thread.ofVirtual().start(() -> {
            long t0 = System.nanoTime();
            try {
                byte[] ct = doEncrypt(session, spec, keyEntry, plain);
                record("ENCRYPT", spec, OpResult.success(System.nanoTime() - t0, ct));
                String b64 = Base64.getEncoder().encodeToString(ct);
                Platform.runLater(() -> ciphertextArea.setText(b64));
            } catch (CryptoOpException e) {
                record("ENCRYPT", spec, OpResult.failure(System.nanoTime() - t0, "GENERAL", e.getMessage()));
                Platform.runLater(() -> showError("암호화 실패: " + e.getMessage()));
            }
        });
    }

    @FXML
    void onDecrypt() {
        LunaSession session = session();
        if (session == null) return;

        AlgoSpec spec = mechCombo.getValue();
        KeyCatalog.KeyEntry keyEntry = keyCombo.getValue();
        String b64 = ciphertextArea.getText().trim();
        if (spec == null || keyEntry == null || b64.isEmpty()) {
            showError("메커니즘, 키, 암호문을 입력하세요."); return;
        }

        byte[] ct;
        try { ct = Base64.getDecoder().decode(b64); }
        catch (Exception e) { showError("Base64 암호문이 올바르지 않습니다."); return; }

        Thread.ofVirtual().start(() -> {
            long t0 = System.nanoTime();
            try {
                byte[] plain = doDecrypt(session, spec, keyEntry, ct);
                record("DECRYPT", spec, OpResult.success(System.nanoTime() - t0, plain));
                String text  = new String(plain, StandardCharsets.UTF_8);
                Platform.runLater(() -> decryptedArea.setText(text));
            } catch (CryptoOpException e) {
                record("DECRYPT", spec, OpResult.failure(System.nanoTime() - t0, "GENERAL", e.getMessage()));
                Platform.runLater(() -> showError("복호화 실패: " + e.getMessage()));
            }
        });
    }

    @FXML
    void onRoundtripTest() {
        LunaSession session = session();
        if (session == null) return;

        AlgoSpec spec = mechCombo.getValue();
        KeyCatalog.KeyEntry keyEntry = keyCombo.getValue();
        if (spec == null || keyEntry == null) { showError("메커니즘과 키를 선택하세요."); return; }

        byte[] plain = "HSM 라운드트립 검증 테스트 — PASS if equal".getBytes(StandardCharsets.UTF_8);

        Thread.ofVirtual().start(() -> {
            try {
                long tEnc = System.nanoTime();
                byte[] ct      = doEncrypt(session, spec, keyEntry, plain);
                record("ENCRYPT", spec, OpResult.success(System.nanoTime() - tEnc, ct));

                long tDec = System.nanoTime();
                byte[] recover = doDecrypt(session, spec, keyEntry, ct);
                record("DECRYPT", spec, OpResult.success(System.nanoTime() - tDec, recover));

                boolean pass = java.util.Arrays.equals(plain, recover);
                String msg = pass ? "✓ PASS" : "✗ FAIL";
                Platform.runLater(() -> {
                    roundtripStatus.setText(msg);
                    roundtripStatus.getStyleClass().setAll("status-label",
                        pass ? "status-connected" : "status-disconnected");
                    ciphertextArea.setText(Base64.getEncoder().encodeToString(ct));
                    decryptedArea .setText(new String(recover, StandardCharsets.UTF_8));
                    logger.info("라운드트립: spec={} result={}", spec.id(), msg);
                });
            } catch (CryptoOpException e) {
                record("ROUNDTRIP", spec, OpResult.failure(0L, "GENERAL", e.getMessage()));
                Platform.runLater(() -> {
                    roundtripStatus.setText("✗ 오류");
                    showError("라운드트립 실패: " + e.getMessage());
                });
            }
        });
    }

    private byte[] doEncrypt(LunaSession s, AlgoSpec spec, KeyCatalog.KeyEntry entry, byte[] plain)
        throws CryptoOpException {
        EncryptOp op = new EncryptOp(s.provider(), spec, resolveKey(s, spec, entry, true), Cipher.ENCRYPT_MODE, null);
        OpResult r = op.execute(plain);
        if (!r.ok()) throw new CryptoOpException(CryptoOpException.Code.GENERAL,
            r.errorMsg().orElse("암호화 실패"));
        return r.output().orElseThrow();
    }

    private byte[] doDecrypt(LunaSession s, AlgoSpec spec, KeyCatalog.KeyEntry entry, byte[] ct)
        throws CryptoOpException {
        EncryptOp op = new EncryptOp(s.provider(), spec, resolveKey(s, spec, entry, false), Cipher.DECRYPT_MODE, null);
        OpResult r = op.execute(ct);
        if (!r.ok()) throw new CryptoOpException(CryptoOpException.Code.GENERAL,
            r.errorMsg().orElse("복호화 실패"));
        return r.output().orElseThrow();
    }

    private java.security.Key resolveKey(LunaSession s, AlgoSpec spec,
                                         KeyCatalog.KeyEntry entry, boolean encrypt)
        throws CryptoOpException {
        KeyCatalog cat = new KeyCatalog(s);
        if (isSymmetric(spec.family())) {
            return cat.asSecretKey(entry).orElseThrow(() ->
                new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                    "대칭키를 찾을 수 없습니다: " + entry.alias()));
        }
        // 비대칭(RSA): 선택한 키와 한 쌍인 공개키/개인키를 자동 탐색
        // (어느 라벨 -pub/-priv 을 골라도 짝을 찾아준다)
        //
        // 키 방향:
        //  - 기본(체크 해제): 암호화=공개키, 복호화=개인키
        //  - 체크 시:         암호화=개인키, 복호화=공개키
        // 즉 공개키 사용 여부 = (암호화 XOR 개인키암호화체크)
        boolean usePublic = encrypt ^ privKeyEncryptCheck.isSelected();
        if (usePublic) {
            return cat.asPublicKey(entry).orElseThrow(() ->
                new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                    "RSA 공개키를 찾을 수 없습니다: " + entry.alias()
                    + " — 키쌍의 공개키 객체나 인증서가 토큰에 있어야 합니다."));
        }
        return cat.asPrivateKey(entry).orElseThrow(() ->
            new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                "RSA 개인키를 찾을 수 없습니다: " + entry.alias()
                + " — 개인키가 토큰에 있어야 합니다."));
    }

    /** 대칭 블록암호/스트림 family 여부 — SecretKey 로 로드해야 하는 계열. */
    private static boolean isSymmetric(AlgoSpec.Family f) {
        return switch (f) {
            case AES, ARIA, SM4, DES, DES3, RC, CAST -> true;
            default -> false;
        };
    }

    private void refreshKeys(LunaSession session) {
        Thread.ofVirtual().start(() -> {
            try {
                List<KeyCatalog.KeyEntry> entries = new KeyCatalog(session).list();
                Platform.runLater(() -> {
                    KeyCatalog.KeyEntry prev = keyCombo.getValue();
                    keyCombo.setConverter(new javafx.util.StringConverter<>() {
                        public String toString(KeyCatalog.KeyEntry e) { return e == null ? "" : e.toString(); }
                        public KeyCatalog.KeyEntry fromString(String s) { return null; }
                    });
                    keyCombo.getItems().setAll(entries);
                    // 이전 선택 유지(별칭 기준), 없으면 첫 항목
                    KeyCatalog.KeyEntry match = prev == null ? null : entries.stream()
                        .filter(e -> e.alias().equals(prev.alias())).findFirst().orElse(null);
                    if (match != null) keyCombo.getSelectionModel().select(match);
                    else if (!entries.isEmpty()) keyCombo.getSelectionModel().selectFirst();
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

    // ── 로그 기록 / 저장 ─────────────────────────────
    private void record(String op, AlgoSpec spec, OpResult r) {
        metrics.add(r);
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("op",   op);
        extra.put("mech", spec.id());
        recorder.append(seq.getAndIncrement(), r, extra);
    }

    @FXML
    void onSaveJson() { saveFile(false); }

    @FXML
    void onSaveCsv() { saveFile(true); }

    @FXML
    void onClearLog() {
        recorder.clear();
        metrics.reset();
        seq.set(0);
        showInfo("로그 기록을 지웠습니다.");
    }

    private void saveFile(boolean csv) {
        if (seq.get() == 0) { showInfo("저장할 로그가 없습니다."); return; }

        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("저장 폴더 선택");
        File dir = chooser.showDialog(mechCombo.getScene().getWindow());
        if (dir == null) return;

        Thread.ofVirtual().start(() -> {
            try {
                MetricsSnapshot snap = metrics.snapshot();
                Path out = csv
                    ? recorder.saveCsv(dir.toPath(), snap, CSV_EXTRA_COLS)
                    : recorder.saveJson(dir.toPath(), snap);
                Platform.runLater(() -> showInfo("저장 완료: " + out.getFileName()));
            } catch (Exception e) {
                Platform.runLater(() -> showError("저장 실패: " + e.getMessage()));
            }
        });
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
