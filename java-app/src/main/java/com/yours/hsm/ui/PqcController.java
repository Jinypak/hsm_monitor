package com.yours.hsm.ui;

import com.yours.hsm.algo.AlgoCatalog;
import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.algo.CryptoOpException;
import com.yours.hsm.core.KeyCatalog;
import com.yours.hsm.core.KeyManager;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.PqcService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 양자내성암호(PQC) 탭 — <b>토큰(실제) 키</b>로 동작.
 * <p>① 필요한 PQC 키를 한 번 생성해 두고, ② '토큰 키'에서 선택해 ML-DSA 서명·검증 또는
 * ML-KEM 캡슐화를 반복 실행한다. 공개키는 {@code LunaKey.LocateKeyByAlias} 로 토큰에서 조회한다.
 * HSM 연결 필요.
 */
public final class PqcController {

    private static final Logger logger = LoggerFactory.getLogger(PqcController.class);

    @FXML private ComboBox<AlgoSpec>            algoCombo;
    @FXML private TextField                     aliasField;
    @FXML private Button                        generateBtn;
    @FXML private Label                         genStatusLabel;
    @FXML private ComboBox<KeyCatalog.KeyEntry> keyCombo;
    @FXML private Button                        runBtn;
    @FXML private Button                        refreshBtn;
    @FXML private Button                        clearBtn;
    @FXML private Label                         statusLabel;
    @FXML private TextArea                      messageArea;
    @FXML private TextArea                      resultArea;

    private SessionHolder sessionHolder;

    /**
     * Luna 네이티브(JNI) 호출은 가상 스레드에서 세션 컨텍스트가 불안정하므로,
     * HSM 작업은 단일 플랫폼 스레드에서 직렬 실행한다.
     */
    private final ExecutorService hsm = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "pqc-hsm");
        t.setDaemon(true);
        return t;
    });

    /** 이번 세션에 생성한 키쌍 캐시(라벨→KeyPair). 재조회 없이 즉시 재사용. */
    private final Map<String, KeyPair> generated = new ConcurrentHashMap<>();

    private static final List<AlgoSpec> PQC_SPECS = buildSpecs();

    private static List<AlgoSpec> buildSpecs() {
        List<AlgoSpec> all = new ArrayList<>();
        all.addAll(AlgoCatalog.by(AlgoSpec.Family.ML_DSA));
        all.addAll(AlgoCatalog.by(AlgoSpec.Family.ML_KEM));
        return List.copyOf(all);
    }

    @FXML
    public void initialize() {
        algoCombo.setConverter(new javafx.util.StringConverter<>() {
            public String toString(AlgoSpec s) {
                if (s == null) return "";
                String kind = s.family() == AlgoSpec.Family.ML_KEM ? "KEM" : "서명";
                return "[" + kind + "] " + s.jceName();
            }
            public AlgoSpec fromString(String s) { return null; }
        });
        algoCombo.getItems().setAll(PQC_SPECS);
        if (!algoCombo.getItems().isEmpty()) algoCombo.getSelectionModel().selectFirst();

        keyCombo.setConverter(new javafx.util.StringConverter<>() {
            public String toString(KeyCatalog.KeyEntry e) { return e == null ? "" : e.toString(); }
            public KeyCatalog.KeyEntry fromString(String s) { return null; }
        });
    }

    void setSessionHolder(SessionHolder holder) {
        this.sessionHolder = holder;
        holder.sessionProperty().addListener((obs, o, session) -> {
            boolean has = session != null;
            generateBtn.setDisable(!has);
            runBtn.setDisable(!has);
            refreshBtn.setDisable(!has);
            if (has) refreshKeys(session);
            else keyCombo.getItems().clear();
        });
        holder.keysVersionProperty().addListener((obs, o, n) -> {
            LunaSession s = holder.getSession();
            if (s != null) refreshKeys(s);
        });
    }

    // ── 토큰에 PQC 키 생성 ─────────────────────────────
    @FXML
    void onGenerate() {
        LunaSession session = session();
        if (session == null) return;

        AlgoSpec spec = algoCombo.getValue();
        String alias  = aliasField.getText() == null ? "" : aliasField.getText().trim();
        if (spec == null) { showError("알고리즘을 선택하세요."); return; }
        if (alias.isBlank()) { showError("라벨(alias)을 입력하세요."); return; }

        String paramSet = spec.jceName();
        boolean isKem   = spec.family() == AlgoSpec.Family.ML_KEM;

        generateBtn.setDisable(true);
        genStatusLabel.setText("생성 중...");
        hsm.submit(() -> {
            try {
                KeyManager mgr = new KeyManager(session);
                KeyPair kp = isKem ? mgr.generateMlKem(alias, paramSet)
                                   : mgr.generateMlDsa(alias, paramSet);
                generated.put(alias, kp); // 캐시 — 재조회 없이 실행에 재사용
                Platform.runLater(() -> {
                    genStatusLabel.setText("생성 완료: " + alias);
                    aliasField.clear();
                    refreshKeys(session);
                    if (sessionHolder != null) sessionHolder.notifyKeysChanged();
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> {
                    genStatusLabel.setText("실패");
                    showError("PQC 키 생성 실패: " + e.getMessage());
                });
            } finally {
                Platform.runLater(() -> generateBtn.setDisable(false));
            }
        });
    }

    // ── 기존 토큰 키로 서명/캡슐화 ─────────────────────
    @FXML
    void onRun() {
        LunaSession session = session();
        if (session == null) return;

        KeyCatalog.KeyEntry entry = keyCombo.getValue();
        if (entry == null) { showError("토큰 PQC 키를 선택하세요. (없으면 위에서 먼저 생성)"); return; }

        boolean isKem  = entry.algorithm().toUpperCase().contains("KEM");
        byte[] message = messageArea.getText().getBytes(StandardCharsets.UTF_8);

        runBtn.setDisable(true);
        statusLabel.setText("실행 중...");
        statusLabel.getStyleClass().setAll("status-label");
        hsm.submit(() -> {
            try {
                // 이번 세션에 생성한 키면 캐시 사용, 아니면 토큰에서 조회
                KeyPair kp = generated.get(entry.alias());
                if (kp == null) {
                    KeyCatalog cat = new KeyCatalog(session);
                    PublicKey  pub  = cat.asPublicKey(entry).orElseThrow(() ->
                        new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                            "공개키를 찾을 수 없습니다: " + entry.alias()
                            + " — 이 키는 이번 세션에서 생성한 키가 아닙니다. 위에서 새로 생성하거나 재연결 후 시도하세요."));
                    PrivateKey priv = cat.asPrivateKey(entry).orElseThrow(() ->
                        new CryptoOpException(CryptoOpException.Code.KEY_NOT_FOUND,
                            "개인키를 찾을 수 없습니다: " + entry.alias()));
                    kp = new KeyPair(pub, priv);
                }

                PqcService pqc = new PqcService(session.provider());
                String out = isKem ? runKem(pqc, kp, entry) : runSign(pqc, kp, entry, message);

                Platform.runLater(() -> {
                    resultArea.setText(out);
                    statusLabel.setText("완료");
                    statusLabel.getStyleClass().setAll("status-label", "status-connected");
                });
            } catch (CryptoOpException e) {
                Platform.runLater(() -> {
                    statusLabel.setText("실패");
                    statusLabel.getStyleClass().setAll("status-label", "status-disconnected");
                    showError(e.getMessage());
                });
            } finally {
                Platform.runLater(() -> runBtn.setDisable(false));
            }
        });
    }

    private String runSign(PqcService pqc, KeyPair kp, KeyCatalog.KeyEntry entry, byte[] msg)
        throws CryptoOpException {
        PqcService.SignResult r = pqc.signVerify(kp, msg);
        StringBuilder sb = new StringBuilder();
        sb.append("== ML-DSA 서명·검증 (토큰 키) ==\n");
        sb.append("키 라벨    : ").append(entry.alias()).append('\n');
        sb.append("알고리즘   : ").append(kp.getPublic().getAlgorithm()).append('\n');
        sb.append("Provider   : LunaProvider(HSM)\n");
        sb.append("메시지     : ").append(msg.length).append(" bytes\n");
        sb.append("서명 길이  : ").append(r.signature().length).append(" bytes\n");
        sb.append("서명 시간  : ").append(fmt(r.signMs())).append(" ms\n");
        sb.append("검증 시간  : ").append(fmt(r.verifyMs())).append(" ms\n");
        sb.append("검증 결과  : ").append(r.verified() ? "✓ PASS" : "✗ FAIL").append("\n\n");
        sb.append("서명(HEX, 앞 64B):\n").append(hexHead(r.signature(), 64)).append('\n');
        return sb.toString();
    }

    private String runKem(PqcService pqc, KeyPair kp, KeyCatalog.KeyEntry entry)
        throws CryptoOpException {
        PqcService.KemResult r = pqc.kemRoundtrip(kp);
        StringBuilder sb = new StringBuilder();
        sb.append("== ML-KEM 키 캡슐화 (토큰 키) ==\n");
        sb.append("키 라벨      : ").append(entry.alias()).append('\n');
        sb.append("알고리즘     : ").append(kp.getPublic().getAlgorithm()).append('\n');
        sb.append("Provider     : LunaProvider(HSM)\n");
        sb.append("캡슐화 길이  : ").append(r.encapsulation().length).append(" bytes\n");
        sb.append("캡슐화 시간  : ").append(fmt(r.encMs())).append(" ms\n");
        sb.append("디캡슐화 시간: ").append(fmt(r.decMs())).append(" ms\n");
        sb.append("비밀 일치    : ").append(r.match() ? "✓ PASS" : "✗ FAIL").append("\n\n");
        sb.append("공유비밀 지문(HMAC-SHA256):\n");
        sb.append("  캡슐화 측 : ").append(hexHead(r.fingerprintA(), 32)).append('\n');
        sb.append("  디캡슐 측 : ").append(hexHead(r.fingerprintB(), 32)).append('\n');
        return sb.toString();
    }

    @FXML
    void onRefresh() { LunaSession s = session(); if (s != null) refreshKeys(s); }

    @FXML
    void onClear() {
        messageArea.clear();
        resultArea.clear();
        statusLabel.setText("");
        statusLabel.getStyleClass().setAll("status-label");
    }

    /** 토큰의 PQC 키(ML-DSA/ML-KEM 개인키·키쌍)만 콤보에 로드 — 선택 유지. */
    private void refreshKeys(LunaSession session) {
        hsm.submit(() -> {
            try {
                List<KeyCatalog.KeyEntry> pqcKeys = new KeyCatalog(session).list().stream()
                    .filter(e -> e.kind() == KeyCatalog.KeyKind.KEYPAIR
                              || e.kind() == KeyCatalog.KeyKind.PRIVATE)
                    .filter(e -> {
                        String a = e.algorithm().toUpperCase();
                        return a.contains("ML-DSA") || a.contains("MLDSA")
                            || a.contains("ML-KEM") || a.contains("MLKEM");
                    })
                    .toList();
                Platform.runLater(() -> {
                    KeyCatalog.KeyEntry prev = keyCombo.getValue();
                    keyCombo.getItems().setAll(pqcKeys);
                    KeyCatalog.KeyEntry match = prev == null ? null : pqcKeys.stream()
                        .filter(e -> e.alias().equals(prev.alias())).findFirst().orElse(null);
                    if (match != null) keyCombo.getSelectionModel().select(match);
                    else if (!pqcKeys.isEmpty()) keyCombo.getSelectionModel().selectFirst();
                });
            } catch (Exception e) {
                logger.warn("PQC 키 목록 로드 실패", e);
            }
        });
    }

    private LunaSession session() {
        if (sessionHolder == null || sessionHolder.getSession() == null) {
            showError("먼저 [연결] 탭에서 HSM에 연결하세요.");
            return null;
        }
        return sessionHolder.getSession();
    }

    private static String fmt(double ms) { return String.format("%.3f", ms); }

    private static String hexHead(byte[] b, int max) {
        int n = Math.min(b.length, max);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i]));
        if (b.length > max) sb.append(" …(+").append(b.length - max).append("B)");
        return sb.toString();
    }

    private void showError(String msg) {
        Alert a = new Alert(Alert.AlertType.ERROR, msg, ButtonType.OK);
        a.setTitle("오류"); a.setHeaderText(null); a.showAndWait();
    }
}
