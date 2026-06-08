package com.yours.hsm.ui;

import com.yours.hsm.algo.AlgoCatalog;
import com.yours.hsm.algo.AlgoSpec;
import com.yours.hsm.core.LunaSession;
import com.yours.hsm.core.ProviderProbe;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.util.StringConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * 메커니즘 탐색기 — 카탈로그 전체를 검색/필터하고, 세션 연결 시 현재 Provider가
 * 실제로 노출하는 메커니즘의 가용성(✅/🔒)을 표시한다.
 */
public final class MechanismExplorerController {

    private static final Logger logger = LoggerFactory.getLogger(MechanismExplorerController.class);

    @FXML private TextField                          searchField;
    @FXML private ComboBox<AlgoSpec.Family>          familyFilter;
    @FXML private ComboBox<AlgoSpec.Op>              opFilter;
    @FXML private CheckBox                           availableOnly;
    @FXML private Button                             resetBtn;
    @FXML private TableView<AlgoSpec>                table;
    @FXML private TableColumn<AlgoSpec, String>      availCol;
    @FXML private TableColumn<AlgoSpec, String>      idCol;
    @FXML private TableColumn<AlgoSpec, String>      familyCol;
    @FXML private TableColumn<AlgoSpec, String>      opCol;
    @FXML private TableColumn<AlgoSpec, String>      jceCol;
    @FXML private TableColumn<AlgoSpec, String>      ckmCol;
    @FXML private TableColumn<AlgoSpec, String>      flagsCol;
    @FXML private Label                              countLabel;

    private final ObservableList<AlgoSpec> master = FXCollections.observableArrayList(AlgoCatalog.all());
    private FilteredList<AlgoSpec> filtered;

    /** 현재 세션에서 가용한 메커니즘 id 집합. 미연결 시 빈 집합. */
    private Set<String> availableIds = Set.of();

    @FXML
    public void initialize() {
        availCol .setCellValueFactory(d -> new SimpleStringProperty(
            availableIds.contains(d.getValue().id()) ? "✅" : "🔒"));
        idCol    .setCellValueFactory(d -> new SimpleStringProperty(d.getValue().id()));
        familyCol.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().family().name()));
        opCol    .setCellValueFactory(d -> new SimpleStringProperty(d.getValue().op().name()));
        jceCol   .setCellValueFactory(d -> new SimpleStringProperty(d.getValue().jceName()));
        ckmCol   .setCellValueFactory(d -> new SimpleStringProperty(d.getValue().ckmHex()));
        flagsCol .setCellValueFactory(d -> new SimpleStringProperty(flags(d.getValue())));

        // Family / Op 필터 (null = 전체)
        List<AlgoSpec.Family> families = new ArrayList<>();
        families.add(null);
        families.addAll(List.of(AlgoSpec.Family.values()));
        familyFilter.setItems(FXCollections.observableArrayList(families));
        familyFilter.setConverter(enumConverter("(전체 Family)"));
        familyFilter.getSelectionModel().selectFirst();

        List<AlgoSpec.Op> ops = new ArrayList<>();
        ops.add(null);
        ops.addAll(List.of(AlgoSpec.Op.values()));
        opFilter.setItems(FXCollections.observableArrayList(ops));
        opFilter.setConverter(enumConverter("(전체 Op)"));
        opFilter.getSelectionModel().selectFirst();

        filtered = new FilteredList<>(master, s -> true);
        table.setItems(filtered);

        searchField.textProperty().addListener((o, a, b) -> applyFilter());
        familyFilter.valueProperty().addListener((o, a, b) -> applyFilter());
        opFilter.valueProperty().addListener((o, a, b) -> applyFilter());
        availableOnly.selectedProperty().addListener((o, a, b) -> applyFilter());

        applyFilter();
    }

    void setSessionHolder(SessionHolder holder) {
        holder.sessionProperty().addListener((obs, o, session) -> refreshAvailability(session));
    }

    private void refreshAvailability(LunaSession session) {
        if (session == null) {
            availableIds = Set.of();
            Platform.runLater(this::rerender);
            return;
        }
        Thread.ofVirtual().start(() -> {
            try {
                ProviderProbe probe = ProviderProbe.of(session.provider());
                Set<String> ids = AlgoCatalog.all().stream()
                    .filter(probe::supports)
                    .map(AlgoSpec::id)
                    .collect(Collectors.toUnmodifiableSet());
                availableIds = ids;
                logger.info("메커니즘 탐색기: {}개 가용 (전체 {}개 중)", ids.size(), master.size());
                Platform.runLater(this::rerender);
            } catch (Exception e) {
                logger.warn("가용성 탐지 실패", e);
            }
        });
    }

    /** 가용성 컬럼/필터를 다시 그린다(셀 값은 availableIds 를 즉시 참조). */
    private void rerender() {
        table.refresh();
        applyFilter();
    }

    @FXML
    void onReset() {
        searchField.clear();
        familyFilter.getSelectionModel().selectFirst();
        opFilter.getSelectionModel().selectFirst();
        availableOnly.setSelected(false);
        applyFilter();
    }

    private void applyFilter() {
        String q = searchField.getText() == null ? "" : searchField.getText().trim().toLowerCase();
        AlgoSpec.Family fam = familyFilter.getValue();
        AlgoSpec.Op     op  = opFilter.getValue();
        boolean availOnly   = availableOnly.isSelected();

        Predicate<AlgoSpec> pred = s -> {
            if (fam != null && s.family() != fam) return false;
            if (op  != null && s.op()     != op)  return false;
            if (availOnly && !availableIds.contains(s.id())) return false;
            if (!q.isEmpty()) {
                boolean match = s.id().toLowerCase().contains(q)
                    || s.jceName().toLowerCase().contains(q)
                    || s.ckmHex().toLowerCase().contains(q)
                    || s.family().name().toLowerCase().contains(q);
                if (!match) return false;
            }
            return true;
        };
        filtered.setPredicate(pred);
        countLabel.setText("표시 %d / 전체 %d  (가용 %d)"
            .formatted(filtered.size(), master.size(), availableIds.size()));
    }

    private static String flags(AlgoSpec s) {
        StringBuilder sb = new StringBuilder();
        if (s.fipsApproved()) sb.append("🛡 ");
        if (s.vendorOnly())   sb.append("🏷 ");
        if (s.deprecated())   sb.append("⚠ ");
        if (s.regional())     sb.append("🌏 ");
        return sb.toString().strip();
    }

    private static <E extends Enum<E>> StringConverter<E> enumConverter(String nullLabel) {
        return new StringConverter<>() {
            @Override public String toString(E e) { return e == null ? nullLabel : e.name(); }
            @Override public E fromString(String s) { return null; }
        };
    }
}
