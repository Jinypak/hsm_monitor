# Phase 1 상세 설계

> 인터페이스/시그니처/책임 분담 박제. 구현 전 검토용.
> 변경 시 이 문서 먼저 갱신 후 코드 반영.

---

## 1. 패키지 의존 그래프

```
        ui (JavaFX, FXML)
         │
         ▼
   ┌──────────┐
   │   algo   │ ◀───────── (데이터 + 인터페이스만)
   └──────────┘
         ▲
         │
   ┌──────────┐      ┌──────────┐
   │   core   │◀────▶│  config  │
   └──────────┘      └──────────┘
         │
         ▼
  LunaProvider (JCE)
         │
         ▼
   cryptoki (네이티브)
```

**규칙**:
- `ui` → `core`, `algo`, `config` 가능
- `core` → `algo`, `config` 가능
- `algo` → 어떤 것도 의존 X (순수 데이터 + 인터페이스)
- `config` → 어떤 것도 의존 X
- **`core`는 JavaFX import 0개**

---

## 2. `algo` 패키지 — 데이터 + 인터페이스

### 2.1 `AlgoSpec` (record)

```java
package com.yours.hsm.algo;

public record AlgoSpec(
    String  id,            // "RSA_SIGN_SHA256_PKCS"  — 안정 ID
    Family  family,        // RSA, AES, EC, EDDSA, ML_DSA, ML_KEM, ...
    Op      op,            // SIGN, VERIFY, ENC, DEC, WRAP, MAC, KDF, KEYGEN, KEYPAIR_GEN
    String  jceName,       // "SHA256withRSA"
    String  ckmHex,        // "0x00000040" — 추적용
    int     keyBits,       // 0 = 가변
    boolean fipsApproved,  // 🛡
    boolean vendorOnly,    // 🏷 (0x80000000+)
    boolean phase1Default  // ⭐ UI 콤보 기본 항목
) {
    public enum Family { RSA, AES, EC, EDDSA, MONTGOMERY, DSA, DH, HMAC, DIGEST, KDF,
                         ARIA, SM2, SM3, SM4, DES3, ML_DSA, ML_KEM, SLH_DSA }
    public enum Op     { KEYGEN, KEYPAIR_GEN, SIGN, VERIFY, ENC, DEC,
                         WRAP, UNWRAP, MAC, DIGEST, DERIVE, KDF, PARAM_GEN }
}
```

### 2.2 `AlgoCatalog`

```java
public final class AlgoCatalog {
    private static final List<AlgoSpec> ALL = List.of(
        // §11.3 mechanism-catalog 항목들 — Phase 1 기본 11개 + 확장
        new AlgoSpec("RSA_KEYPAIR",        Family.RSA, Op.KEYPAIR_GEN, "RSA",
                     "0x00000000", 0, true, false, true),
        new AlgoSpec("RSA_SIGN_SHA256",    Family.RSA, Op.SIGN, "SHA256withRSA",
                     "0x00000040", 0, true, false, true),
        new AlgoSpec("RSA_SIGN_SHA256_PSS",Family.RSA, Op.SIGN, "SHA256withRSA/PSS",
                     "0x00000043", 0, true, false, true),
        new AlgoSpec("RSA_OAEP_SHA256",    Family.RSA, Op.ENC,
                     "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                     "0x00000009", 0, true, false, true),
        new AlgoSpec("AES_KEYGEN",         Family.AES, Op.KEYGEN, "AES",
                     "0x00001080", 0, true, false, true),
        new AlgoSpec("AES_CBC_PKCS5",      Family.AES, Op.ENC, "AES/CBC/PKCS5Padding",
                     "0x00001085", 0, true, false, true),
        new AlgoSpec("AES_GCM",            Family.AES, Op.ENC, "AES/GCM/NoPadding",
                     "0x00001087", 0, true, false, true),
        new AlgoSpec("AES_KWP",            Family.AES, Op.WRAP, "AESWrapPad",
                     "0x80000171", 0, true, true,  true),
        new AlgoSpec("AES_CMAC",           Family.AES, Op.MAC, "AESCMAC",
                     "0x0000108a", 0, true, false, true),
        new AlgoSpec("HMAC_SHA256",        Family.HMAC, Op.MAC, "HmacSHA256",
                     "0x00000251", 0, true, false, true),
        new AlgoSpec("SHA256",             Family.DIGEST, Op.DIGEST, "SHA-256",
                     "0x00000250", 0, true, false, true)
        // 비-Phase1 항목은 데이터로만 추가 (phase1Default=false)
    );

    public static List<AlgoSpec> all()                       { ... }
    public static List<AlgoSpec> phase1()                    { ... }   // phase1Default=true
    public static List<AlgoSpec> by(Family f)                { ... }
    public static List<AlgoSpec> by(Op op)                   { ... }
    public static Optional<AlgoSpec> findById(String id)     { ... }
}
```

### 2.3 `CryptoOperation` (sealed interface)

```java
public sealed interface CryptoOperation
    permits SignOp, EncryptOp, WrapOp, MacOp, KemOp {

    AlgoSpec spec();
    OpResult execute(byte[] input) throws CryptoOpException;
}

public final class SignOp    implements CryptoOperation { ... }
public final class EncryptOp implements CryptoOperation { ... }   // ENC/DEC 둘 다
public final class WrapOp    implements CryptoOperation { ... }
public final class MacOp     implements CryptoOperation { ... }
public final class KemOp     implements CryptoOperation { ... }   // ⚠ Phase 4 자리, 본문 throw new UnsupportedOperationException
```

### 2.4 `OpResult` / `CryptoOpException`

```java
public record OpResult(
    boolean         ok,
    long            durationNs,
    Optional<byte[]> output,    // 서명·암호문·MAC 등
    Optional<byte[]> verifyHash,// 검증 시 사용한 해시 (UI 표시용)
    Optional<String> errorCode, // CKR_* 매핑
    Optional<String> errorMsg
) {
    public double durationMs() { return durationNs / 1_000_000.0; }
}

public class CryptoOpException extends Exception {
    public enum Code { PIN_INCORRECT, KEY_NOT_FOUND, MECH_NOT_SUPPORTED,
                       SLOT_LOCKED, SESSION_CLOSED, GENERAL }
    private final Code code;
    public Code code() { return code; }
}
```

---

## 3. `core` 패키지 — 비즈니스 로직

### 3.1 `LunaSession`

```java
public final class LunaSession implements AutoCloseable {

    public static LunaSession connect(int slot, char[] pin) throws CryptoOpException;

    public KeyStore  keyStore();          // KeyStore("Luna") 인스턴스
    public Provider  provider();          // LunaProvider 핸들
    public String    tokenLabel();
    public int       slot();
    public boolean   isLoggedIn();

    @Override public void close();        // logout + 자원 해제
}
```

**책임**:
- LunaProvider 등록 (`Security.addProvider`)
- `LunaSlotManager.login()` 호출
- KeyStore 로드 (`KeyStore.getInstance("Luna")`)
- 라이프사이클 관리 (`AutoCloseable`)

**의존**: LunaProvider (JCE), `config.AppConfig`

### 3.2 `KeyCatalog`

```java
public final class KeyCatalog {

    public KeyCatalog(LunaSession session);

    public List<KeyEntry>      list()                throws CryptoOpException;
    public Optional<KeyEntry>  findByAlias(String a) throws CryptoOpException;
    public Optional<KeyPair>   asKeyPair(KeyEntry e) throws CryptoOpException;
    public Optional<SecretKey> asSecretKey(KeyEntry e) throws CryptoOpException;

    public record KeyEntry(
        String  alias,
        KeyKind kind,         // PRIVATE, PUBLIC, SECRET, KEYPAIR
        String  algorithm,    // "RSA", "AES", "EC" ...
        int     keyBits       // 0 if unknown
    ) {}

    public enum KeyKind { PRIVATE, PUBLIC, SECRET, KEYPAIR }
}
```

### 3.3 `ProviderProbe`

```java
public final class ProviderProbe {

    public static ProviderProbe of(Provider lunaProvider);

    public Set<String> jceAlgorithms();      // "Signature.SHA256withRSA" 형식
    public boolean     supports(AlgoSpec s);
    public List<AlgoSpec> filter(Collection<AlgoSpec> candidates);  // 가용한 것만
}
```

**책임**: 시작 시 1회, 펌웨어 업그레이드 후 자동으로 새 알고리즘 노출.

### 3.4 `SignWorkload`

```java
public final class SignWorkload implements AutoCloseable {

    public SignWorkload(LunaSession session, AlgoSpec spec, KeyEntry key);

    /** 비동기 루프 시작. 콜백은 워커 스레드에서 호출됨. */
    public void start(WorkloadConfig cfg, Listener listener);
    public void stop();

    public record WorkloadConfig(
        double  ratePerSec,    // 0.1 ~ 10.0
        boolean externalVerify // true = SunRsaSign으로 외부 검증
    ) {}

    public interface Listener {
        void onResult(int seq, OpResult r);
        void onStats(MetricsSnapshot snapshot);
        void onError(Throwable t);
    }

    @Override public void close();
}
```

**책임**:
- 루프 내에서 `Signature.sign()` + `Verifier.verify()` 수행
- 결과를 `MetricsCollector` 에 누적
- 콜백으로 UI 통지 (UI 스레드 전환은 호출자 책임)

### 3.5 `Verifier`

```java
public final class Verifier {

    public Verifier(Provider externalProvider);  // SunRsaSign / SunEC / null=같은 LunaProvider

    public boolean verify(AlgoSpec spec, PublicKey pub, byte[] data, byte[] sig)
        throws CryptoOpException;
}
```

### 3.6 `MetricsCollector` / `MetricsSnapshot`

```java
public final class MetricsCollector {

    public void add(OpResult r);
    public MetricsSnapshot snapshot();
    public void reset();
}

public record MetricsSnapshot(
    long total, long pass, long fail,
    double rate,            // ops/sec
    double avgSignMs,
    double avgVerifyMs,
    Duration elapsed
) {}
```

### 3.7 `Recorder`

```java
public final class Recorder {

    public void append(int seq, OpResult r);
    public void clear();

    public Path saveJson(Path dir, MetricsSnapshot stats) throws IOException;
    public Path saveCsv (Path dir, MetricsSnapshot stats) throws IOException;
}
```

---

## 4. `config` 패키지

```java
public record AppConfig(
    String  lunaLibPath,        // "C:\\Program Files\\SafeNet\\LunaClient"
    int     defaultSlot,
    String  lastSelectedAlias,
    String  lastSelectedAlgoId, // AlgoSpec.id
    double  lastRate,
    Path    lastSaveDir
) {
    public static AppConfig load();          // %APPDATA%\HSMMonitor\config.json
    public        void      save();
    public static AppConfig defaults();
}
```

**주의**: PIN은 저장하지 **않는다**. Phase 3에서 OS keystore(Windows DPAPI) 검토.

---

## 5. `ui` 패키지 — JavaFX 컨트롤러

```java
public final class MainController {
    @FXML private TabPane tabs;
    @FXML private Tab     connectionTab, signVerifyTab, encryptTab, resultTab;

    public void initialize();
}

public final class ConnectionController {
    @FXML private TextField slotField, libPathField;
    @FXML private PasswordField pinField;
    @FXML private TableView<KeyEntry> keyTable;
    @FXML private Label  statusLabel;

    @FXML private void onConnect();
    @FXML private void onRefresh();
}

public final class SignVerifyController {
    @FXML private ComboBox<AlgoSpec>  mechCombo;
    @FXML private ComboBox<KeyEntry>  keyCombo;
    @FXML private Slider              rateSlider;
    @FXML private TextArea            logArea;
    @FXML private Label total, pass, fail, avgSign, avgVerify, elapsed;

    @FXML private void onStart();
    @FXML private void onStop();
    @FXML private void onSaveJson();
    @FXML private void onSaveCsv();
}

public final class EncryptController {
    @FXML private ComboBox<AlgoSpec> mechCombo;     // AES_CBC_PKCS5 / AES_GCM / RSA_OAEP_SHA256
    @FXML private ComboBox<KeyEntry> keyCombo;
    @FXML private TextArea           plaintextArea, ciphertextArea, decryptedArea;
    @FXML private Label              roundtripStatus;

    @FXML private void onEncrypt();
    @FXML private void onDecrypt();
    @FXML private void onRoundtripTest();
}
```

UI 스레드 전환: 모든 콜백은 `Platform.runLater(...)` 로 감싸서 처리.

---

## 6. 주요 시퀀스

### 6.1 연결 + 키조회

```
User → ConnectionCtrl : onConnect()
ConnectionCtrl → LunaSession : connect(slot, pin)
LunaSession → LunaProvider  : Security.addProvider
LunaSession → LunaSlotManager : login(slot, pin)
LunaSession ← (session)
ConnectionCtrl → KeyCatalog : new(session).list()
KeyCatalog → KeyStore       : aliases() + 메타데이터 추출
KeyCatalog ← List<KeyEntry>
ConnectionCtrl → keyTable.setItems(...)
```

### 6.2 RSA Sign/Verify 자동화 1회

```
User → SignVerifyCtrl : onStart()
SignVerifyCtrl → SignWorkload : new(session, algo, key)
SignWorkload → Signature.getInstance(spec.jceName(), provider)
loop {
  SignWorkload → Signature : initSign(priv) + update + sign
  SignWorkload → Verifier  : verify(spec, pub, data, sig)
  SignWorkload → MetricsCollector : add(OpResult)
  SignWorkload → Listener.onResult(seq, r)
  SignWorkload → Listener.onStats(snapshot)
  sleep(interval)
}
```

### 6.3 AES 라운드트립 (CBC/GCM)

```
User → EncryptCtrl : onRoundtripTest()
EncryptCtrl → KeyCatalog.asSecretKey(aesAlias)
EncryptCtrl → Cipher.getInstance("AES/GCM/NoPadding", provider)
            → init(ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            → doFinal(plain) → ciphertext
            → init(DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            → doFinal(ciphertext) → recovered
EncryptCtrl → assertEquals(plain, recovered)
EncryptCtrl → roundtripStatus.setText("PASS")
```

---

## 7. 에러 처리 정책

| Luna/JCE 예외 | 매핑 코드 | UI 표시 |
|---------------|----------|--------|
| `LoginException` (PIN 불일치) | PIN_INCORRECT | "PIN이 올바르지 않습니다" + 입력 초기화 |
| `LoginException` (PIN 잠금) | SLOT_LOCKED | "슬롯이 잠겼습니다. HSM 관리자 문의" |
| `KeyStoreException` | KEY_NOT_FOUND | 빨간색 로그 + 키 콤보 비우기 |
| `NoSuchAlgorithmException` | MECH_NOT_SUPPORTED | "이 메커니즘은 현재 펌웨어에서 미지원" + 콤보에서 비활성 표시로 갱신 |
| `ProviderException` (네이티브) | GENERAL | 풀 스택트레이스를 로그에만, 사용자에겐 요약 |
| `InvalidKeyException` | GENERAL | 키 종류 불일치 안내 |

원칙:
- **사용자 메시지는 한글, 친근하게**
- **로그는 영문 가능, 스택트레이스 포함**
- 워커 스레드 예외는 절대 삼키지 않는다 → `Listener.onError(t)`

---

## 8. 테스트 매트릭스

### 8.1 단위 (LunaProvider 없음)

| 대상 | 시나리오 | 모킹 |
|------|---------|------|
| `AlgoCatalog` | phase1() 11개 반환, by(Family.RSA) 필터링 | — |
| `MetricsCollector` | 1000건 누적 후 통계 정확성 | — |
| `Recorder` | JSON/CSV 출력 포맷 검증 | tmp dir |
| `ProviderProbe` | 가짜 Provider의 서비스 셋 → AlgoSpec 필터 | `MockProvider` |
| `Verifier` | RSA SHA256 PKCS#1 정상/위변조 케이스 | SunRsaSign 실사용 |
| `SignWorkload` | 정상 sign+verify 루프 → MetricsSnapshot | `MockProvider` + Mockito |

### 8.2 통합 (Luna 필요)

| 시나리오 | 사전 조건 |
|---------|---------|
| 슬롯 로그인 + KeyStore 로드 | 유효 PIN |
| RSA 키쌍 1개 생성 | RW 세션 |
| Sign/Verify 100회 루프 | RSA 키 존재 |
| AES 키 생성 + CBC/GCM 라운드트립 | RW 세션 |
| AES KWP로 RSA 공개키 래핑 | 둘 다 존재 |

→ `@EnabledIfEnvironmentVariable(named="LUNA_PIN", matches=".+")` 로 게이트.

### 8.3 UI (수동)

- 한글 라벨/메시지 깨짐 없음
- 슬라이더 0.1~10.0 범위 동작
- FAIL 누적 시 빨간색 로그
- 탭 전환 후 통계 유지

---

## 9. 비기능 요구

| 항목 | 목표 |
|------|------|
| 기동 시간 | < 3초 (LunaProvider 로드 제외) |
| 1회 sign+verify 추가 오버헤드 (JNI 외) | < 1ms |
| 메모리 | 기본 < 200MB, 100k records 보관 시 < 500MB |
| UI 프리즈 | 100ms 이상 메인스레드 점유 0건 |
| 로그 파일 | 일자별 롤링, 30일 보관 |

---

## 10. DoD (Phase 1 종료 조건)

`phase1-scope.md` §DoD 와 동일.
이 설계서의 클래스/시그니처가 모두 구현되고 8.1·8.2 테스트 그린일 것.

---

## 11. 미결 항목 (구현 시 결정)

- [ ] `Signature.getInstance("SHA256withRSA/PSS", provider)` vs `setParameter(PSSParameterSpec)` — 실 Provider 동작 확인 필요
- [ ] `AESWrapPad` 알고리즘명이 LunaProvider에서 그대로 노출되는지
- [ ] `KeyStore("Luna")` 로드 시 InputStream에 무엇을 넣을지 (slot 식별 방식) — 10.x 문서 확인 필요
- [ ] HMAC 키를 KeyStore에서 alias로 가져오는 절차 (LunaProvider 매뉴얼 §HMAC)
- [ ] `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", provider)` 의 정확한 OAEPParameterSpec 인자
