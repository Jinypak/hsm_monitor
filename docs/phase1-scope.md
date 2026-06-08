# Phase 1 스코프

> 이 문서는 1차 릴리스 범위와 결정사항을 박제한다. 합의 변경 시 이 문서를 갱신.

## 결정 요약

| 항목 | 값 |
|------|-----|
| 대상 사용자 | 사내 배포용 (B 옵션) |
| 알고리즘 | **AES + RSA only** |
| GUI | JavaFX (Swing 아님) |
| 빌드 | Gradle (Kotlin DSL) |
| 마이그레이션 전략 | A — 점진적 (Python 도구 병행 운영) |

## 모듈 구조 (java-app/)

```
src/main/java/com/yours/hsm/
├── App.java                       # JavaFX entry
├── core/                          # JavaFX import 0개
│   ├── LunaSession.java           # LunaSlotManager.login/logout
│   ├── KeyCatalog.java            # KeyStore("Luna") alias 열거
│   ├── SignWorkload.java          # Sign/Verify 루프, 통계
│   ├── Verifier.java              # Sun* provider 외부 검증
│   ├── MetricsCollector.java      # 통계 집계
│   ├── Recorder.java              # JSON/CSV 저장
│   └── ProviderProbe.java         # 런타임 알고리즘 가용성 탐지
├── algo/
│   ├── AlgoSpec.java              # record(family, op, jceName, keySize, ...)
│   ├── AlgoCatalog.java           # mechanism-catalog.md §11.3 데이터화
│   └── CryptoOperation.java       # 인터페이스
│       ├── SignOp                 # 구현
│       ├── EncryptOp              # 구현
│       ├── WrapOp                 # 구현
│       └── KemOp                  # 미래 PQC 자리 (인터페이스만)
├── config/
│   └── AppConfig.java             # %APPDATA%\HSMMonitor\config.json
└── ui/
    ├── MainController.java
    ├── ConnectionTab.java
    ├── SignVerifyTab.java         # legacy-py hsm_gui 화면 1:1 이식
    ├── EncryptTab.java            # 신규 — AES/RSA 암복호화
    └── theme.css

src/main/resources/
├── fxml/
│   ├── main.fxml
│   ├── connection.fxml
│   ├── sign-verify.fxml
│   └── encrypt.fxml
├── css/dark.css                   # 현 hsm_gui.py 다크테마 이식
└── log4j2.xml

src/test/java/com/yours/hsm/
├── core/...                       # 단위 테스트
└── mock/MockProvider.java         # LunaProvider 없는 CI용 가짜 Provider
```

## UI — 3-탭 구성

```
┌─ 연결 ───────────────────────────────────────┐
│ Slot / PIN / Provider 정보 / 키 목록           │
├─ 서명·검증 (RSA) ────────────────────────────┤
│ 키 선택 + 메커니즘 선택 + 속도 + 통계 + 로그    │  ← legacy-py 화면 거의 그대로
├─ 암복호화 (AES/RSA) ─────────────────────────┤
│ 모드(CBC/GCM/OAEP) + 평문/IV + 라운드트립 검증  │  ← 신규
└─ 결과 ───────────────────────────────────────┘
   누적 통계 차트 + JSON/CSV 저장 + 비교
```

## 사용 메커니즘 (mechanism-catalog.md §11.3 발췌)

| 용도 | CKM | JCE |
|------|-----|-----|
| RSA 키쌍 생성 | CKM_RSA_PKCS_KEY_PAIR_GEN | `RSA` |
| RSA 서명 (PKCS#1 v1.5) | CKM_SHA256_RSA_PKCS | `SHA256withRSA` |
| RSA 서명 (PSS) | CKM_SHA256_RSA_PKCS_PSS | `SHA256withRSA/PSS` |
| RSA 암복호화 | CKM_RSA_PKCS_OAEP | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` |
| AES 키 생성 | CKM_AES_KEY_GEN | `AES` |
| AES 암복호화 (CBC) | CKM_AES_CBC_PAD | `AES/CBC/PKCS5Padding` |
| AES 암복호화 (GCM) | CKM_AES_GCM | `AES/GCM/NoPadding` |
| AES 키래핑 | CKM_AES_KWP | `AESWrapPad` |
| AES MAC | CKM_AES_CMAC | `AESCMAC` |
| HMAC (보조) | CKM_SHA256_HMAC | `HmacSHA256` |
| 외부 검증용 해시 | CKM_SHA256 | `SHA-256` |

## PQC 대비 — "지금 안 만들지만 막히지 않게"

3곳만 추상화하면 펌웨어 업그레이드 후 코드 변경 최소화:

1. **AlgoSpec 데이터** — 카탈로그를 enum이 아니라 데이터(JSON 또는 Java record 리스트)로
2. **CryptoOperation 인터페이스** — `SignOp`, `EncryptOp`, `WrapOp` 외에 `KemOp` 자리만 만들어두기 (구현 X)
3. **ProviderProbe** — 시작 시 `Security.getProvider("LunaProvider").getServices()` 로 가용 알고리즘 광고 → UI 콤보는 항상 *프로바이더가 실제로 노출하는 것*만 보여줌. 펌웨어 올라가면 ML-DSA가 자동으로 콤보에 뜸

UI 콤보박스: 비활성 항목은 "🔒 펌웨어 ≥ X.Y 필요" 툴팁.

## 명시적 제외 항목 (Phase 1에서 안 함)
- EC / ECDSA / ECDH
- EdDSA (Ed25519/Ed448)
- 모든 PQC (ML-KEM, ML-DSA, SLH-DSA)
- DSA / DH (legacy)
- DES / DES3 / ARIA / SM2·SM3·SM4 / RC*/CAST*
- DUKPT / Milenage / TUAK / BIP32
- SSL3 KDF, PBE
- HA(High Availability) 그룹 시연 — Phase 2 이후 검토

## Definition of Done — Phase 1
- [ ] `./gradlew run` 으로 GUI 기동
- [ ] `./gradlew test` 그린 (LunaProvider 없는 환경에서도)
- [ ] 연결 → 키 목록 → RSA Sign/Verify 자동화 → JSON/CSV 저장 동작
- [ ] AES 키 생성 → CBC/GCM 암복호화 → 라운드트립 검증 동작
- [ ] AES KWP 래핑 시연 (RSA 공개키로 AES 키 래핑 데모)
- [ ] 외부 검증(`SunRsaSign`) 통과 — HSM 결과의 독립 검증
- [ ] 한글 로그 + 한글 메시지 박스 정상 출력
- [ ] `legacy-py/hsm_gui.py`의 기능을 모두 대체 가능

## 향후 결정 보류 항목
- HSM 연결 정보 영속화 위치/암호화 방식 (Phase 1 후반)
- PSS 알고리즘 문자열 정확한 표기 — `SHA256withRSA/PSS` vs `SHA256withRSAandMGF1` (Provider 등록 후 확인)
- AES-KW vs AES-KWP 기본값 (KWP 잠정 채택, RFC 5649)
- HMAC을 1차에 포함할지 — 잠정 포함 (보조)

---

# Phase 2 — 전체 메커니즘 지원 (확장)

> Phase 1 의 "AES+RSA only / 알고리즘별 탭" 제약을 풀고, `mechanism-catalog.md` 의
> 메커니즘을 **JCE 매핑되는 것은 전부 실연산**, 나머지는 **카탈로그/가용성 표시**로 노출한다.
> 아키텍처는 Phase 1 설계(데이터+인터페이스+ProviderProbe)를 그대로 활용 — 코드 구조 변경 없이 데이터/콤보만 확장.

## 결정
| 항목 | 값 |
|------|-----|
| 범위 | JCE 표준 서비스로 매핑되는 메커니즘은 실연산(Tier A), 도메인 특화는 카탈로그/가용성(Tier B) |
| 카탈로그 | `AlgoCatalog.java` Java record 유지, 항목 대폭 추가 |
| UI | 알고리즘별 → **연산(Op) 중심 범용 탭** + **메커니즘 탐색기** 신설 |

## 연산 등급
- **Tier A (실연산)**: RSA(전 SHA·PKCS/PSS), AES(ECB/CBC/CTR/CFB/OFB/GCM/XTS, CMAC/GMAC, KW/KWP),
  EC(ECDSA 전 SHA, ECDH), EdDSA(Ed25519/Ed448), DSA, DH, ARIA, DES3(legacy), 전 Digest, 전 HMAC, PBKDF2.
- **Tier B (카탈로그/가용성)**: PQC(ML-DSA/ML-KEM/SLH-DSA), SM2/3/4, DUKPT/Milenage/TUAK/BIP32, SSL3, PBE, RC/CAST.
  → `ProviderProbe` 가 노출하면 연산 탭에도 자동 등장.

## 데이터/연산 변경
- `AlgoSpec` — 표시 플래그 `deprecated`(⚠)·`regional`(🌏) 추가(9-인자 호환 생성자 유지). `Family` enum 에 DES/RC/CAST/BIP32/DUKPT/MILENAGE/TUAK/SSL3/PBE 추가.
- `AlgoCatalog` — Tier A/B 항목 추가. `phase1Default=true` 는 §11.3 의 11개로 **불변**.
- `ProviderProbe.serviceType` — `DERIVE→KeyAgreement`, `KDF→SecretKeyFactory` 매핑 추가.
- `CryptoOperation`(sealed) — `DigestOp`(해시)·`DeriveOp`(ECDH/DH 키합의) 추가.
- `EncryptOp` — 모드 일반화(transformation 파싱 + `getBlockSize()` IV). AES 전 모드/ARIA/SM4/DESede 지원.
- `KeyManager` — `generateSecret(jceAlgo,…)`(ARIA/DESede/SM4)·`generateEc(curve)` 추가.

## UI — 연산 중심 탭
1. 연결  2. **메커니즘 탐색기**(검색/Family·Op 필터/가용성 ✅·🔒)  3. 서명·검증(전 SIGN family)
4. 암복호화(전 ENC)  5. **MAC·해시**(MAC+DIGEST 단발)  6. 키 관리(AES/RSA/EC/DES3/ARIA keygen)

연산 콤보는 `MechanismAvailability.filter(session, …)` 로 미연결 시 전체 후보, 연결 시 Provider 가용 항목만 노출.

## Phase 2 DoD
- [x] `./gradlew test` 그린 (Digest/EncryptOp 모드/KeyManager EC·DESede 단위테스트 포함)
- [ ] `./gradlew algoList` — 확장 카탈로그 × 실제 LunaProvider 가용성 매칭(HSM 필요)
- [ ] GUI: 탐색기 가용성 확인 / 암복호화(AES CTR·GCM·ARIA) / MAC·해시 / 서명·검증(EC 포함) / EC keygen (HSM 필요)
- [ ] 회귀: Phase 1 흐름(RSA Sign/Verify, AES CBC/GCM, AES-KWP) 유지
