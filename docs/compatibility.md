# 호환성 매트릭스

빌드 시작 전 검증해야 할 환경 호환성. 문제 발생 시 이 표를 갱신.

## 결정된 기본값

| 항목 | 값 | 근거 |
|------|-----|------|
| JDK | OpenJDK 25 LTS | PQC(ML-KEM/ML-DSA) JEP 496/497 — JDK 24 정식, 25 안정화 |
| Luna Client | 10.9.1 | 사용자 환경 표준 |
| 펌웨어 | TBD (10.9.1 매트릭스 기준 → 추후 PQC 빌드) | |
| LunaProvider | Luna Client 10.9.1 동봉 jar | |

## ⚠ 위험 요소와 대응

| 위험 | 영향 | 대응 |
|------|------|------|
| Luna JSP 10.9.1 공식 지원 매트릭스에 JDK 25 미명시 가능 | 정식 지원 미보장 | CI에 **JDK 21 LTS 매트릭스 병행** — 필요 시 즉시 다운그레이드 가능하게 |
| JDK 22+ 네이티브 액세스 제약 강화 | LunaProvider 네이티브 호출 시 경고/오류 | 런타임 옵션 `--enable-native-access=ALL-UNNAMED` 추가 |
| Provider signing 검증 강화 | LunaProvider.jar 로드 거부 | Thales 서명 유효성 확인, 만료 시 갱신본 요청 |
| HSM PQC ≠ JDK PQC | JDK가 ML-DSA 알고리즘을 광고해도 HSM에 키 생성 불가능 | `ProviderProbe`가 LunaProvider의 서비스만 보고 결정 (JDK 표준 Provider 무시) |
| `cryptoki.dll` 경로 자동 탐색 실패 | 연결 시 UnsatisfiedLinkError | `-Djava.library.path=C:\Program Files\SafeNet\LunaClient` 명시 |
| `Cryptoki.cfg` 위치 다양 | 슬롯 검출 실패 | `-DLUNA_CONFIG_PATH=...` 명시, jpackage 시 동봉 |
| OpenJFX 모듈 의존 | 배포본에 JavaFX 누락 | jpackage 시 OpenJFX 모듈 명시 포함 |

## Gradle toolchain 설정

```kotlin
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(
            providers.gradleProperty("javaVersion")
                .map(Integer::parseInt)
                .orElse(25)
                .get()
        ))
    }
}
```

CI 매트릭스:
- 메인: `./gradlew test` (JDK 25)
- 폴백: `./gradlew test -PjavaVersion=21`

둘 다 그린이어야 머지 가능.

## 의존성 핵심 (build.gradle.kts 발췌)

```kotlin
dependencies {
    implementation(files("libs/LunaProvider.jar"))
    implementation("org.openjfx:javafx-controls:21")
    implementation("org.openjfx:javafx-fxml:21")
    implementation("org.slf4j:slf4j-api:2.0.13")
    implementation("org.apache.logging.log4j:log4j-slf4j2-impl:2.23.1")
    implementation("org.apache.logging.log4j:log4j-core:2.23.1")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    testImplementation("org.mockito:mockito-core:5.11.0")
}

tasks.named<JavaExec>("run") {
    jvmArgs = listOf(
        "--enable-native-access=ALL-UNNAMED",
        "-Djava.library.path=C:\\Program Files\\SafeNet\\LunaClient",
        "-Dlog4j.configurationFile=log4j2.xml"
    )
}
```

## jpackage 옵션 (Phase 3)

```bash
jpackage \
  --name "HSM-Monitor" \
  --type msi \
  --input build/libs \
  --main-jar hsm-monitor.jar \
  --icon icon.ico \
  --win-shortcut --win-menu \
  --java-options "--enable-native-access=ALL-UNNAMED" \
  --java-options "-Djava.library.path=C:\Program Files\SafeNet\LunaClient" \
  --java-options "-Dlog4j.configurationFile=log4j2.xml"
```

JRE는 jpackage가 자동 번들. **LunaClient는 사용자가 별도 설치** (이미 Thales 환경엔 깔려 있다고 가정).

## 검증 체크리스트 (Phase 1 시작 시)

- [ ] OpenJDK 25 설치 및 `JAVA_HOME` 확인
- [ ] OpenJDK 21 별도 설치 (폴백용)
- [ ] Luna Client 10.9.1 설치 + `lunacm` 동작 확인
- [ ] `LunaProvider.jar` 위치 확인 (`C:\Program Files\SafeNet\LunaClient\jsp\LunaProvider.jar`)
- [ ] HSM 슬롯 PIN 보유
- [ ] 테스트용 RSA/AES 키 1쌍 미리 생성
- [ ] 한글 IME 입력 가능한 환경 (로그·메시지 박스용)

## 펌웨어 업그레이드 후 (Phase 4 진입 조건)

- [ ] PQC 빌드 펌웨어 적용
- [ ] `lunacm mechanism list` 재덤프
- [ ] `mechanism-catalog.md` 갱신 — ML-KEM/ML-DSA/SLH-DSA 항목 추가
- [ ] `ProviderProbe` 출력에서 새 알고리즘 자동 검출 확인
- [ ] UI 콤보에서 PQC 항목 활성화 확인
