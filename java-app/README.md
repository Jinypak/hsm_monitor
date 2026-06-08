# java-app

HSM Monitor의 JavaFX 본체.

## 사전 준비

1. **OpenJDK 25** 설치 + `JAVA_HOME` 설정 (또는 폴백용 JDK 21)
2. **Luna Client 10.9.1** 설치 — 네이티브 라이브러리 + LunaProvider.jar 동봉
3. **`LunaProvider.jar`를 `libs/`로 복사**:
   `C:\Program Files\SafeNet\LunaClient\jsp\LunaProvider.jar` → `libs/`
4. `build.gradle.kts`에서 `implementation(files("libs/LunaProvider.jar"))` **주석 해제**

> 현 단계(b 스켈레톤)에서는 LunaProvider 없이도 빈 화면이 뜬다.
> Phase 1 코드를 채우기 시작하면 jar가 필수가 된다.

## Gradle Wrapper 생성 (최초 1회)

이 저장소엔 wrapper 바이너리가 없다. 직접 생성:

```bash
gradle wrapper --gradle-version 8.10
```

생성 후엔 `./gradlew` (Windows: `gradlew.bat`) 사용.

## 빌드 / 실행

```bash
./gradlew run                       # 개발 실행 (JDK 25)
./gradlew run -PjavaVersion=21      # JDK 21 폴백 (Luna JSP 호환성 이슈 시)
./gradlew test                      # 테스트 (JUnit 5)
./gradlew build                     # JAR 빌드
```

## 환경 변수 (선택)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `LUNA_LIB_PATH` | `C:\Program Files\SafeNet\LunaClient` | `java.library.path` 로 전달 |

## 디렉터리

```
java-app/
├── settings.gradle.kts
├── build.gradle.kts
├── gradle.properties
├── libs/                       # LunaProvider.jar 위치 (사용자가 복사)
└── src/
    ├── main/
    │   ├── java/com/yours/hsm/
    │   │   ├── App.java
    │   │   └── ui/MainController.java
    │   └── resources/
    │       ├── fxml/main.fxml
    │       ├── css/dark.css
    │       └── log4j2.xml
    └── test/java/com/yours/hsm/
        └── AppSmokeTest.java
```

## 현재 상태

**Phase 1 스켈레톤.**
- 4-탭(연결/서명·검증/암복호화/결과) 빈 화면 기동
- legacy-py의 다크 테마 색상 이식 (CSS)
- 로깅: SLF4J + Log4j2 (`%USERPROFILE%\.hsm-monitor\logs\app.log`)

다음 단계:
- `core/`, `algo/`, `config/` 패키지 채우기 (`docs/phase1-design.md` 참고)
- `ConnectionController`, `SignVerifyController`, `EncryptController` 구현
- LunaProvider 등록 + KeyStore 로드
