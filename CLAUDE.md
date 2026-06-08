# CLAUDE.md — HSM Monitor

이 폴더에서 작업할 때 따를 가이드. 상위 `claude_pro/CLAUDE.md`보다 이 파일이 우선.

## 프로젝트 목표
Thales Luna HSM의 동작을 GUI로 시연/검증하는 도구. **운영환경의 Java 호출 경로(LunaProvider via JCE)를 그대로 재현**하는 것이 핵심 가치.

## 기술 스택
- OpenJDK 25 LTS (PQC JEP 496/497 정식 포함)
- Gradle (Kotlin DSL)
- JavaFX 21+ (FXML + CSS)
- LunaProvider — Luna Client 10.9.1 동봉 jar
- SLF4J + Log4j2
- JUnit 5 + Mockito (PKCS11 mock)

## 코드 규칙
- 커밋 메시지는 한글
- `System.out.println` 금지 → `logger` 사용
- 테스트 코드 필수. PKCS11 mock으로 LunaProvider 없는 환경에서도 빌드/테스트 가능해야 함
- 알고리즘은 enum/if-else로 박지 않는다
  - `AlgoSpec` 카탈로그(데이터) +
  - `CryptoOperation` 인터페이스(연산) +
  - `ProviderProbe`(런타임 가용성)
  → 펌웨어 업그레이드만으로 PQC가 켜지는 구조
- `core/` 패키지는 **JavaFX import 0개** (CLI 모드 가능하게)
- LunaProvider.jar는 `java-app/libs/` 경로에 두고 `implementation(files("libs/LunaProvider.jar"))`로 참조

## 빌드 / 실행
```
./gradlew run                   # 개발 실행
./gradlew test                  # 테스트
./gradlew :java-app:jpackage    # .msi 패키징 (Phase 3)
```

JDK 호환성 이슈 발생 시:
```
./gradlew run -PjavaVersion=21
```

## ⚠ 주의 사항
- **JDK 25는 Luna JSP 10.9.1 공식 지원 매트릭스에 미명시 가능** — CI에 JDK 21 매트릭스 병행 필수
- JDK 22+에서는 `--enable-native-access=ALL-UNNAMED` 런타임 옵션 필요
- Luna 네이티브 라이브러리 경로는 `-Djava.library.path` 또는 jpackage `--java-options`로 명시
- `Cryptoki.cfg` 위치는 `LunaProvider`가 자동 탐색 못 할 때 `-DLUNA_CONFIG_PATH=...`로 지정

## 알고리즘 스코프
**Phase 1: AES + RSA만**.
나머지는 `docs/mechanism-catalog.md`에 데이터로만 보관, UI에 노출하지 않음.
구체 매핑은 카탈로그 `§11.3` 참고.

## 작업 시 우선 참고 순서
1. `docs/phase1-scope.md` — 스코프와 결정사항
2. `docs/compatibility.md` — 빌드 환경 결정
3. `docs/mechanism-catalog.md` — 알고리즘 카탈로그
4. `legacy-py/hsm_gui.py` — 기능 명세 겸 동작 비교 기준
