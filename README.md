# HSM Monitor

Thales Luna HSM 운영 시연·검증 도구.
**Luna JSP Provider(Java JCE)** 기반.

> 현재 상태: **Phase 1 시작 전 (설계 단계)**
> Python 프로토타입(`legacy-py/`)을 기반으로 Java/JavaFX 본 제품으로 전환.

---

## 1차 알고리즘 스코프
**AES + RSA**
EC/EdDSA/PQC 등 그 외 메커니즘은 카탈로그에 데이터로만 두고 미구현. 펌웨어 업그레이드(PQC 빌드) 후 ML-KEM/ML-DSA 추가 예정.

---

## 디렉터리

| 경로 | 내용 |
|------|------|
| `docs/` | 설계 문서 — Phase 1 스코프, 호환성, 메커니즘 카탈로그 |
| `java-app/` | (Phase 1 시작 시) Gradle + JavaFX 소스 — 현재 비어있음 |
| `legacy-py/` | Python 프로토타입 — 참고용, 더는 수정하지 않음 |

---

## 스택

| 항목 | 값 |
|------|-----|
| JDK | OpenJDK 25 LTS |
| 빌드 | Gradle (Kotlin DSL) |
| GUI | JavaFX 21+ |
| HSM | Thales Luna (Network/PCIe) |
| 클라이언트 | Luna Client 10.9.1 |
| 펌웨어 | TBD (PQC 빌드로 추후 업그레이드) |
| Provider | LunaProvider (JCE) |
| 로깅 | SLF4J + Log4j2 |
| 테스트 | JUnit 5 + Mockito |
| 패키징 | jpackage → `.msi` |

---

## Phase 로드맵

| Phase | 목표 | 산출물 |
|-------|------|--------|
| 1 | Gradle 스켈레톤 + 연결/키조회 + RSA Sign/Verify | legacy-py 1:1 이식 완료 |
| 2 | AES 암복호화·KW·CMAC, 메커니즘 콤보, 차트, CSV | 운영 시연 완성도 |
| 3 | jpackage 인스톨러, 설정 영속화(`%APPDATA%`), Discord 알림 연동 | `.msi` 배포본 |
| 4 | PQC 지원 (펌웨어 업그레이드 후) | ML-DSA·ML-KEM 추가 |

---

## 참고 문서
- [Phase 1 상세 스코프](docs/phase1-scope.md)
- [Phase 1 상세 설계](docs/phase1-design.md)
- [JDK 25 + Luna 10.9.1 호환성 매트릭스](docs/compatibility.md)
- [메커니즘 카탈로그](docs/mechanism-catalog.md)
- [legacy-py 안내](legacy-py/README.md)
