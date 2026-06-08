# legacy-py

Python 프로토타입. **참고용. 더는 수정하지 않음.**

## 역할
Java/JavaFX 본 제품(`../java-app/`)의 **기능 명세서 겸 동작 비교 기준**으로만 사용.

## 파일

| 파일 | 설명 |
|------|------|
| `hsm_gui.py` | tkinter 기반 단일 화면 GUI. 연결/키조회/Sign-Verify 자동화/JSON 저장 |
| `hsm_sign_verify.py` | CLI 단발 Sign/Verify |
| `hsm_auto.py` | CLI 자동화 루프 (키쌍 생성 포함) |
| `samples/hsm_result.json` | `hsm_sign_verify.py` 실행 결과 샘플 |
| `samples/hsm_auto_result.json` | `hsm_auto.py` 실행 결과 샘플 |

## 의존
- Python 3.x
- PyKCS11
- cryptography
- Luna Client (`cryptoki.dll`)

## 실행 (참고용)
```
python hsm_gui.py
```

## Java 이식 매핑
| Python (현 위치) | Java 대응 (예정) |
|------------------|-----------------|
| `hsm_gui.py::HsmGui` | `ui.MainController` + `ui.SignVerifyTab` |
| `hsm_gui.py::_connect_worker` | `core.LunaSession` |
| `hsm_gui.py::_load_keys` | `core.KeyCatalog` |
| `hsm_gui.py::_loop` | `core.SignWorkload` |
| `hsm_gui.py::_save` | `core.Recorder` |
| `cryptography.hazmat ... verify(...)` | `core.Verifier` (SunRsaSign) |
| PyKCS11 직접 호출 | LunaProvider via JCE |

상세 매핑은 Phase 1 진입 시 별도 문서로.
