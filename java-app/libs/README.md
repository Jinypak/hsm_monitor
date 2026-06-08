# libs/

LunaProvider.jar 가 위치할 디렉터리.

## 복사

Luna Client 10.9.1 설치 후:

```
원본: C:\Program Files\SafeNet\LunaClient\jsp\LunaProvider.jar
대상: hsm-monitor/java-app/libs/LunaProvider.jar
```

복사 후 `../build.gradle.kts` 에서 다음 라인의 주석을 해제:

```kotlin
implementation(files("libs/LunaProvider.jar"))
```

## 주의

- 이 디렉터리의 jar 는 Luna Client 와 함께 배포되는 **벤더 jar** 다. 직접 빌드하지 않는다.
- 이 폴더는 향후 git 연동 시 `.gitignore` 로 **반드시 제외**할 것 (라이선스/저작권 이슈).
