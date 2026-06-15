# Luna 공개키 getEncoded() == null 원인 정리

## 증상
구버전 LunaProvider(예: **10.5**)에서 토큰의 인증서로부터 공개키를 꺼낼 때
`publicKey.getEncoded()` 가 `null` 을 반환한다. 그 결과:
- 공개키 export(`.der`) 시 빈 값/NPE
- 공개키 base64 출력 시 null

신버전(10.7+)에서는 정상(예: RSA-2048 → 294 bytes DER)이라 환경에 따라 재현이 갈린다.

## 원인
```
Certificate c   = ks.getCertificate(alias);   // LunaCertificateX509
PublicKey   pub = c.getPublicKey();            // ← 여기서 받는 객체가 버전마다 다름
pub.getEncoded();                              // 10.5: null / 10.7+: X.509 DER
```

- **JCE 계약**: `Key.getEncoded()` 는 "키가 인코딩을 지원하지 않으면 null 을 반환할 수 있다."
- **10.5 동작**: `cert.getPublicKey()` 가 **HSM 토큰 객체를 가리키는 `LunaPublicKey`(하드웨어 백업 키)** 를 돌려준다.
  이 객체는 키 바이트를 JVM 메모리에 들고 있지 않고 토큰을 참조만 하므로,
  `getEncoded()` 가 토큰에서 값을 읽어 X.509 로 인코딩하지 않고 그냥 `null` 을 반환한다.
- **10.7+ 동작**: 인증서를 파싱해 **소프트웨어 공개키(`sun.security.rsa.RSAPublicKeyImpl`)** 로 돌려주므로
  `getEncoded()` 가 정상 동작한다.

즉 키가 잘못된 게 아니라, **구버전이 공개키를 토큰 핸들로 주고 인코딩을 구현하지 않은 것**이 원인이다.

## 해결
공개키의 **modulus / publicExponent 는 비밀이 아니므로 토큰 객체에서도 읽을 수 있다.**
이 두 값으로 표준 소프트웨어 공개키를 재구성하면 버전과 무관하게 정상 인코딩을 얻는다.

```java
PublicKey pub = cert.getPublicKey();
if (pub.getEncoded() == null && pub instanceof RSAPublicKey r) {
    pub = KeyFactory.getInstance("RSA")   // SunRsaSign
            .generatePublic(new RSAPublicKeySpec(r.getModulus(), r.getPublicExponent()));
}
// 이제 pub.getEncoded() 는 항상 X.509 SubjectPublicKeyInfo DER
```

`LunaRsaKeyLifecycle.publicKey()` 와 `RsaKeySample` 에 적용됨.

## 공개키 조회 3가지 방법
| # | 방법 | 설명 | 구버전(10.5) |
|---|------|------|------|
| 1 | `publicKeyRaw()` | `cert.getPublicKey()` 그대로 | `getEncoded()=null` 가능 |
| 2 | `publicKey()` | (1)이 null 이면 **Java 키의 modulus/exponent** 로 재구성 | OK |
| 3 | `publicKeyFromToken()` | **토큰 객체의 CKA_MODULUS/CKA_PUBLIC_EXPONENT** 직접 읽어 재구성 | OK (가장 견고) |

(2)는 Java 키 객체가 `RSAPublicKey.getModulus()` 를 지원할 때, (3)은 그것마저 안 될 때의 최후 수단.

## 검증 (세 경로 비교)
`LunaRsaKeyLifecycle.diagnosePublicKey(alias)` 가 세 경로를 모두 출력·비교한다.

실행:
```
./gradlew rsaLifecycle -Pslot=0 -Ppin=<PIN> -Plabel=<라벨>
```

기대 로그:
- **10.7+** (정상 환경, 실측):
  ```
  [1 raw   ] cert.getPublicKey()     : 294 bytes
  [2 robust] modulus/exponent 재구성 : 294 bytes
  [3 token ] CKA_MODULUS 직접 읽기   : 294 bytes
  [result  ] 1=OK 2=OK 3=OK | 일치: 1=true 2=true 3=true
  ```
- **10.5** (예상): `[1 raw] null ← 실패`, `[2]`·`[3]` 은 `294 bytes OK` → 재구성으로 해결됨을 확인.

## 근거 (어디까지가 사실이고 어디부터가 추정인가)

### ✅ 공식 문서로 입증되는 사실
1. **JCE 계약**: `Key.getEncoded()` 는 "키가 인코딩을 지원하지 않으면 **null 반환**"이 정상 동작.
   - Oracle Java SE API: *"Returns the key in its primary encoding format, or null if this key does not support encoding."*
   - 즉 null 이 와도 규약 위반이 아님.
2. **HSM 백업 키가 getEncoded()=null 을 반환하는 것은 HSM JCE provider 공통의 알려진 동작**.
   - AWS CloudHSM 공식 문서: HSM 키는 extraction 이 기본 비활성이라 `getEncoded()` 가 null 을 반환한다고 명시.
   - → Luna 만의 버그가 아니라 "HSM-백업 키 + 비추출 정책"에서 보편적으로 나타나는 패턴.

### 🔎 내가 직접 실측한 사실 (LunaProvider 10.7, Windows)
- `cert.getPublicKey()` 의 실제 클래스 = **`LunaPublicKeyRsa`** (소프트웨어 키가 아니라 Luna 객체).
- 10.7 에서는 그 객체의 `getEncoded()` 가 294 bytes 를 정상 반환 → 세 경로 전부 동일.
- 즉 "공개키 객체가 Luna-백업 객체다"는 **확인됨**. (버전에 따라 인코딩 구현 여부가 갈림)

### ⚠ 추정 (확정 출처 없음)
- **"10.5 에서 null, 10.7+ 에서 정상"** 이라는 버전 경계는 **고객 보고 + 위 실측의 조합으로 추론**한 것이며,
  Thales 공식 문서에서 "버전 X부터 getEncoded 구현"이라고 못박은 출처는 확인하지 못함.
- 10.5 가 내부적으로 "토큰 핸들만 들고 인코딩 미구현"인지는 합리적 추정이지 디컴파일로 확인한 사실은 아님.

### 🎯 확정 증거를 얻는 방법
고객 환경(10.5)에서 `diagnosePublicKey()` 를 돌리면 **그 환경에 대한 직접 증거**가 나온다:
- `[1 raw] null` 이면 → 구버전이 실제로 null 을 반환함이 입증됨
- `[2]/[3]` 이 OK 면 → 재구성 우회가 유효함이 입증됨

즉 "왜"의 일반 원리는 문서로, "이 고객 버전에서 실제로 그런지"는 진단 출력으로 확정한다.

## 비고
- 개인키는 어차피 토큰 밖으로 안 나오므로 이 이슈와 무관(공개키 전용).
- CKA_MODULUS=0x120, CKA_PUBLIC_EXPONENT=0x122 (PKCS#11 공개 속성).

## 출처
- Oracle Java SE — `java.security.Key.getEncoded()` (null 허용 계약)
- AWS CloudHSM 문서 — JCE `getEncoded()` 가 HSM 키에서 null 반환 (HSM 공통 동작 사례)
