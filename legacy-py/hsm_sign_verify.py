"""
HSM RSA Sign/Verify 테스트
- Luna HSM에서 RSA-2048 키쌍으로 서명 수행
- HSM 공개키를 추출해 소프트웨어(cryptography 라이브러리)로 검증
- 결과를 hsm_result.json에 저장
"""
import PyKCS11
import datetime
import json
import hashlib
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ── 설정 ────────────────────────────────────────
LIB_PATH    = r"C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
SLOT        = 0
PIN         = "12341234"
PRIV_LABEL  = "Generated RSA Private Key"
PUB_LABEL   = "Generated RSA Public Key"
TEST_DATA   = b"HSM Sign/Verify Test | " + datetime.datetime.now().isoformat().encode()
OUTPUT_FILE = r"C:\Users\Park\Desktop\claude_pro\hsm_result.json"
MECHANISM   = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)


def find_key(session, label, key_class):
    objs = session.findObjects([(PyKCS11.CKA_CLASS, key_class), (PyKCS11.CKA_LABEL, label)])
    if not objs:
        raise RuntimeError(f"키를 찾을 수 없음: {label!r}")
    return objs[0]


def extract_rsa_public_key(session, pub_handle):
    """HSM 공개키에서 Modulus + Exponent 추출 → cryptography RSA 공개키 반환"""
    attrs = session.getAttributeValue(pub_handle, [
        PyKCS11.CKA_MODULUS,
        PyKCS11.CKA_PUBLIC_EXPONENT,
    ])
    modulus  = int.from_bytes(bytes(attrs[0]), "big")
    exponent = int.from_bytes(bytes(attrs[1]), "big")
    pub_key  = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
    return pub_key, modulus, exponent


def get_key_info(session, handle, label, key_class):
    """키 기본 정보 반환 (handle 제외)"""
    attrs_to_read = [PyKCS11.CKA_MODULUS_BITS]
    if key_class == PyKCS11.CKO_PUBLIC_KEY:
        attrs_to_read += [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT]
    try:
        vals = session.getAttributeValue(handle, attrs_to_read)
        modulus_bits = vals[0] if isinstance(vals[0], int) else int.from_bytes(bytes(vals[0]), "big")
        return {"label": label, "key_bits": modulus_bits}
    except Exception:
        return {"label": label, "key_bits": "?"}


def run():
    print("=" * 60)
    print("  HSM RSA Sign/Verify 테스트")
    print("=" * 60)

    # 1. 라이브러리 로드
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(LIB_PATH)
    print(f"[OK] 라이브러리 로드")

    # 2. 토큰 정보
    slots = pkcs11.getSlotList(tokenPresent=True)
    token_label = str(pkcs11.getTokenInfo(SLOT).label).strip()
    print(f"[OK] 슬롯: {slots}  토큰: {token_label}")

    # 3. 세션 + 로그인
    session = pkcs11.openSession(SLOT, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    session.login(PIN)
    print(f"[OK] 로그인 완료 (Slot {SLOT})")

    # 4. 키 검색
    priv_handle = find_key(session, PRIV_LABEL, PyKCS11.CKO_PRIVATE_KEY)
    pub_handle  = find_key(session, PUB_LABEL,  PyKCS11.CKO_PUBLIC_KEY)
    priv_info   = get_key_info(session, priv_handle, PRIV_LABEL, PyKCS11.CKO_PRIVATE_KEY)
    pub_info    = get_key_info(session, pub_handle,  PUB_LABEL,  PyKCS11.CKO_PUBLIC_KEY)
    print(f"[OK] Private Key: {priv_info}")
    print(f"[OK] Public  Key: {pub_info}")

    # 5. HSM 공개키 추출 (소프트웨어 검증용)
    sw_pubkey, modulus, exponent = extract_rsa_public_key(session, pub_handle)
    pub_pem = sw_pubkey.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    print(f"[OK] 공개키 추출 완료 (N={str(modulus)[:20]}...)")

    # 6. HSM 서명
    print(f"\n[서명] 데이터: {TEST_DATA.decode()}")
    sig_raw   = session.sign(priv_handle, list(TEST_DATA), MECHANISM)
    signature = bytes(sig_raw)
    sig_hex   = signature.hex()
    sig_b64   = base64.b64encode(signature).decode()
    print(f"[OK] 서명 완료: {len(signature)} bytes")
    print(f"     HEX(앞32): {sig_hex[:64]}...")

    # 7. 소프트웨어 검증 — 원본 데이터 + 올바른 서명
    verify_ok  = False
    verify_msg = ""
    try:
        sw_pubkey.verify(
            signature,
            TEST_DATA,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        verify_ok  = True
        verify_msg = "서명 검증 성공 (VALID)"
        print(f"[OK] {verify_msg}")
    except InvalidSignature as e:
        verify_msg = f"서명 검증 실패: {e}"
        print(f"[FAIL] {verify_msg}")

    # 8. 소프트웨어 검증 — 변조된 서명 거부 확인
    tamper_ok  = False
    tamper_msg = ""
    bad_sig = bytearray(signature)
    bad_sig[0] ^= 0xFF
    bad_sig[len(bad_sig) // 2] ^= 0xFF
    try:
        sw_pubkey.verify(
            bytes(bad_sig),
            TEST_DATA,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        tamper_msg = "변조 서명이 통과됨 (비정상!)"
        print(f"[WARN] {tamper_msg}")
    except InvalidSignature:
        tamper_ok  = True
        tamper_msg = "변조 서명 정상 거부 (INVALID)"
        print(f"[OK] {tamper_msg}")

    # 9. 세션 종료
    session.logout()
    session.closeSession()

    # 10. 결과 저장
    result = {
        "timestamp":         datetime.datetime.now().isoformat(),
        "token_label":       token_label,
        "slot":              SLOT,
        "mechanism":         "CKM_SHA256_RSA_PKCS (RSA-2048 + SHA-256 + PKCS#1 v1.5)",
        "test_data":         TEST_DATA.decode(),
        "test_data_sha256":  hashlib.sha256(TEST_DATA).hexdigest(),
        "private_key":       priv_info,
        "public_key":        {**pub_info, "pem": pub_pem},
        "signature": {
            "length_bytes": len(signature),
            "hex":          sig_hex,
            "base64":       sig_b64,
        },
        "verification": {
            "method":                    "software (cryptography library)",
            "original_data_valid":       verify_ok,
            "original_msg":              verify_msg,
            "tampered_sig_rejected":     tamper_ok,
            "tampered_msg":              tamper_msg,
        },
        "overall_pass": verify_ok and tamper_ok,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    status = "PASS" if result["overall_pass"] else "FAIL"
    print(f"  최종 결과: {status}")
    print(f"  저장 위치: {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    run()
