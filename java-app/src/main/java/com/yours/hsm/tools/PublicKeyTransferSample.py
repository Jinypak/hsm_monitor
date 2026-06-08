"""
ML-DSA 공개키 이전 샘플 (PyKCS11)
slot 0 에서 공개키를 추출(export) 하고 slot 1 에 주입(import) 한다.
"""
import PyKCS11
import pathlib
import struct

# ── 상수 ───────────────────────────────────────────────────
PIN              = "userpin"
SRC_LABEL        = "slot0_mldsa65_pub-alias"    # slot 0 공개키 라벨
DST_LABEL        = "slot1_mldsa65_pub-alias"    # slot 1 저장 라벨
PUB_FILE         = pathlib.Path("C:/Program Files/SafeNet/LunaClient/pub.bin")

CKK_ML_DSA              = 0x4a         # Luna ML-DSA key type
CKA_VALUE               = 0x00000011  # 공개키 원시 바이트
LUNA_CKA_MLDSA_PARAMSET = 0x0000061D  # Luna ML-DSA 파라미터셋 (ML-DSA-65 = 2)

# ── PKCS#11 라이브러리 로드 ────────────────────────────────
p = PyKCS11.PyKCS11Lib()
p.load("C:/Program Files/SafeNet/LunaClient/cryptoki.dll")

# ── Export: slot 0 공개키 → 파일 ──────────────────────────
s0 = p.openSession(0, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
s0.login(PIN)

objs = s0.findObjects([
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
    (PyKCS11.CKA_LABEL, SRC_LABEL),
])
pub_bytes = bytes(s0.getAttributeValue(objs[0], [CKA_VALUE])[0])  # 1952 bytes
PUB_FILE.write_bytes(pub_bytes)

s0.logout()
s0.closeSession()

# ── Import: 파일 → slot 1 토큰 ────────────────────────────
s1 = p.openSession(1, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
s1.login(PIN)

template = [
    (PyKCS11.CKA_CLASS,           PyKCS11.CKO_PUBLIC_KEY),
    (PyKCS11.CKA_KEY_TYPE,        CKK_ML_DSA),
    (PyKCS11.CKA_TOKEN,           True),
    (PyKCS11.CKA_PRIVATE,         False),
    (PyKCS11.CKA_VERIFY,          True),
    (PyKCS11.CKA_LABEL,           DST_LABEL),
    (LUNA_CKA_MLDSA_PARAMSET,     list(struct.pack("<I", 2))),  # ML-DSA-65 = 2
    (CKA_VALUE,                   list(PUB_FILE.read_bytes())),
]
s1.createObject(template)

s1.logout()
s1.closeSession()
