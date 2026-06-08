"""
HSM RSA Sign/Verify 자동화
사용법:
  python hsm_auto.py          # 기본 1회/초
  python hsm_auto.py --rate 5 # 5회/초
  python hsm_auto.py --rate 10 --output my_log.json
"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import PyKCS11
import argparse
import datetime
import json
import base64
import hashlib
import time
import os
import signal
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ── 고정 설정 ──────────────────────────────────
LIB_PATH   = r"C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
SLOT       = 0
PIN        = "12341234"
PRIV_LABEL = "Generated RSA Private Key"
PUB_LABEL  = "Generated RSA Public Key"
MECHANISM  = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)

# ── 전역 상태 ───────────────────────────────────
running   = True
stats     = {"total": 0, "pass": 0, "fail": 0, "start": None}

def handle_sigint(sig, frame):
    global running
    running = False

signal.signal(signal.SIGINT, handle_sigint)


def find_key(session, label, key_class):
    objs = session.findObjects([(PyKCS11.CKA_CLASS, key_class), (PyKCS11.CKA_LABEL, label)])
    if not objs:
        raise RuntimeError(f"키를 찾을 수 없음: {label!r}")
    return objs[0]


def extract_sw_pubkey(session, pub_handle):
    attrs = session.getAttributeValue(pub_handle, [
        PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT
    ])
    n = int.from_bytes(bytes(attrs[0]), "big")
    e = int.from_bytes(bytes(attrs[1]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def sign_verify_once(session, priv_handle, sw_pubkey, seq):
    """1회 Sign/Verify 수행 → 결과 dict 반환"""
    ts    = datetime.datetime.now().isoformat(timespec="milliseconds")
    data  = f"HSM Auto Test #{seq} | {ts}".encode()

    t0 = time.perf_counter()
    sig_raw   = session.sign(priv_handle, list(data), MECHANISM)
    t_sign    = time.perf_counter() - t0

    signature = bytes(sig_raw)
    ok        = False
    err_msg   = ""

    t1 = time.perf_counter()
    try:
        sw_pubkey.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        ok = True
    except InvalidSignature as e:
        err_msg = str(e)
    t_verify = time.perf_counter() - t1

    return {
        "seq":          seq,
        "timestamp":    ts,
        "data":         data.decode(),
        "data_sha256":  hashlib.sha256(data).hexdigest(),
        "sign_ms":      round(t_sign  * 1000, 2),
        "verify_ms":    round(t_verify * 1000, 2),
        "total_ms":     round((t_sign + t_verify) * 1000, 2),
        "signature_b64": base64.b64encode(signature).decode(),
        "pass":         ok,
        "error":        err_msg,
    }


def print_status(rec, rate):
    elapsed = time.time() - stats["start"]
    actual_rate = stats["total"] / elapsed if elapsed > 0 else 0
    status  = "PASS" if rec["pass"] else "FAIL"
    print(
        f"[{rec['timestamp']}] #{rec['seq']:>5} | {status} | "
        f"sign={rec['sign_ms']:6.1f}ms  verify={rec['verify_ms']:5.1f}ms | "
        f"rate={actual_rate:.2f}/s | PASS={stats['pass']} FAIL={stats['fail']}"
    )


def save_summary(output_file, records, rate, sw_pubkey):
    pem = sw_pubkey.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    elapsed = time.time() - stats["start"]
    avg_sign   = sum(r["sign_ms"]   for r in records) / len(records) if records else 0
    avg_verify = sum(r["verify_ms"] for r in records) / len(records) if records else 0
    summary = {
        "config": {
            "slot":       SLOT,
            "token":      "HA_test",
            "mechanism":  "CKM_SHA256_RSA_PKCS (RSA-2048 + SHA-256)",
            "target_rate": f"{rate}/s",
            "interval_ms": round(1000 / rate, 1),
        },
        "public_key_pem": pem,
        "run": {
            "start":       datetime.datetime.fromtimestamp(stats["start"]).isoformat(),
            "end":         datetime.datetime.now().isoformat(),
            "elapsed_sec": round(elapsed, 2),
            "total":       stats["total"],
            "pass":        stats["pass"],
            "fail":        stats["fail"],
            "actual_rate": round(stats["total"] / elapsed, 2) if elapsed > 0 else 0,
            "avg_sign_ms":   round(avg_sign, 2),
            "avg_verify_ms": round(avg_verify, 2),
        },
        "records": records,
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n결과 저장: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="HSM RSA Sign/Verify 자동화")
    parser.add_argument("--rate",   type=float, default=1.0,
                        help="초당 실행 횟수 (0.1~10, 기본 1)")
    parser.add_argument("--count",  type=int,   default=0,
                        help="총 실행 횟수 (0=무제한, 기본 0)")
    parser.add_argument("--output", type=str,   default="hsm_auto_result.json",
                        help="결과 저장 파일명")
    args = parser.parse_args()

    rate     = max(0.1, min(10.0, args.rate))
    interval = 1.0 / rate
    max_count = args.count  # 0 = 무제한

    print("=" * 70)
    print(f"  HSM RSA Sign/Verify 자동화  |  목표 속도: {rate}/초  |  간격: {interval*1000:.0f}ms")
    print(f"  종료: Ctrl+C")
    print("=" * 70)

    # HSM 연결
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(LIB_PATH)
    token_label = str(pkcs11.getTokenInfo(SLOT).label).strip()
    session = pkcs11.openSession(SLOT, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    session.login(PIN)
    print(f"[OK] 로그인 완료 / 토큰: {token_label}")

    priv_handle = find_key(session, PRIV_LABEL, PyKCS11.CKO_PRIVATE_KEY)
    pub_handle  = find_key(session, PUB_LABEL,  PyKCS11.CKO_PUBLIC_KEY)
    sw_pubkey   = extract_sw_pubkey(session, pub_handle)
    print(f"[OK] 키 로드 완료 / 시작합니다\n")

    records = []
    stats["start"] = time.time()
    seq = 1

    while running and (max_count == 0 or seq <= max_count):
        loop_start = time.perf_counter()

        try:
            rec = sign_verify_once(session, priv_handle, sw_pubkey, seq)
            records.append(rec)
            stats["total"] += 1
            if rec["pass"]:
                stats["pass"] += 1
            else:
                stats["fail"] += 1
            print_status(rec, rate)
        except Exception as e:
            stats["total"] += 1
            stats["fail"]  += 1
            print(f"[ERROR] #{seq} 오류: {e}")

        seq += 1

        # 인터벌 유지 (처리 시간 제외)
        elapsed = time.perf_counter() - loop_start
        sleep_t = interval - elapsed
        if sleep_t > 0:
            time.sleep(sleep_t)

    # 종료 처리
    print("\n[중지됨] 세션 종료 중...")
    session.logout()
    session.closeSession()

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.output)
    save_summary(output_path, records, rate, sw_pubkey)

    elapsed = time.time() - stats["start"]
    print(f"\n총 {stats['total']}회 | PASS {stats['pass']} / FAIL {stats['fail']} | "
          f"실제 속도 {stats['total']/elapsed:.2f}/s | 소요 {elapsed:.1f}초")


if __name__ == "__main__":
    main()
