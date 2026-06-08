import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, time, datetime, json, base64, os

import PyKCS11
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

LIB_PATH  = r"C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
MECHANISM = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)

KEY_CLASS = {PyKCS11.CKO_PUBLIC_KEY: "공개키", PyKCS11.CKO_PRIVATE_KEY: "개인키", PyKCS11.CKO_SECRET_KEY: "대칭키"}
KEY_TYPE  = {0: "RSA", 1: "DSA", 2: "DH", 3: "EC", 16: "AES", 18: "DES3"}

BG     = "#0f172a"
PANEL  = "#1e293b"
BORDER = "#334155"
ACCENT = "#38bdf8"

GREEN  = "#34d399"
RED    = "#f87171"
YELLOW = "#fbbf24"
TEXT   = "#e2e8f0"
MUTED  = "#64748b"
INPUT  = "#0f172a"


def styled_btn(parent, text, cmd, fg=ACCENT):
    b = tk.Button(parent, text=text, command=cmd, bg=PANEL, fg=fg,
                  activebackground=BORDER, activeforeground=fg,
                  relief="flat", bd=0, padx=10, pady=5,
                  font=("Segoe UI", 9, "bold"), cursor="hand2")
    b.bind("<Enter>", lambda e: b.config(bg=BORDER))
    b.bind("<Leave>", lambda e: b.config(bg=PANEL))
    return b


def section_label(parent, text):
    tk.Label(parent, text=text, bg=PANEL, fg=ACCENT,
             font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(10, 4))


def divider(parent):
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=8, pady=6)


class HsmGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HSM Sign/Verify Monitor")
        self.configure(bg=BG)
        self.minsize(860, 600)
        self.geometry("1000x680")

        self.pkcs11 = None
        self.session = None
        self.sw_pubkey = None
        self.priv_handle = None
        self.running = False
        self.stats = {"total": 0, "pass": 0, "fail": 0, "start": None}
        self.records = []
        self._sign_times = []
        self._verify_times = []

        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── 레이아웃 ────────────────────────────────
    def _build(self):
        # 상단 바
        top = tk.Frame(self, bg="#0a0f1e")
        top.pack(fill="x")
        tk.Label(top, text="  HSM Sign/Verify Monitor", bg="#0a0f1e",
                 fg=ACCENT, font=("Segoe UI", 13, "bold")).pack(side="left", pady=10)
        self.lbl_conn = tk.Label(top, text="● 미연결", bg="#0a0f1e",
                                 fg=RED, font=("Segoe UI", 9))
        self.lbl_conn.pack(side="right", padx=14)
        tk.Frame(self, bg=ACCENT, height=1).pack(fill="x")

        # 중간 영역 (좌패널 + 우패널)
        mid = tk.Frame(self, bg=BG)
        mid.pack(fill="both", expand=True, padx=10, pady=8)

        self._build_left(mid)
        self._build_right(mid)

        # 로그 영역
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=10)
        self._build_log()

    # ── 좌측 패널 ───────────────────────────────
    def _build_left(self, parent):
        left = tk.Frame(parent, bg=PANEL, width=210,
                        highlightbackground=BORDER, highlightthickness=1)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        section_label(left, "HSM 연결")

        def row(lbl, var, show=None, width=13):
            f = tk.Frame(left, bg=PANEL)
            f.pack(fill="x", padx=12, pady=2)
            tk.Label(f, text=lbl, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9), width=5, anchor="w").pack(side="left")
            e = tk.Entry(f, textvariable=var, show=show, width=width,
                         bg=INPUT, fg=TEXT, insertbackground=TEXT,
                         relief="flat", bd=3, font=("Segoe UI", 9))
            e.pack(side="right")
            return e

        self.v_slot = tk.StringVar(value="0")
        self.v_pin  = tk.StringVar()
        row("Slot", self.v_slot, width=5)
        row("PIN",  self.v_pin,  show="*")

        tk.Frame(left, bg=BORDER, height=1).pack(fill="x", padx=8, pady=6)
        self.btn_conn = styled_btn(left, "연결 / 키 조회", self._connect)
        self.btn_conn.pack(fill="x", padx=12, pady=2)

        divider(left)
        section_label(left, "자동화 설정")

        # 속도 슬라이더
        f = tk.Frame(left, bg=PANEL)
        f.pack(fill="x", padx=12, pady=(0, 2))
        tk.Label(f, text="속도 (회/초)", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left")
        self.v_rate = tk.DoubleVar(value=1.0)
        self.lbl_rate = tk.Label(left, text="1.0/s  |  간격 1000ms",
                                 bg=PANEL, fg=TEXT, font=("Segoe UI", 8))
        self.lbl_rate.pack(anchor="w", padx=14)
        tk.Scale(left, from_=0.1, to=10.0, resolution=0.1,
                 orient="horizontal", variable=self.v_rate,
                 bg=PANEL, fg=TEXT, troughcolor=BORDER,
                 highlightthickness=0, showvalue=False,
                 command=self._on_rate).pack(fill="x", padx=12, pady=2)

        # 서명 키 선택
        tk.Label(left, text="서명 키", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(4, 0))
        self.v_key = tk.StringVar(value="(연결 후 선택)")
        self.combo = ttk.Combobox(left, textvariable=self.v_key,
                                  state="readonly", font=("Segoe UI", 8))
        self.combo.pack(fill="x", padx=12, pady=2)

        divider(left)
        self.btn_start = styled_btn(left, "▶  시작", self._start, fg=GREEN)
        self.btn_start.pack(fill="x", padx=12, pady=2)
        self.btn_start.config(state="disabled")

        self.btn_stop = styled_btn(left, "■  중지", self._stop, fg=RED)
        self.btn_stop.pack(fill="x", padx=12, pady=2)
        self.btn_stop.config(state="disabled")

        divider(left)
        styled_btn(left, "결과 저장 (JSON)", self._save, fg=MUTED).pack(
            fill="x", padx=12, pady=2)

    # ── 우측 (키 테이블 + 통계) ─────────────────
    def _build_right(self, parent):
        right = tk.Frame(parent, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        # 키 테이블
        tbl_frame = tk.Frame(right, bg=PANEL,
                             highlightbackground=BORDER, highlightthickness=1)
        tbl_frame.pack(fill="both", expand=True, pady=(0, 6))

        tk.Label(tbl_frame, text="키 목록", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(8, 4))

        # Treeview 컨테이너 (pack 안에서 grid 사용하려면 전용 서브프레임)
        tv_wrap = tk.Frame(tbl_frame, bg=PANEL)
        tv_wrap.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=INPUT, foreground=TEXT,
                        fieldbackground=INPUT, rowheight=24,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=BORDER,
                        foreground=ACCENT, font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", BORDER)])

        cols = ("handle", "label", "type", "class", "bits")
        self.tree = ttk.Treeview(tv_wrap, columns=cols, show="headings", height=7)
        hdrs = [("handle","Handle",60), ("label","Label",230),
                ("type","유형",65), ("class","클래스",65), ("bits","크기",75)]
        for cid, htxt, w in hdrs:
            self.tree.heading(cid, text=htxt)
            self.tree.column(cid, width=w, anchor="w" if cid=="label" else "center")

        vsb = ttk.Scrollbar(tv_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        # tv_wrap 내부는 grid 단독
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tv_wrap.rowconfigure(0, weight=1)
        tv_wrap.columnconfigure(0, weight=1)

        self.tree.tag_configure("priv", foreground=YELLOW)
        self.tree.tag_configure("pub",  foreground=GREEN)
        self.tree.tag_configure("sym",  foreground=MUTED)

        # 통계 바
        stat_frame = tk.Frame(right, bg=PANEL,
                              highlightbackground=BORDER, highlightthickness=1)
        stat_frame.pack(fill="x")

        self.indicator = tk.Label(stat_frame, text="●", bg=PANEL,
                                  fg=BORDER, font=("Segoe UI", 20))
        self.indicator.pack(side="right", padx=12, pady=4)

        stats_row = tk.Frame(stat_frame, bg=PANEL)
        stats_row.pack(side="left", fill="x", expand=True)

        def stat(lbl, attr, color=TEXT):
            f = tk.Frame(stats_row, bg=PANEL)
            f.pack(side="left", padx=12, pady=6)
            tk.Label(f, text=lbl, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 8)).pack()
            v = tk.StringVar(value="0")
            setattr(self, attr, v)
            tk.Label(f, textvariable=v, bg=PANEL, fg=color,
                     font=("Segoe UI", 12, "bold")).pack()

        stat("총 실행",  "sv_total",   ACCENT)
        stat("PASS",    "sv_pass",    GREEN)
        stat("FAIL",    "sv_fail",    RED)
        stat("속도",    "sv_rate",    YELLOW)
        stat("서명(avg)","sv_sign",   TEXT)
        stat("검증(avg)","sv_verify", TEXT)
        stat("경과",    "sv_elapsed", MUTED)

    # ── 로그 ────────────────────────────────────
    def _build_log(self):
        log_outer = tk.Frame(self, bg=PANEL,
                             highlightbackground=BORDER, highlightthickness=1)
        log_outer.pack(fill="both", expand=True, padx=10, pady=(6, 10))

        # 헤더 (pack)
        hdr = tk.Frame(log_outer, bg=PANEL)
        hdr.pack(fill="x", padx=8, pady=(6, 2))
        tk.Label(hdr, text="실시간 로그", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        styled_btn(hdr, "지우기", self._clear_log, fg=MUTED).pack(side="right")

        # 텍스트 + 스크롤바 (전용 서브프레임, grid 단독)
        txt_frame = tk.Frame(log_outer, bg=PANEL)
        txt_frame.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        self.log = tk.Text(txt_frame, bg=INPUT, fg=TEXT,
                           font=("Consolas", 9), wrap="none",
                           relief="flat", state="disabled",
                           insertbackground=TEXT)
        vsb = ttk.Scrollbar(txt_frame, orient="vertical",   command=self.log.yview)
        hsb = ttk.Scrollbar(txt_frame, orient="horizontal", command=self.log.xview)
        self.log.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # txt_frame 내부는 grid 단독
        self.log.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        txt_frame.rowconfigure(0, weight=1)
        txt_frame.columnconfigure(0, weight=1)

        self.log.tag_configure("pass", foreground=GREEN)
        self.log.tag_configure("fail", foreground=RED)
        self.log.tag_configure("info", foreground=ACCENT)
        self.log.tag_configure("warn", foreground=YELLOW)
        self.log.tag_configure("dim",  foreground=MUTED)

    # ── 이벤트 ──────────────────────────────────
    def _on_rate(self, val):
        r  = float(val)
        ms = round(1000 / r)
        self.lbl_rate.config(text=f"{r:.1f}/s  |  간격 {ms}ms")

    def _log(self, msg, tag=""):
        def _do():
            self.log.config(state="normal")
            self.log.insert("end", msg + "\n", tag)
            self.log.see("end")
            self.log.config(state="disabled")
        self.after(0, _do)

    def _clear_log(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    # ── HSM 연결 ────────────────────────────────
    def _connect(self):
        threading.Thread(target=self._connect_worker, daemon=True).start()

    def _connect_worker(self):
        self.after(0, lambda: self.btn_conn.config(state="disabled", text="연결 중..."))
        try:
            slot = int(self.v_slot.get())
            pin  = self.v_pin.get()
            if not pin:
                messagebox.showwarning("오류", "PIN을 입력하세요.")
                return

            if self.session:
                try:
                    self.session.logout(); self.session.closeSession()
                except Exception: pass

            if not self.pkcs11:
                self.pkcs11 = PyKCS11.PyKCS11Lib()
                self.pkcs11.load(LIB_PATH)

            tok = str(self.pkcs11.getTokenInfo(slot).label).strip()
            self.session = self.pkcs11.openSession(
                slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
            self.session.login(pin)

            self.after(0, lambda: self.lbl_conn.config(
                text=f"● {tok}", fg=GREEN))
            self._log(f"[연결] Slot {slot} / 토큰: {tok}", "info")
            self._load_keys()

        except Exception as e:
            self._log(f"[오류] {e}", "fail")
            messagebox.showerror("연결 실패", str(e))
        finally:
            self.after(0, lambda: self.btn_conn.config(
                state="normal", text="연결 / 키 조회"))

    def _load_keys(self):
        self.after(0, lambda: [self.tree.delete(i)
                               for i in self.tree.get_children()])

        def ga(obj, attr_id):
            """속성 하나를 안전하게 읽기 → 실패 시 None"""
            try:
                return self.session.getAttributeValue(obj, [attr_id])[0]
            except Exception:
                return None

        def safe_int(v, default=0):
            if v is None: return default
            if isinstance(v, (list, tuple, bytes)):
                try: return int.from_bytes(bytes(v), "big")
                except: return default
            try: return int(v)
            except: return default

        def safe_str(v, default=""):
            if v is None: return default
            if isinstance(v, (list, tuple)):
                try: return bytes(v).decode("utf-8", errors="replace").strip()
                except: return default
            return str(v).strip()

        classes = [PyKCS11.CKO_PUBLIC_KEY,
                   PyKCS11.CKO_PRIVATE_KEY,
                   PyKCS11.CKO_SECRET_KEY]
        all_objs = []
        for c in classes:
            try:
                all_objs += self.session.findObjects([(PyKCS11.CKA_CLASS, c)])
            except Exception:
                pass

        priv_options = []
        self.key_map = {}

        for obj in all_objs:
            try:
                hdl   = obj.value()                          # 핸들 정수
                cls   = safe_int(ga(obj, PyKCS11.CKA_CLASS))
                ktype = safe_int(ga(obj, PyKCS11.CKA_KEY_TYPE))
                label = safe_str(ga(obj, PyKCS11.CKA_LABEL), default=f"(handle {hdl})")
                bits  = ga(obj, PyKCS11.CKA_MODULUS_BITS)   # RSA만 존재, EC는 None

                cls_s  = KEY_CLASS.get(cls,  str(cls))
                type_s = KEY_TYPE.get(ktype, str(ktype))
                bits_s = f"{safe_int(bits)} bit" if bits is not None else "N/A"
                tag    = ("priv" if cls == PyKCS11.CKO_PRIVATE_KEY
                          else "pub" if cls == PyKCS11.CKO_PUBLIC_KEY
                          else "sym")

                self.after(0, lambda h=hdl, lb=label, ts=type_s,
                                         cs=cls_s, bs=bits_s, tg=tag:
                    self.tree.insert("", "end",
                                     values=(h, lb, ts, cs, bs),
                                     tags=(tg,)))

                key_id = f"{hdl} | {label}"
                self.key_map[key_id] = obj
                if cls == PyKCS11.CKO_PRIVATE_KEY:
                    priv_options.append(key_id)

            except Exception as e:
                self._log(f"[경고] 키 읽기 실패 (handle {getattr(obj,'value',lambda:'-')()}): {e}", "warn")

        self._log(f"[키 조회] 총 {len(all_objs)}개", "info")

        if priv_options:
            self.after(0, lambda opts=priv_options: self._set_combo(opts))

    def _set_combo(self, opts):
        self.combo["values"] = opts
        self.combo.current(0)
        self.btn_start.config(state="normal")
        self._prep_keys()

    def _prep_keys(self):
        try:
            sel = self.v_key.get()
            obj = self.key_map.get(sel)
            if not obj:
                return

            self.priv_handle = obj
            priv_label = sel.split("|")[1].strip() if "|" in sel else ""
            pub_label  = priv_label.replace("Private", "Public")

            # 공개키 찾기 (라벨 매칭)
            pub_objs = self.session.findObjects(
                [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])
            self.pub_handle  = None
            self.sw_pubkey   = None

            for o in pub_objs:
                try:
                    lbl = self.session.getAttributeValue(o, [PyKCS11.CKA_LABEL])[0]
                    lbl = str(lbl).strip()
                    if lbl == pub_label:
                        self.pub_handle = o
                        break
                except Exception:
                    pass

            if not self.pub_handle and pub_objs:
                self.pub_handle = pub_objs[0]

            # RSA 공개키만 소프트웨어 검증 가능
            if self.pub_handle:
                ktype = self.session.getAttributeValue(
                    self.pub_handle, [PyKCS11.CKA_KEY_TYPE])[0]
                if ktype == 0:  # CKK_RSA
                    av = self.session.getAttributeValue(
                        self.pub_handle,
                        [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT])
                    n = int.from_bytes(bytes(av[0]), "big")
                    e = int.from_bytes(bytes(av[1]), "big")
                    self.sw_pubkey = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
                    self._log(f"[키 준비] RSA 키 세팅 완료  (priv={self.priv_handle.value()}  pub={self.pub_handle.value()})", "info")
                else:
                    self._log("[경고] RSA 외 키는 소프트웨어 검증 미지원 (RSA 개인키를 선택하세요)", "warn")

        except Exception as ex:
            self._log(f"[경고] 키 준비 실패: {ex}", "warn")

    # ── 자동화 ──────────────────────────────────
    def _start(self):
        if not self.session:
            messagebox.showwarning("준비 안됨", "먼저 HSM에 연결하세요.")
            return
        self._prep_keys()
        if not self.priv_handle or not self.sw_pubkey:
            messagebox.showerror("오류", "키 준비 실패. 연결 후 다시 시도하세요.")
            return

        self.running = True
        self.stats   = {"total": 0, "pass": 0, "fail": 0, "start": time.time()}
        self.records  = []
        self._sign_times   = []
        self._verify_times = []

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._log("─" * 72, "dim")
        self._log("[시작] Sign/Verify 자동화", "info")

        threading.Thread(target=self._loop, daemon=True).start()
        self._blink()

    def _stop(self):
        self.running = False
        self.btn_stop.config(state="disabled")
        self.btn_start.config(state="normal")
        self._log("[중지] 자동화 중지", "warn")
        self.after(0, lambda: self.indicator.config(fg=BORDER))

    def _loop(self):
        seq = 1
        while self.running:
            t0       = time.perf_counter()
            rate     = self.v_rate.get()
            interval = 1.0 / rate

            ts   = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            data = (f"HSM Auto #{seq} | "
                    f"{datetime.datetime.now().isoformat(timespec='milliseconds')}").encode()

            ok = False; err = ""; sig = b""; t_sign = 0.0; t_verify = 0.0
            try:
                t1      = time.perf_counter()
                sig_raw = self.session.sign(self.priv_handle, list(data), MECHANISM)
                t_sign  = (time.perf_counter() - t1) * 1000
                sig     = bytes(sig_raw)

                t2 = time.perf_counter()
                self.sw_pubkey.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
                t_verify = (time.perf_counter() - t2) * 1000
                ok = True

            except InvalidSignature as e:
                err = f"검증 실패: {e}"
            except Exception as e:
                err = f"오류: {e}"

            self.stats["total"] += 1
            if ok:
                self.stats["pass"] += 1
                self._sign_times.append(t_sign)
                self._verify_times.append(t_verify)
            else:
                self.stats["fail"] += 1

            elapsed = time.time() - self.stats["start"]
            a_rate  = self.stats["total"] / elapsed if elapsed > 0 else 0
            avg_s   = (sum(self._sign_times[-200:])   / len(self._sign_times[-200:])
                       if self._sign_times else 0)
            avg_v   = (sum(self._verify_times[-200:]) / len(self._verify_times[-200:])
                       if self._verify_times else 0)

            self.records.append({
                "seq": seq, "timestamp": ts,
                "sign_ms": round(t_sign, 2), "verify_ms": round(t_verify, 2),
                "pass": ok, "error": err,
                "sig_b64": base64.b64encode(sig).decode() if ok else "",
            })

            tag    = "pass" if ok else "fail"
            status = "PASS" if ok else f"FAIL  ({err})"
            h, rm  = divmod(int(elapsed), 3600)
            m, s   = divmod(rm, 60)

            self.after(0, self._upd_stats,
                       a_rate, avg_s, avg_v, f"{h:02d}:{m:02d}:{s:02d}")
            self.after(0, self._upd_log,
                       ts, seq, status, t_sign, t_verify, a_rate, tag,
                       data, sig)

            seq += 1
            spent = time.perf_counter() - t0
            rem   = interval - spent
            if rem > 0:
                time.sleep(rem)

        self.after(0, lambda: self.btn_stop.config(state="disabled"))
        self.after(0, lambda: self.btn_start.config(state="normal"))

    def _upd_stats(self, rate, avg_s, avg_v, elapsed):
        self.sv_total.set(str(self.stats["total"]))
        self.sv_pass.set(str(self.stats["pass"]))
        self.sv_fail.set(str(self.stats["fail"]))
        self.sv_rate.set(f"{rate:.2f}/s")
        self.sv_sign.set(f"{avg_s:.1f}ms")
        self.sv_verify.set(f"{avg_v:.1f}ms")
        self.sv_elapsed.set(elapsed)

    def _upd_log(self, ts, seq, status, t_sign, t_verify, rate, tag,
                 data: bytes = b"", sig: bytes = b""):
        import hashlib
        n = 6
        # Input  : 평문 앞 n자
        inp  = data.decode(errors="replace")[:n] + ".."
        # 서명값 : 서명 hex 앞 n자
        sv   = (sig.hex()[:n] + "..") if sig else "------"
        # 검증값 : SHA-256(data) hex 앞 n자  ← 실제 서명 대상 해시
        vv   = (hashlib.sha256(data).hexdigest()[:n] + "..") if data else "------"

        msg = (f"[{ts}] #{seq:>5} | {status:<6} | "
               f"In:{inp:<8} | 서명:{sv:<8} | 검증:{vv:<8} | "
               f"sign={t_sign:6.1f}ms  vrfy={t_verify:5.1f}ms | "
               f"{rate:.2f}/s")
        self._log(msg, tag)

    def _blink(self):
        if not self.running:
            return
        cur = self.indicator.cget("fg")
        self.indicator.config(fg=GREEN if cur != GREEN else BORDER)
        self.after(500, self._blink)

    # ── 저장 ────────────────────────────────────
    def _save(self):
        if not self.records:
            messagebox.showinfo("저장", "데이터가 없습니다.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            initialfile=f"hsm_{datetime.datetime.now():%Y%m%d_%H%M%S}.json")
        if not path:
            return
        elapsed = (time.time() - self.stats["start"]
                   if self.stats["start"] else 0)
        out = {
            "saved_at": datetime.datetime.now().isoformat(),
            "run": {**self.stats, "elapsed_sec": round(elapsed, 2)},
            "records": self.records,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        self._log(f"[저장] {path}", "info")
        messagebox.showinfo("저장 완료", path)

    def _on_close(self):
        self.running = False
        if self.session:
            try:
                self.session.logout()
                self.session.closeSession()
            except Exception: pass
        self.destroy()


if __name__ == "__main__":
    HsmGui().mainloop()
