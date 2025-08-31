import streamlit as st
import sqlite3
import os, base64, re, unicodedata, hmac, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

DB_PATH = 'regForm.db'

# Fresh-table schema (new deployments get full constraints)
TABLE_DDL_FRESH = """
CREATE TABLE IF NOT EXISTS registrations(
    NAME        TEXT NOT NULL CHECK (length(NAME)        > 0),
    EMPLOYEEID  TEXT NOT NULL CHECK (length(EMPLOYEEID)  > 0),
    DESIGNATION TEXT NOT NULL CHECK (length(DESIGNATION) > 0),
    EMAIL       TEXT NOT NULL CHECK (length(EMAIL)       > 0),
    PHONENUM    TEXT NOT NULL CHECK (length(PHONENUM)    > 0),
    AADHARNUM   TEXT NOT NULL CHECK (length(AADHARNUM)   > 0),
    IFSC        TEXT NOT NULL CHECK (length(IFSC)        > 0),
    BANKNAME    TEXT NOT NULL CHECK (length(BANKNAME)    > 0),
    BANKACCNUM  TEXT NOT NULL CHECK (length(BANKACCNUM)  > 0),
    BRANCHLOC   TEXT NOT NULL CHECK (length(BRANCHLOC)   > 0),

    -- Deterministic privacy-preserving tags for uniqueness / lookup
    EMPLOYEEID_TAG  BLOB NOT NULL UNIQUE,
    PHONENUM_TAG    BLOB NOT NULL UNIQUE,
    AADHARNUM_TAG   BLOB NOT NULL UNIQUE,
    IFSC_ACC_TAG    BLOB NOT NULL UNIQUE
);
"""

AES_KEY_LEN = 32   # 256-bit
IV_LEN = 16        # AES block size

# ---------------- Canonicalization & Validation ----------------
def _canon(s: str) -> str:
    return unicodedata.normalize("NFKC", (s or "")).strip()

def canon_name(s: str) -> str:
    return _canon(s)

def canon_empid(s: str) -> str:
    return _canon(s).upper()

def canon_designation(s: str) -> str:
    return _canon(s)

def canon_email(s: str) -> str:
    return _canon(s).lower()

def canon_phone(s: str) -> str:
    # digits only; adjust if you prefer E.164
    return re.sub(r"\D", "", _canon(s))

def canon_aadhar(s: str) -> str:
    return re.sub(r"\D", "", _canon(s))

def canon_ifsc(s: str) -> str:
    return _canon(s).upper()

def canon_bankname(s: str) -> str:
    return _canon(s)

def canon_bankacc(s: str) -> str:
    return re.sub(r"\D", "", _canon(s))

def canon_branchloc(s: str) -> str:
    return _canon(s)

def validate_fields(d):
    errs = []

    def _len_ok(v, n, label):
        if len(v) == 0:
            errs.append(f"{label}: cannot be empty.")
        elif len(v) > n:
            errs.append(f"{label}: too long (>{n} chars).")

    def _match(v, pat, label, msg="invalid format"):
        if v and not re.fullmatch(pat, v):
            errs.append(f"{label}: {msg}.")

    _len_ok(d["name"],        80,  "Name")
    _len_ok(d["employeeId"],  20,  "Employee ID")
    _len_ok(d["designation"], 80,  "Designation")
    _len_ok(d["email"],       254, "Email")
    _len_ok(d["phoneNum"],    13,  "Phone Number")
    _len_ok(d["aadharNum"],   12,  "Aadhar")
    _len_ok(d["ifsc"],        11,  "IFSC Code")
    _len_ok(d["bankName"],    80,  "Name of Bank")
    _len_ok(d["bankAccNum"],  18,  "Account Number")
    _len_ok(d["branchLoc"],   120, "Location of Branch")

    _match(d["email"],     r"[^@\s]+@[^@\s]+\.[^@\s]+", "Email")
    _match(d["phoneNum"],  r"\d{10,13}", "Phone Number")
    _match(d["aadharNum"], r"\d{12}",    "Aadhar")
    _match(d["ifsc"],      r"[A-Z]{4}0[A-Z0-9]{6}", "IFSC Code")
    _match(d["bankAccNum"],r"\d{9,18}",  "Account Number")

    return (len(errs) == 0, errs)

# ---------------- HMAC tag (privacy-preserving unique keys) ----------------
def _pepper_bytes() -> bytes:
    pep = os.environ.get("REG_PEP", "") or st.secrets.get("REG_PEP", "")
    if not pep:
        raise RuntimeError(
            "Server-side secret pepper REG_PEP not set. "
            "Set REG_PEP to a strong random string (e.g., 32+ bytes base64)."
        )
    try:
        # allow either raw string or base64-encoded secret
        return base64.b64decode(pep)
    except Exception:
        return pep.encode("utf-8")

def hmac_tag(canonical_value: str) -> bytes:
    return hmac.new(_pepper_bytes(), canonical_value.encode("utf-8"), hashlib.sha256).digest()

# ---------------- Crypto ----------------
def encrypt_field(plaintext: str, key: bytes) -> str:
    pt = (plaintext or "").encode("utf-8")
    iv = os.urandom(IV_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(pt, AES.block_size))
    return base64.b64encode(iv + ct).decode("utf-8")

# ---------------- DB ----------------
def _set_pragmas(conn: sqlite3.Connection):
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")

def _table_has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    cur = conn.execute(f"PRAGMA table_info({table});")
    return any(r[1] == col for r in cur.fetchall())

def init_db():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        _set_pragmas(conn)
        # Try to create fresh schema (no-op if table exists already)
        conn.execute(TABLE_DDL_FRESH)
        conn.commit()

        # If this is an older table, ensure tag columns & unique indexes exist
        needs_alter = False
        for col in ("EMPLOYEEID_TAG", "PHONENUM_TAG", "AADHARNUM_TAG", "IFSC_ACC_TAG"):
            if not _table_has_column(conn, "registrations", col):
                conn.execute(f"ALTER TABLE registrations ADD COLUMN {col} BLOB;")
                needs_alter = True

        if needs_alter:
            conn.commit()

        # Create unique indexes (idempotent)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_empid_tag  ON registrations(EMPLOYEEID_TAG);")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_phone_tag   ON registrations(PHONENUM_TAG);")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_aadhar_tag  ON registrations(AADHARNUM_TAG);")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_ifscacc_tag ON registrations(IFSC_ACC_TAG);")
        conn.commit()

def add_encrypted_row(enc_values_tuple, tags_tuple):
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        _set_pragmas(conn)
        # Insert 14 columns: 10 encrypted TEXT + 4 BLOB tags
        sql = """
        INSERT INTO registrations
        (NAME,EMPLOYEEID,DESIGNATION,EMAIL,PHONENUM,AADHARNUM,IFSC,BANKNAME,BANKACCNUM,BRANCHLOC,
         EMPLOYEEID_TAG,PHONENUM_TAG,AADHARNUM_TAG,IFSC_ACC_TAG)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        try:
            conn.execute(sql, enc_values_tuple + tags_tuple)
            conn.commit()
        except sqlite3.IntegrityError as e:
            # Unique violation → duplicate field
            raise ValueError(
                "Duplicate detected for one of: Employee ID, Phone Number, Aadhar, or IFSC+Account."
            ) from e

# ---------------- UI ----------------
def formCreation():
    st.title("Registration Form:")
    st.caption("A 256-bit key is generated and shown once. Make sure you copy and save it.")

    with st.form(key="Registration Form"):
        name        = st.text_input("Full name (as per Aadhar)")
        employeeId  = st.text_input("Employee ID")
        designation = st.text_input("Designation")
        email       = st.text_input("Email")
        phoneNum    = st.text_input("Phone number")
        aadharNum   = st.text_input("Aadhar number")
        ifsc        = st.text_input("IFSC code")
        bankName    = st.text_input("Bank name")
        bankAccNum  = st.text_input("Bank account number")
        branchLoc   = st.text_input("Branch location")
        submit      = st.form_submit_button(label='Register (Encrypt & Store)')

    if submit:
        # Canonicalize
        data = {
            "name":        canon_name(name),
            "employeeId":  canon_empid(employeeId),
            "designation": canon_designation(designation),
            "email":       canon_email(email),
            "phoneNum":    canon_phone(phoneNum),
            "aadharNum":   canon_aadhar(aadharNum),
            "ifsc":        canon_ifsc(ifsc),
            "bankName":    canon_bankname(bankName),
            "bankAccNum":  canon_bankacc(bankAccNum),
            "branchLoc":   canon_branchloc(branchLoc),
        }

        # Validate non-empty + formats
        ok, errs = validate_fields(data)
        if not ok:
            for e in errs:
                st.error(e)
            return

        # Require server-side pepper for tags
        try:
            _ = _pepper_bytes()
        except RuntimeError as e:
            st.error(str(e))
            return

        # Generate unique tags (BLOB)
        emp_tag   = hmac_tag(data["employeeId"])
        phone_tag = hmac_tag(data["phoneNum"])
        aadh_tag  = hmac_tag(data["aadharNum"])
        ifsc_acc_tag = hmac_tag(f"{data['ifsc']}:{data['bankAccNum']}")

        # 256-bit random key (not stored)
        key = os.urandom(AES_KEY_LEN)
        key_b64 = base64.b64encode(key).decode('utf-8')

        # Encrypt each field (IV per field; prepend IV; base64)
        enc_values = tuple(
            encrypt_field(data[k], key) for k in
            ["name","employeeId","designation","email","phoneNum",
             "aadharNum","ifsc","bankName","bankAccNum","branchLoc"]
        )

        # Store encrypted values + tags
        try:
            add_encrypted_row(enc_values, (emp_tag, phone_tag, aadh_tag, ifsc_acc_tag))
        except ValueError as e:
            st.error(str(e))
            return

        st.success("Your data has been stored securely.")
        st.info("Save this key safely. It will not be shown again.")
        st.code(key_b64, language="text")

if __name__ == "__main__":
    init_db()
    formCreation()
