import streamlit as st
import sqlite3
import base64, unicodedata, re, os, hmac, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DB_PATH = 'regForm.db'
IV_LEN = 16  # AES block size for CBC

# Encrypted columns (TEXT base64(iv+ct))
COLUMNS = ["NAME","EMPLOYEEID","DESIGNATION","EMAIL","PHONENUM",
           "AADHARNUM","IFSC","BANKNAME","BANKACCNUM","BRANCHLOC"]

DISPLAY_LABELS = [
    "Name",
    "Employee ID",
    "Designation",
    "Email",
    "Phone Number",
    "Aadhar",
    "IFSC Code",
    "Name of Bank",
    "Account Number",
    "Location of Branch",
]

def _canon(s: str) -> str:
    return unicodedata.normalize("NFKC", (s or "")).strip()

def canon_empid(s: str) -> str:
    return _canon(s).upper()

def decrypt_field(enc_b64: str, key: bytes) -> str:
    raw = base64.b64decode(enc_b64)
    iv, ct = raw[:IV_LEN], raw[IV_LEN:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def _pepper_bytes() -> bytes:
    pep = os.environ.get("REG_PEP", "") or st.secrets.get("REG_PEP", "")
    if not pep:
        raise RuntimeError("Server-side secret pepper REG_PEP not set on this server.")
    try:
        return base64.b64decode(pep)
    except Exception:
        return pep.encode("utf-8")

def hmac_tag(canonical_value: str) -> bytes:
    return hmac.new(_pepper_bytes(), canonical_value.encode("utf-8"), hashlib.sha256).digest()

def fetch_row_by_empid_tag(empid_plain: str):
    emp_tag = hmac_tag(canon_empid(empid_plain))
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cur = conn.cursor()
        # Use the deterministic tag for fast lookup
        cur.execute("""
            SELECT rowid, NAME,EMPLOYEEID,DESIGNATION,EMAIL,PHONENUM,
                   AADHARNUM,IFSC,BANKNAME,BANKACCNUM,BRANCHLOC
            FROM registrations
            WHERE EMPLOYEEID_TAG=? LIMIT 1
        """, (emp_tag,))
        return cur.fetchone()

def main():
    st.title("View details:")
    st.caption("Enter Employee ID and key.")

    with st.form("decrypt_form"):
        emp_id_input = st.text_input("Employee ID")
        key_b64 = st.text_input("Key", type="password")
        submit = st.form_submit_button("Display Data")

    if submit:
        emp = canon_empid(emp_id_input)
        key_in = _canon(key_b64)

        if not emp or not key_in:
            st.error("Please provide both Employee ID and Key.")
            return

        try:
            key_bytes = base64.b64decode(key_in)
            if len(key_bytes) not in (16, 24, 32):
                st.warning("Enter the exact key.")
                return
        except Exception:
            st.error("Invalid Base64 key.")
            return

        try:
            row = fetch_row_by_empid_tag(emp)
        except RuntimeError as e:
            st.error(str(e))
            return

        if not row:
            st.error("No matching record found for this Employee ID.")
            return

        rowid = row[0]
        enc = dict(zip(COLUMNS, row[1:]))

        try:
            dec = {col: decrypt_field(enc[col], key_bytes) for col in COLUMNS}
        except Exception as e:
            st.error(f"Decryption failed. Wrong key or corrupted data.\nDetails: {e}")
            return

        st.success(f"Record found")
        st.text("Employee details:")
        for col, label in zip(COLUMNS, DISPLAY_LABELS):
            st.text(f"{label}: {dec[col]}")

if __name__ == "__main__":
    main()
