# app.py
from flask import Flask, request, jsonify, redirect
import sqlite3
import os
import base64
import hashlib
import datetime
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from cryptography.fernet import Fernet
import re
import jwt

# -------------------------
# Configuration
# -------------------------
app = Flask(__name__)
# SECRET_KEY used for admin JWT signing. In production set a strong secret via env var.
app.config['SECRET_KEY'] = os.environ.get("APP_SECRET_KEY", "change-this-secret-in-prod")
DB_PATH = os.environ.get("DB_PATH", "regForm.db")

# Encryption key management:
# - You should set ENCRYPTION_KEY env var to a base64 urlsafe 32-byte key (Fernet key).
# - If absent, derive one deterministically from APP_SECRET_KEY (only OK for dev).
FERNET_KEY = os.environ.get("ENCRYPTION_KEY")
if FERNET_KEY:
    fernet_key = FERNET_KEY.encode()
else:
    # Derive a 32-byte key from SECRET_KEY using PBKDF2-HMAC-SHA256 (dev fallback)
    salt = b"static-salt-change-in-prod"
    dk = hashlib.pbkdf2_hmac("sha256", app.config['SECRET_KEY'].encode(), salt, 200000, dklen=32)
    fernet_key = base64.urlsafe_b64encode(dk)
fernet = Fernet(fernet_key)

# Argon2 password hasher
ph = PasswordHasher()

# Rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["100 per hour"])
limiter.init_app(app)

# -------------------------
# Utility helpers
# -------------------------
def db_connect():
    return sqlite3.connect(DB_PATH)

def encrypt_field(plaintext: str) -> str:
    if plaintext is None:
        return None
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt_field(token: str) -> str:
    if not token:
        return None
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        # Decryption failure — return None (but don't leak details)
        return None

def hash_for_lookup(value: str) -> str:
    """Deterministic digest for searching & uniqueness checks (lowercased)."""
    if value is None:
        return None
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, provided_password: str) -> bool:
    try:
        return ph.verify(stored_hash, provided_password)
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception:
        # Any other failure treat as verification failure
        return False

def is_strong_password(password: str) -> bool:
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$'
    return bool(re.match(pattern, password or ""))

def get_json_or_400():
    data = request.get_json(silent=True)
    if data is None:
        return None, (jsonify({"error": "Request body must be JSON"}), 400)
    return data, (None, None)

# Masking helpers (admins see masked PII)
def mask_email(email_plain: str):
    if not email_plain or "@" not in email_plain:
        return email_plain
    name, domain = email_plain.split("@", 1)
    if len(name) <= 1:
        return "*" + "@" + domain
    return name[0] + "*" * (len(name) - 1) + "@" + domain

def mask_phone(phone_plain: str):
    if not phone_plain or len(phone_plain) < 4:
        return phone_plain
    return "*" * (len(phone_plain) - 4) + phone_plain[-4:]

def mask_aadhar(aadhar_plain: str):
    if not aadhar_plain or len(aadhar_plain) < 4:
        return aadhar_plain
    return "****-****-" + aadhar_plain[-4:]

def mask_account_no(acct_plain: str):
    if not acct_plain or len(acct_plain) < 4:
        return acct_plain
    return "*" * (len(acct_plain) - 4) + acct_plain[-4:]
def teacher_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        parts = auth.split()
        token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else None
        if not token:
            return jsonify({"error": "Authorization header with Bearer token required"}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            teacher_id = payload.get("teacher_id")
            if not teacher_id:
                raise ValueError("Invalid token payload")
        except Exception:
            return jsonify({"error": "Token is invalid or expired"}), 401
        return f(teacher_id, *args, **kwargs)
    return decorated


# -------------------------
# DB initialization
# -------------------------
def init_db():
    conn = db_connect()
    c = conn.cursor()
    # teachers table stores encrypted PII fields and deterministic hashes for searching/uniqueness
    c.execute('''CREATE TABLE IF NOT EXISTS teachers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email_enc TEXT,
        email_hash TEXT UNIQUE,
        phone_enc TEXT,
        phone_hash TEXT UNIQUE,
        aadhar_enc TEXT,
        aadhar_hash TEXT UNIQUE,
        ifsc_enc TEXT,
        account_enc TEXT,
        account_hash TEXT UNIQUE,
        bank_name_enc TEXT,
        branch_enc TEXT,
        classes_taken INTEGER,
        designation TEXT,
        password_hash TEXT
    )''')
    # admin table
    c.execute('''CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT DEFAULT 'admin'
    )''')
    # admin audit logs
    c.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        performed_by TEXT,
        target TEXT,
        timestamp TEXT
    )''')
    # failed login attempts
    c.execute('''CREATE TABLE IF NOT EXISTS failed_logins (
        username TEXT PRIMARY KEY,
        attempts INTEGER,
        last_attempt TEXT
    )''')
    conn.commit()

    # Ensure a superadmin exists (development convenience). In production, create securely.
    c.execute("SELECT COUNT(*) FROM admin")
    total_admins = c.fetchone()[0]
    if total_admins == 0:
        # default superadmin: change immediately in prod
        default_user = "superadmin"
        default_pwd = os.environ.get("SUPERADMIN_PWD", "SuperAdmin123!")  # enforce to change in prod
        pwd_hash = hash_password(default_pwd)
        c.execute("INSERT INTO admin (username, password_hash, role) VALUES (?, ?, ?)",
                  (default_user, pwd_hash, "superadmin"))
        conn.commit()
    conn.close()

# -------------------------
# Validation Helpers
# -------------------------
def validate_teacher_fields(data):
    if "phone" in data and data["phone"] and len(data["phone"]) != 10:
        return "Phone number must be 10 digits"
    if "aadhar" in data and data["aadhar"] and len(data["aadhar"]) != 12:
        return "Aadhar number must be 12 digits"
    if "account_no" in data and data["account_no"] and not (10 <= len(data["account_no"]) <= 18):
        return "Account number must be 10–18 digits"
    if "ifsc" in data and data["ifsc"] and len(data["ifsc"]) != 11:
        return "IFSC code must be 11 characters"
    return None

# -------------------------
# JWT Admin Decorator
# -------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        parts = auth.split()
        token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else None
        if not token:
            return jsonify({"error": "Authorization header with Bearer token required"}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            admin_user = payload.get("username")
            if not admin_user:
                raise ValueError("invalid token payload")
        except Exception:
            return jsonify({"error": "Token is invalid or expired"}), 401
        return f(admin_user, *args, **kwargs)
    return decorated

# -------------------------
# Admin Routes
# -------------------------
@app.route("/api/admin/register", methods=["POST"])
@token_required
@limiter.limit("2 per hour")
def register_admin(current_admin):
    data, (err_resp, err_code) = get_json_or_400()
    if err_resp:
        return err_resp, err_code
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if not is_strong_password(password):
        return jsonify({"error": "Password must be 8+ chars, include uppercase, number, special char"}), 400
    try:
        conn = db_connect()
        c = conn.cursor()
        # Only superadmin may create admins
        c.execute("SELECT role FROM admin WHERE username=?", (current_admin,))
        row = c.fetchone()
        if not row or row[0] != "superadmin":
            conn.close()
            return jsonify({"error": "Only superadmin can register new admins"}), 403
        pwd_hash = hash_password(password)
        c.execute("INSERT INTO admin (username, password_hash, role) VALUES (?, ?, ?)",
                  (username, pwd_hash, "admin"))
        # audit
        ts = datetime.datetime.utcnow().isoformat()
        c.execute("INSERT INTO admin_logs (action, performed_by, target, timestamp) VALUES (?, ?, ?, ?)",
                  ("create_admin", current_admin, username, ts))
        conn.commit()
        conn.close()
        return jsonify({"message": f"Admin '{username}' registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Admin already exists"}), 409
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

@app.route("/api/admin/login", methods=["POST"])
@limiter.limit("5 per minute")
def admin_login():
    data, (err_resp, err_code) = get_json_or_400()
    if err_resp:
        return err_resp, err_code
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT password_hash FROM admin WHERE username=?", (username,))
        row = c.fetchone()
        if row and verify_password(row[0], password):
            # clear failed attempts
            c.execute("DELETE FROM failed_logins WHERE username=?", (username,))
            conn.commit()
        else:
            # increment failed attempts
            c.execute("SELECT attempts FROM failed_logins WHERE username=?", (username,))
            fr = c.fetchone()
            now = datetime.datetime.utcnow().isoformat()
            if fr:
                attempts = fr[0] + 1
                c.execute("UPDATE failed_logins SET attempts=?, last_attempt=? WHERE username=?",
                          (attempts, now, username))
            else:
                c.execute("INSERT INTO failed_logins (username, attempts, last_attempt) VALUES (?, ?, ?)",
                          (username, 1, now))
            conn.commit()
        conn.close()
        if not row or not verify_password(row[0], password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = jwt.encode({
            "username": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode()
        return jsonify({"token": token}), 200
    except Exception as e:
    	import traceback
    	print("ADMIN LOGIN ERROR:", e)
    	traceback.print_exc()
    	return jsonify({"error": "An internal server error occurred"}), 500

@app.route("/api/admin/teachers", methods=["GET"])
@token_required
def admin_get_teachers(current_admin):
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT id, name, email_enc, phone_enc, aadhar_enc, ifsc_enc, account_enc, bank_name_enc, branch_enc, classes_taken, designation FROM teachers")
        rows = c.fetchall()
        conn.close()
        result = []
        for r in rows:
            # decrypt where possible, then mask
            email_plain = decrypt_field(r[2])
            phone_plain = decrypt_field(r[3])
            aadhar_plain = decrypt_field(r[4])
            ifsc_plain = decrypt_field(r[5])
            account_plain = decrypt_field(r[6])
            bank_plain = decrypt_field(r[7])
            branch_plain = decrypt_field(r[8])
            result.append({
                "id": r[0],
                "name": r[1],
                "email": mask_email(email_plain) if email_plain else None,
                "phone": mask_phone(phone_plain) if phone_plain else None,
                "aadhar": mask_aadhar(aadhar_plain) if aadhar_plain else None,
                "ifsc": mask_account_no(ifsc_plain) if ifsc_plain else None,
                "account_no": mask_account_no(account_plain) if account_plain else None,
                "bank_name": mask_account_no(bank_plain) if bank_plain else None,
                "branch": mask_account_no(branch_plain) if branch_plain else None,
                "classes_taken": r[9],
                "designation": r[10]
            })
        return jsonify(result), 200
    except Exception:
        return jsonify({"error": "Could not fetch teacher data"}), 500

@app.route("/api/admin/teacher/<int:teacher_id>", methods=["DELETE"])
@token_required
def admin_delete_teacher(current_admin, teacher_id):
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("DELETE FROM teachers WHERE id=?", (teacher_id,))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        if deleted == 0:
            return jsonify({"error": "Teacher not found"}), 404
        return jsonify({"message": "Teacher deleted successfully"}), 200
    except Exception:
        return jsonify({"error": "Could not delete teacher"}), 500

# -------------------------
# Teacher Routes (no JWT)
# -------------------------
# -------------------------
# Teacher Routes (Secure, no JWT)
# -------------------------

@app.route("/api/teacher/register", methods=["POST"])
@limiter.limit("5 per hour")
def teacher_register():
    data, (err_resp, err_code) = get_json_or_400()
    if err_resp:
        return err_resp, err_code

    required_fields = ["name", "email", "phone", "aadhar", "ifsc",
                       "account_no", "bank_name", "branch",
                       "classes_taken", "designation", "password"]
    if not all(field in data and data[field] for field in required_fields):
        return jsonify({"error": "All fields are required"}), 400

    v_err = validate_teacher_fields(data)
    if v_err:
        return jsonify({"error": v_err}), 400
    if not is_strong_password(data["password"]):
        return jsonify({"error": "Password must be strong"}), 400

    try:
        classes_taken_val = int(data["classes_taken"])
    except Exception:
        return jsonify({"error": "classes_taken must be an integer"}), 400

    try:
        email_enc = encrypt_field(data["email"])
        phone_enc = encrypt_field(data["phone"])
        aadhar_enc = encrypt_field(data["aadhar"])
        ifsc_enc = encrypt_field(data["ifsc"])
        account_enc = encrypt_field(data["account_no"])
        bank_enc = encrypt_field(data["bank_name"])
        branch_enc = encrypt_field(data["branch"])
        email_hash = hash_for_lookup(data["email"])
        phone_hash = hash_for_lookup(data["phone"])
        aadhar_hash = hash_for_lookup(data["aadhar"])
        account_hash = hash_for_lookup(data["account_no"])
        pwd_hash = hash_password(data["password"])

        conn = db_connect()
        c = conn.cursor()
        c.execute('''INSERT INTO teachers
            (name, email_enc, email_hash, phone_enc, phone_hash, aadhar_enc, aadhar_hash,
             ifsc_enc, account_enc, account_hash, bank_name_enc, branch_enc, classes_taken, designation, password_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (data["name"], email_enc, email_hash, phone_enc, phone_hash,
                   aadhar_enc, aadhar_hash, ifsc_enc, account_enc, account_hash,
                   bank_enc, branch_enc, classes_taken_val, data["designation"], pwd_hash))
        conn.commit()
        conn.close()
        return jsonify({"message": "Teacher registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Teacher with this email/phone/aadhar/account already exists"}), 409
    except Exception:
        return jsonify({"error": "An error occurred"}), 500


# -------------------------
@app.route("/api/teacher/login", methods=["POST"])
@limiter.limit("10 per minute")
def teacher_login():
    data, (err_resp, err_code) = get_json_or_400()
    if err_resp:
        return err_resp, err_code

    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    try:
        email_hash = hash_for_lookup(email)
        conn = db_connect()
        c = conn.cursor()
        c.execute("""
            SELECT id, name, email_enc, phone_enc, aadhar_enc, ifsc_enc, account_enc,
                   bank_name_enc, branch_enc, classes_taken, designation, password_hash
            FROM teachers WHERE email_hash=?""", (email_hash,))
        row = c.fetchone()
        conn.close()
        if not row or not verify_password(row[11], password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = jwt.encode({
            "teacher_id": row[0],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)  # token valid for 12 hours
        }, app.config['SECRET_KEY'], algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode()

        # Return teacher info + JWT
        teacher_obj = {
            "id": row[0],
            "name": row[1],
            "email": decrypt_field(row[2]),
            "phone": decrypt_field(row[3]),
            "aadhar": decrypt_field(row[4]),
            "ifsc": decrypt_field(row[5]),
            "account_no": decrypt_field(row[6]),
            "bank_name": decrypt_field(row[7]),
            "branch": decrypt_field(row[8]),
            "classes_taken": row[9],
            "designation": row[10]
        }
        return jsonify({"message": "Login successful", "teacher": teacher_obj, "token": token}), 200
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

@app.route("/api/teacher/edit", methods=["PUT"])
@limiter.limit("10 per hour")
@teacher_token_required
def teacher_edit_profile(teacher_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    v_err = validate_teacher_fields(data)
    if v_err:
        return jsonify({"error": v_err}), 400

    allowed_fields = ["name", "email", "phone", "aadhar", "ifsc",
                      "account_no", "bank_name", "branch", "classes_taken", "designation", "password"]
    updates = []
    values = []

    try:
        conn = db_connect()
        c = conn.cursor()

        for field in allowed_fields:
            if field in data and data[field] not in [None, ""]:
                if field == "email":
                    enc = encrypt_field(data["email"])
                    updates.append("email_enc=?")
                    updates.append("email_hash=?")
                    values.extend([enc, hash_for_lookup(data["email"])])
                elif field == "phone":
                    enc = encrypt_field(data["phone"])
                    updates.append("phone_enc=?")
                    updates.append("phone_hash=?")
                    values.extend([enc, hash_for_lookup(data["phone"])])
                elif field == "aadhar":
                    enc = encrypt_field(data["aadhar"])
                    updates.append("aadhar_enc=?")
                    updates.append("aadhar_hash=?")
                    values.extend([enc, hash_for_lookup(data["aadhar"])])
                elif field == "account_no":
                    enc = encrypt_field(data["account_no"])
                    updates.append("account_enc=?")
                    updates.append("account_hash=?")
                    values.extend([enc, hash_for_lookup(data["account_no"])])
                elif field == "ifsc":
                    updates.append("ifsc_enc=?")
                    values.append(encrypt_field(data["ifsc"]))
                elif field == "bank_name":
                    updates.append("bank_name_enc=?")
                    values.append(encrypt_field(data["bank_name"]))
                elif field == "branch":
                    updates.append("branch_enc=?")
                    values.append(encrypt_field(data["branch"]))
                elif field == "password":
                    updates.append("password_hash=?")
                    values.append(hash_password(data["password"]))
                elif field == "classes_taken":
                    try:
                        values.append(int(data["classes_taken"]))
                        updates.append("classes_taken=?")
                    except Exception:
                        conn.close()
                        return jsonify({"error": "classes_taken must be an integer"}), 400
                else:
                    updates.append(f"{field}=?")
                    values.append(data[field])

        if updates:
            values.append(teacher_id)
            query = f"UPDATE teachers SET {', '.join(updates)} WHERE id=?"
            c.execute(query, values)
            conn.commit()

        conn.close()
        return jsonify({"message": "Profile updated successfully"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "Provided value conflicts with existing record (duplicate)"}), 409
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

# -------------------------
# Run App with HTTPS
# -------------------------
if __name__ == "__main__":
    init_db()

    # Force HTTPS in production
    @app.before_request
    def enforce_https_in_production():
        if not request.is_secure and os.environ.get("FLASK_ENV") == "production":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

    # Determine environment
    FLASK_ENV = os.environ.get("FLASK_ENV", "development")

    if FLASK_ENV == "development":
        # Use self-signed certificate for local testing
        cert_file = os.environ.get("SSL_CERT_FILE", "cert.pem")
        key_file = os.environ.get("SSL_KEY_FILE", "key.pem")

        # Check if files exist
        import os
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("⚠️ SSL cert or key not found. Generating self-signed cert for development.")
            os.system(f"openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj '/CN=localhost'")

        app.run(
            debug=True,
            host="0.0.0.0",
            port=int(os.environ.get("PORT", 5000)),
            ssl_context=(cert_file, key_file)
        )
    else:
        # In production, run Flask on HTTP behind reverse proxy (Nginx handles HTTPS)
        app.run(
            debug=False,
            host="127.0.0.1",
            port=int(os.environ.get("PORT", 5000))
        )

