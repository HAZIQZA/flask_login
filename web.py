import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, request, redirect, session, url_for
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# -------------------- LOAD ENV --------------------

load_dotenv()

# -------------------- FLASK SETUP --------------------

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret-key")
csrf = CSRFProtect(app)

# -------------------- RATE LIMITING --------------------

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# -------------------- EMAIL SETUP --------------------

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = EMAIL_USER
app.config["MAIL_PASSWORD"] = EMAIL_PASS

mail = Mail(app)

# -------------------- DATABASE SETUP (SQLITE) --------------------

DB_PATH = Path("users.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --------------------JUST FOR TESTING---------------------

print("EMAIL_USER:", EMAIL_USER)
print("EMAIL_PASS:", bool(EMAIL_PASS))

# -------------------- PASSWORD POLICY --------------------


def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# -------------------- NO CACHE --------------------

@app.after_request
def apply_no_cache(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# -------------------- ROUTES --------------------

@app.route("/")
def home():
    return redirect(url_for("login"))

# -------------------- REGISTER --------------------

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if not is_strong_password(password):
            return "Password must include upper, lower, number & special char."

        hashed_pw = generate_password_hash(password)
        token = secrets.token_hex(16)

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()

            cur.execute("SELECT username FROM users WHERE username=?", (username,))
            if cur.fetchone():
                return "User already exists"

            cur.execute("""
                INSERT INTO users VALUES (?, ?, ?, ?, ?)
            """, (username, email, hashed_pw, 0, token))

            conn.commit()
            conn.close()

        except Exception as e:
            return f"Database error: {e}"

        link = url_for("verify_email", token=token, _external=True)

        if EMAIL_USER and EMAIL_PASS:
            msg = Message(
                "Verify Your Account",
                sender=EMAIL_USER,
                recipients=[email]
            )
            msg.body = f"Click to verify your account: {link}"
            mail.send(msg)
        else:
            print(f"[DEV MODE] Verification link: {link}")

        return "Account created! Check email (or console in dev mode)."

    return render_template("register.html")

# -------------------- EMAIL VERIFY --------------------

@app.route("/verify/<token>")
def verify_email(token):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET is_verified=1, verification_token=NULL
        WHERE verification_token=?
    """, (token,))

    if cur.rowcount == 0:
        conn.close()
        return "Invalid or expired token."

    conn.commit()
    conn.close()
    return "Email verified! You can log in."

# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        identifier = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute("""
            SELECT * FROM users WHERE username=? OR email=?
        """, (identifier, identifier))

        user = cur.fetchone()
        conn.close()

        if not user:
            return "Invalid credentials"

        username, email, hashed_pw, verified, _ = user

        if not check_password_hash(hashed_pw, password):
            return "Invalid credentials"

        if not verified:
            return "Please verify your email first."

        otp = str(secrets.randbelow(900000) + 100000)

        session["pending_user"] = username
        session["otp"] = otp
        session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()

        if EMAIL_USER and EMAIL_PASS:
            msg = Message(
                "Your Login OTP",
                sender=EMAIL_USER,
                recipients=[email]
            )
            msg.body = f"Your OTP is: {otp} (valid for 5 minutes)"
            mail.send(msg)
        else:
            print(f"[DEV MODE] OTP for {username}: {otp}")

        return redirect(url_for("verify_otp"))

    return render_template("login.html")

# -------------------- OTP VERIFY --------------------

@app.route("/verify_otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp():
    if request.method == "POST":
        user_otp = request.form["otp"]

        if "otp" not in session:
            return "OTP expired."

        if datetime.utcnow().timestamp() > session["otp_expiry"]:
            return "OTP expired."

        if user_otp != session["otp"]:
            return "Incorrect OTP."

        session["user"] = session["pending_user"]

        session.pop("otp")
        session.pop("pending_user")
        session.pop("otp_expiry")

        return redirect(url_for("dashboard"))

    return render_template("otp.html")

# -------------------- DASHBOARD --------------------

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

# -------------------- LOGOUT --------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------- DELETE ACCOUNT --------------------

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (session["user"],))
    conn.commit()
    conn.close()

    session.clear()
    return redirect(url_for("register"))

# -------------------- RUN --------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
