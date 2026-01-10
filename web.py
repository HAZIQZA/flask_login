#!/usr/bin/python
from flask import Flask, render_template, request, redirect, session, url_for
from flask_limiter import Limiter
from datetime import timedelta,datetime,timezone
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from flask_wtf.csrf import CSRFProtect
import re
import secrets
from flask_mail import Mail, Message

app = Flask(__name__)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "abdulsalihaslah@gmail.com"  
app.config["MAIL_PASSWORD"] = "cttb krfu qltr jrke"  # generated from Google
mail = Mail(app)

#cache clearer
@app.after_request
def apply_no_cache(response):
    if "user" in session:   # only logged-in pages
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)


#strong password checker
def is_strong_password(password):
    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False

    return True

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

app.config.update(
    #csrf token expiry time
    WTF_CSRF_TIME_LIMIT=3600, #1 hour
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
    #SESSION_COOKIE_SECURE=True,     #tern this on after deployment for https
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- ROUTES ----------

@app.route("/")
def home():
    return redirect("/login")

# ---------- REGISTER ----------
import secrets

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if not is_strong_password(password):
            return "Password must be at least 8 characters and include upper, lower, number, and special character."

        hashed_password = generate_password_hash(password)
        token = secrets.token_hex(16)   # 32-char secure token

        try:
            conn = sqlite3.connect("database.db")
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password, email, verification_token) VALUES (?, ?, ?, ?)",
                (username, hashed_password, email, token)
            )
            conn.commit()
            conn.close()

        except:
            return "User already exists"

        # Normally: send email with link
        verification_link = url_for("verify_email", token=token, _external=True)
        msg = Message(
        subject="Verify Your Account",
        sender="abdulsalihaslah@gmail.com",
        recipients=[email],
        )       

        msg.body = f"Click the link to verify your account: {verification_link}"
        mail.send(msg)


        return "Account created! Check your email to verify your account."


    return render_template("register.html")

#-----------VERIFICATION---------

@app.route("/verify/<token>")
def verify_email(token):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("SELECT username FROM users WHERE verification_token=?", (token,))
    user = cur.fetchone()

    if not user:
        return "Invalid or expired verification link"

    cur.execute("UPDATE users SET is_verified=1, verification_token=NULL WHERE verification_token=?", (token,))
    conn.commit()
    conn.close()

    return "Email verified! You can now log in."





# ---------- LOGIN ----------


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        identifier = request.form["username"]  # user can enter username OR email
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()

        # Check if identifier is email or username
        if "@" in identifier:
            # User typed email
            cur.execute("SELECT username, password, email FROM users WHERE email=?", (identifier,))
        else:
            # User typed username
            cur.execute("SELECT username, password, email FROM users WHERE username=?", (identifier,))

        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):

            # Step 1 — generate OTP
            otp = secrets.randbelow(900000) + 100000  # secure 6-digit OTP

            session["pending_user"] = user[0]   # store username
            session["otp"] = otp
            session["otp_expiry"] = (datetime.now() + timedelta(minutes=5)).timestamp()

            # Step 2 — send OTP email
            msg = Message(
                subject="Your Login OTP",
                sender="abdulsalihaslah@gmail.com",
                recipients=[user[2]],
            )
            msg.body = f"Your OTP is: {otp}. It is valid for 5 minutes."
            mail.send(msg)

            return redirect("/verify_otp")

        else:
            return "Invalid credentials"

    return render_template("login.html")

#----------OTP VERIFICATION--------------
@app.route("/verify_otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form["otp"]

        if "otp" not in session:
            return "OTP expired or invalid."

        if datetime.now().timestamp() > session["otp_expiry"]:
            return "OTP expired. Try logging in again."

        if str(session["otp"]) == entered_otp:
            # Login successful
            session["user"] = session["pending_user"]

            session.pop("otp")
            session.pop("pending_user")
            session.pop("otp_expiry")

            return redirect("/dashboard")
        else:
            return "Incorrect OTP"

    return render_template("otp.html")


# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template("dashboard.html", user=session["user"],expires_at=session.get("expires_at"))

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")

#------------DELETE USER---------
@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    # Clear session after deletion
    session.clear()

    return redirect("/register")
#--------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0",debug=True)
