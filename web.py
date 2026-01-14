import os
import boto3
import secrets
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, url_for
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from boto3.dynamodb.conditions import Key

# -------------------- FLASK SETUP --------------------

app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)

# -------------------- EMAIL SETUP --------------------

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("EMAIL_USER")
app.config["MAIL_PASSWORD"] = os.environ.get("EMAIL_PASS")

mail = Mail(app)

# -------------------- RATE LIMITING --------------------

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# -------------------- DYNAMODB --------------------

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("Users")

# -------------------- PASSWORD RULE --------------------

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

# -------------------- HOME --------------------

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
            return "Password must be strong (upper/lower/number/special)."

        hashed_pw = generate_password_hash(password)
        token = secrets.token_hex(16)

        # Check if user exists
        try:
            existing = table.get_item(Key={"username": username})
            if "Item" in existing:
                return "User already exists"

        except:
            pass

        # Insert user
        table.put_item(
            Item={
                "username": username,
                "email": email,
                "password": hashed_pw,
                "is_verified": False,
                "verification_token": token
            }
        )

        # Send email
        link = url_for("verify_email", token=token, _external=True)
        msg = Message(
            "Verify Your Account",
            sender=os.environ.get("EMAIL_USER"),
            recipients=[email]
        )
        msg.body = f"Click to verify your account: {link}"
        mail.send(msg)

        return "Account created! Check your email."

    return render_template("register.html")

# -------------------- EMAIL VERIFICATION --------------------

@app.route("/verify/<token>")
def verify_email(token):
    resp = table.scan(
        FilterExpression=Key("verification_token").eq(token)
    )

    if not resp["Items"]:
        return "Invalid or expired token."

    user = resp["Items"][0]

    table.update_item(
        Key={"username": user["username"]},
        UpdateExpression="SET is_verified = :v, verification_token = :t",
        ExpressionAttributeValues={
            ":v": True,
            ":t": None
        }
    )

    return "Email verified! You can now log in."

# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        identifier = request.form["username"]
        password = request.form["password"]

        # Query by username OR email
        if "@" in identifier:
            resp = table.scan(
                FilterExpression=Key("email").eq(identifier)
            )
        else:
            resp = table.get_item(Key={"username": identifier})
            resp = {"Items": [resp.get("Item")] if "Item" in resp else []}

        if not resp["Items"]:
            return "Invalid credentials"

        user = resp["Items"][0]

        if not check_password_hash(user["password"], password):
            return "Invalid credentials"

        if not user.get("is_verified"):
            return "Please verify your email first."

        # OTP
        otp = secrets.randbelow(900000) + 100000
        session["pending_user"] = user["username"]
        session["otp"] = str(otp)
        session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()

        msg = Message(
            "Your Login OTP",
            sender=os.environ.get("EMAIL_USER"),
            recipients=[user["email"]],
        )
        msg.body = f"Your OTP is: {otp} (valid 5 minutes)"
        mail.send(msg)

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

    table.delete_item(Key={"username": session["user"]})
    session.clear()
    return redirect(url_for("register"))

# -------------------- RUN --------------------

if __name__ == "__main__":
    app.run(debug=True)
