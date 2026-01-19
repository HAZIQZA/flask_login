# Secure Flask Authentication System

A secure Flask-based authentication system implementing:

* User registration
* Email verification
* OTP-based login
* Rate limiting
* Password strength validation

This project is designed to run **locally on any machine** and is **safe to publish on GitHub**.
No cloud services or credentials are required to run the core functionality.

---

## 🚀 Features

* User registration with strong password enforcement
* Email verification using a token
* OTP-based login authentication
* Rate limiting to prevent brute-force attacks
* CSRF protection
* Secure password hashing
* SQLite database (auto-created)
* Development-safe mode (works even without email credentials)

---

## 📂 Project Structure

```
project/
│
├── web.py                # Main Flask application
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
├── .gitignore            # Ignored files
│
├── templates/            # HTML templates
│   ├── login.html
│   ├── register.html
│   ├── otp.html
│   └── dashboard.html
│
├── static/               # CSS / JS files (if any)
│
└── users.db              # SQLite database (auto-created, not committed)
```

---

## 🛠️ Requirements

* Python **3.9+**
* pip
* Internet connection (only if email sending is enabled)

---

## 📦 Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone <your-github-repo-url>
cd <project-folder>
```

---

### 2️⃣ Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate   # Linux / macOS
venv\Scripts\activate      # Windows
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🔐 Environment Variables (IMPORTANT)

This project uses **environment variables** for sensitive data.

### Create a `.env` file in the project root:

```
EMAIL_USER=
EMAIL_PASS=
FLASK_SECRET="supersecretkey"
```

### 🔹 Notes:

* `.env` is **NOT included in GitHub** (for security)
* Each user must create their own `.env`
* Email credentials are **optional**

---

## ✉️ Email Behavior (Very Important)

### ✅ If EMAIL credentials are provided:

* Verification links and OTPs are sent via email

### ✅ If EMAIL credentials are NOT provided:

* Verification links and OTPs are printed in the **console**
* The application still works normally

This design ensures:

* The project runs on **any machine**
* No credentials are required for testing
* Safe for GitHub and academic evaluation

---

## ▶️ Running the Application

```bash
python web.py
```

The server will start on:

```
http://localhost:5000
```

To access from another device on the same network:

```
http://<your-local-ip>:5000
```

---

## 🧪 Application Flow

1. Register a new account
2. Receive verification link (email or console)
3. Verify email
4. Login using username/email + password
5. Receive OTP (email or console)
6. Enter OTP to access dashboard

---

## 🗄️ Database

* Uses **SQLite**
* Database file (`users.db`) is created automatically
* No manual setup required
* Database file is ignored by Git

---

## 🛡️ Security Measures Implemented

* Password hashing (Werkzeug)
* Strong password enforcement
* CSRF protection
* Rate limiting
* OTP expiration
* Session protection
* No hardcoded credentials

---

## 🧹 Ignored Files

The following are intentionally excluded from version control:

```
.env
users.db
venv/
__pycache__/
```

---

## 📜 License

This project is intended for educational and demonstration purposes.

---

## 👨‍💻 Author

Developed as part of a cybersecurity and secure application development practice project.
