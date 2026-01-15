#  Secure Flask Authentication System  
A fully secure, production-ready authentication system built using **Flask**, **AWS DynamoDB**, **Flask-Mail**, and **Zappa (AWS Lambda)**.  
This project includes:

- ✔ User Registration  
- ✔ Email Verification (secure token link)  
- ✔ Login using Username or Email  
- ✔ OTP-based two-factor authentication  
- ✔ Password hashing  
- ✔ CSRF protection  
- ✔ Rate limiting (anti-bruteforce)  
- ✔ No-cache security headers  
- ✔ Serverless DynamoDB database  
- ✔ Deployment on AWS Lambda using Zappa  

---

##  Features

###  1. **User Registration**
- Strong password validation  
- Unique username + email  
- Email verification token sent through Gmail SMTP

###  2. **Email Verification**
- User receives a secure token link  
- Account activated only after verification

###  3. **Secure Login**
- Login using *username OR email*  
- Password verified using hashed storage  
- Only verified users can log in

###  4. **OTP (One-Time Password)**
- 6-digit secure OTP generated using `secrets`  
- OTP expires in 5 minutes  
- Sent directly to the user’s email  
- Adds an extra security layer

###  5. **Security Controls**
- CSRF tokens for all forms  
- Rate limiting on login & register routes  
- No-cache headers prevent “back button” session leaks  
- Session cookies are HttpOnly and SameSite protected  
- Environment variables for secrets (never stored in code)

###  6. **Serverless DynamoDB**
- Fully persistent NoSQL database  
- No need to upload SQLite files  
- Accessible from AWS Lambda across deployments

###  7. **Zappa + AWS Lambda Deployment**
- Zero server maintenance  
- Auto-scaling  
- API Gateway hosted endpoints  
- Perfect for free-tier usage

---

##  Project Structure

.
│── app.py # Main Flask application
│── templates/
│ ├── login.html
│ ├── register.html
│ ├── otp.html
│ └── dashboard.html
│── static/
│ └── style.css
│── zappa_settings.json # AWS Lambda deployment config
│── README.md # Documentation


---

##  Environment Variables Required

These must be added in AWS Lambda (Configuration → Environment Variables):

| Variable | Purpose |
|---------|---------|
| `EMAIL_USER` | Gmail address used for sending emails |
| `EMAIL_PASS` | Gmail App Password |
| `AWS_REGION` | Region of DynamoDB Table (e.g., `ap-south-1`) |

You must also enable Gmail **App Passwords**.

---

##  DynamoDB Table Structure

Table name: **Users**

| Key | Type | Description |
|-----|------|-------------|
| `username` | STRING (Partition Key) | Unique username |
| `email` | STRING | Must be unique |
| `password` | STRING | Hashed password |
| `verification_token` | STRING | For email verification |
| `is_verified` | BOOLEAN | User must verify email |
| `otp` | STRING | Temporary OTP |
| `otp_expiry` | NUMBER | UNIX timestamp |

---

## ▶ Local Development

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py


Visit:

http://127.0.0.1:5000

☁ Deploying to AWS Lambda (Zappa)
1️ Install Zappa
pip install zappa

2️ Initialize Zappa
zappa init

3️ Deploy
zappa deploy dev

4️ Update
zappa update dev

 Security Features Summary
============================
Feature	Description
CSRF Protection	Prevents cross-site request forgery
Password Hashing	Uses Werkzeug hashing
Rate Limiting	Stops brute-force attacks
OTP	Second factor authentication
No Cache Headers	Prevents back-button access after logout
HttpOnly Cookies	JS cannot read session cookies


 License
=============
MIT License
You may use and modify this project.

Author:-
aslah ap



