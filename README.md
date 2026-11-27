# Secure Student Registration and Login Portal

A Flask + SQLite web app where students register, sign in, view an ID-card style profile, update limited details and change their password. It is built around the security controls in the capstone brief and ships with the tests and tooling to prove them.

## Quick start
```bash
./run.sh                     # macOS/Linux  (Windows: double-click run.bat)
# or manually:
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                # http://127.0.0.1:5000
```
Run the checks:
```bash
python -m unittest discover -s tests          # 21 automated tests
python scripts/security_check.py              # 20 attack checks against the running app
python demo/sqli_demo.py                      # vulnerable vs parameterized SQL, side by side
```
First run creates `instance/portal.db`, `instance/secret.key` and `logs/security.log`.

## Features
| Requirement from the brief | Implementation |
|---|---|
| User registration | `/register`, server-side validation, duplicate email/roll detection |
| Login / logout | `/login`, `/logout` (POST only, CSRF-protected) |
| Password hashing | Werkzeug salted one-way hashes (scrypt); plain passwords are never stored or logged |
| Session management | Signed HttpOnly SameSite cookie, new session on login, cleared on logout |
| Automatic session timeout | 10 min idle, enforced on the server; the browser shows a countdown, a 60-second warning and "Stay signed in" |
| Profile page | ID card with branch colour and roll-number barcode, details, recent sign-in activity |
| Update limited profile info | Name, branch, semester, gender only; email and roll number are fixed |
| Input validation | Regex rules in `validators.py`, repeated live in the browser and as CHECK constraints in the database |
| Whitelist validation | Branch, semester (1-8) and gender must match fixed lists; any other value is rejected |
| SQL injection protection | Every query uses `?` placeholders; no SQL is built from input |
| Failed-login logging | `logs/security.log` records `LOGIN_FAILED`, `LOGIN_BLOCKED`, `LOGIN_OK` with time, IP and browser |
| Error handling | Friendly 400/403/404/405/413/500 pages; details go to the log, never to the user |

**Validation rules:** Name = letters and spaces only. Email = valid format. Roll number = 10-12 letters or digits. Semester = 1-8. Password = 8-128 characters with a letter and a digit, not a common password.

**Extras beyond the brief:** change password, sign-in activity page (failed attempts visible to the owner), brute-force lockout (5 failures per email + IP in 15 minutes, resets after a successful login), CSRF tokens, Content Security Policy and other security headers, generic login error and equal-time check for unknown emails, log-injection protection, 16 KB request limit, dark mode, mobile layout, keyboard and screen-reader support.

## Project layout
```
app.py              routes, sessions, lockout, logging, error handlers
validators.py       all validation rules and whitelists
schema.sql          tables with CHECK constraints
templates/ static/  UI (no inline scripts or styles, so the strict CSP holds)
tests/              21 unit and integration tests
scripts/            security_check.py (live attack checks)
demo/               sqli_demo.py (educational comparison)
docs/               SECURITY_TESTING.md (SonarQube, ZAP, Burp, manual SQLi), PROJECT_REPORT.md
sonar-project.properties, docker-compose.sonarqube.yml
```

## Configuration
| Setting | How |
|---|---|
| Secret key | `SECRET_KEY` env var, otherwise generated once in `instance/secret.key` |
| HTTPS deployment | `HTTPS=1` turns on the Secure cookie flag and HSTS (put the app behind TLS) |
| Timeout / lockout | constants at the top of `app.py` |

Production note: the built-in Flask server is for development and demos. For real deployment use a WSGI server such as gunicorn or waitress behind an HTTPS reverse proxy.
