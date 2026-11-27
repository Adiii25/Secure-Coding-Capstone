# Project Report: Secure Student Registration and Login Portal

## 1. Objective
Build a small web application where a student can register, sign in, view a profile and update limited details, while applying core secure-coding practices: input validation, safe database access, strong authentication, session control, logging and error handling. Then verify those controls with static analysis, dynamic scanning, proxy inspection and manual attacks.

## 2. Technology
Python 3 and Flask, SQLite (standard library `sqlite3`), Werkzeug password hashing, Jinja2 templates, plain CSS and JavaScript. No client-side framework, so the strict Content-Security-Policy needs no exceptions.

## 3. Architecture
Browser > Flask routes in `app.py` > validators (`validators.py`) > SQLite via parameterized queries > `logs/security.log`.
Tables: `users` (profile and password hash) and `login_attempts` (every sign-in attempt, used for lockout and the activity page).

## 4. Threat to control mapping (OWASP Top 10)
| Risk | Control in this project |
|---|---|
| A01 Broken access control | `login_required` on all private routes; the user id comes from the server-side session, never from the request; profile edits only touch the signed-in user's row |
| A02 Cryptographic failures | Salted scrypt hashes; random secret key; Secure cookie and HSTS when `HTTPS=1` |
| A03 Injection (SQL, XSS) | `?` placeholders for every query; whitelist and regex validation; Jinja auto-escaping; CSP blocks inline script |
| A04 Insecure design | Lockout, idle timeout, least-privilege profile fields, database CHECK constraints |
| A05 Security misconfiguration | Debug off, security headers, no stack traces, request size limit |
| A07 Identification and authentication failures | Password rules, common-password check, generic login error, equal-time unknown-user check, session rotation at login, lockout |
| A08 Integrity failures | Signed session cookie; CSRF token on every POST |
| A09 Logging and monitoring failures | Audit log for register, login ok/failed/blocked, logout, timeout, profile and password changes; control characters stripped to prevent log forging |

## 5. Validation rules
Name: letters and spaces only. Email: valid format. Roll number: 10-12 alphanumeric. Semester: 1-8. Branch and gender: fixed whitelists. Password: 8-128 characters, one letter and one digit, not common. Validation runs in the browser for usability, on the server as the authority, and in the database as a last line of defence.

## 6. Secure vs insecure query
```python
# Vulnerable: input becomes part of the SQL
"SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
# Used here: input is bound as data
db.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
```
`demo/sqli_demo.py` runs both versions with `' OR '1'='1` to show the difference.

## 7. Test plan and results
Fill in from `docs/SECURITY_TESTING.md` section 5. Automated evidence: 21 passing unit tests and 20 passing live checks from `scripts/security_check.py`.

## 8. Limitations and future work
Rate limiting is per email and IP, not global. Email verification and password reset by email are not included. The development server is not for production. Add HTTPS, a WSGI server and optional multi-factor authentication for real deployments.
