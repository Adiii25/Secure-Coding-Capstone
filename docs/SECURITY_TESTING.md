# Security Testing Guide

Start the app: `python app.py` (http://127.0.0.1:5000). Test only your own copy of the app.

Quick overview of what is automated and what you run by hand:

| Test | Tool | Where |
|---|---|---|
| 21 unit/integration tests | unittest | `python -m unittest discover -s tests` |
| 20 live attack checks | Python script | `python scripts/security_check.py` |
| Vulnerable vs safe SQL | Python demo | `python demo/sqli_demo.py` |
| Static analysis | SonarQube | section 2 |
| Web vulnerability scan | OWASP ZAP | section 3 |
| Login request inspection | Burp Suite | section 4 |
| Manual SQL injection | Browser + Burp | section 1 |

## 1. Manual SQL injection tests
Type these into the login form. (The browser may reject some in the email box; send them with Burp Repeater as in section 4.)

| Payload | Expected result |
|---|---|
| `' OR '1'='1` in email and password | "Incorrect email or password", HTTP 401 |
| `admin'--` | Same |
| `' OR 1=1 --` | Same |
| `'; DROP TABLE users;--` | Same; the users table is untouched |
| `' UNION SELECT 1,2,3,4,5,6,7,8,9 --` | Same; no data returned |
| Register with name `Robert'); DROP TABLE users;--` | Rejected by validation, HTTP 400 |

Why it fails: the login query is `SELECT id, password_hash FROM users WHERE email = ?`. The payload is bound as a value, so it is just a string that matches no email. See `python demo/sqli_demo.py` for the vulnerable version of the same query being bypassed.

Then open `logs/security.log` and confirm each attempt shows as `LOGIN_FAILED`. After 5 failures you get HTTP 429 and `LOGIN_BLOCKED`.

## 2. SonarQube (static analysis)
1. Start it: `docker compose -f docker-compose.sonarqube.yml up -d`, then open http://localhost:9000 (admin / admin; change the password).
2. Create a local project with key `secure-student-portal`, choose "Locally", and generate a token.
3. Install the SonarScanner CLI and run from the project root: `sonar-scanner -Dsonar.token=YOUR_TOKEN` (settings are in `sonar-project.properties`).
4. Review Bugs, Vulnerabilities, Security Hotspots and Code Smells; screenshot the dashboard.

Expected review items to discuss in your report:
- Cookie `Secure` flag is set only when `HTTPS=1` (a hotspot on plain HTTP; correct behaviour for local testing).
- `app.run(...)` binds to 127.0.0.1 with debug off, which is safe.
- Jinja templates auto-escape output, which is why XSS payloads are shown as text.

## 3. OWASP ZAP (dynamic scan)
GUI: set the target to http://127.0.0.1:5000, run **Automated Scan**, then export the HTML report. For deeper coverage use Manual Explore: sign in through the ZAP browser first so authenticated pages are crawled.

Command line (Docker; on Linux add `--network host`, and use `host.docker.internal` on Windows/macOS):
```bash
docker run --rm -v "$(pwd):/zap/wrk" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000 -r zap-report.html
```
Expected: no SQL injection or XSS alerts. Likely low or informational items, each explainable:
- Cookie without Secure flag / missing HSTS: only because testing over HTTP. Run behind HTTPS with `HTTPS=1`.
- Server header discloses the Werkzeug version: the development server adds it; a production proxy hides it.
- Sec-Fetch-* headers missing (informational): sent by browsers, not by the scanner.

## 4. Burp Suite (inspect login requests)
1. Proxy > Open browser, visit http://127.0.0.1:5000/login, turn Intercept on and submit a login.
2. A captured request looks like:
```
POST /login HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded
Cookie: session=eyJjc3JmIjoi...

csrf_token=9f1c...&email=asha%40example.com&password=Secret123
```
   Observe: three fields, a per-session `csrf_token`, and in the response `Set-Cookie: session=...; HttpOnly; SameSite=Lax`.
3. **Repeater:** change `email` to `' OR '1'='1` and resend: 401. Delete or alter `csrf_token`: 400.
4. **Intruder:** attack the `password` field with a short wordlist against one email: five 401 responses, then 429.
5. Report note: over plain HTTP the password is readable in the proxy. That is the reason production must use HTTPS.

## 5. Results table (fill in for your report)
| Test | Tool | Expected | Your result / evidence |
|---|---|---|---|
| SQL injection on login | Manual / Burp Repeater | 401, no bypass | |
| SQL injection in registration | security_check.py | 400, never reflected | |
| CSRF token missing/forged | Burp / script | 400 | |
| Brute-force lockout | Burp Intruder | 401 x5 then 429 | |
| Session timeout | Browser (wait 10 min or see countdown) | Redirect to login | |
| Cookie flags | Burp response | HttpOnly, SameSite | |
| Static analysis | SonarQube | No vulnerabilities | |
| Web scan | ZAP | No SQLi/XSS | |
