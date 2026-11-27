#!/usr/bin/env python3
"""Black-box security checks against a RUNNING portal (default http://127.0.0.1:5000).
Uses only the standard library. Run it only against your own copy of this app.

    python scripts/security_check.py [base_url]

Prints a PASS/FAIL table you can paste into your report. Exit code 1 if anything fails.
"""
import http.cookiejar
import random
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000").rstrip("/")
results = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(jar)), jar


def call(op, path, data=None, headers=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(BASE + path, data=body, headers=headers or {})
    try:
        r = op.open(req, timeout=10)
    except urllib.error.HTTPError as e:
        r = e
    return r.status if hasattr(r, "status") else r.code, r.headers, r.read().decode("utf-8", "replace")


def token(op, path="/login"):
    return re.search(r'name="csrf_token" value="([^"]+)"', call(op, path)[2]).group(1)


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def main():
    rnd = random.randint(100000, 999999)
    email, pw = f"sec{rnd}@example.com", "Str0ngPass99"
    user = dict(name="Security Tester", email=email, roll_number=f"SEC{rnd}AB1"[:12], branch="IT",
                semester="2", gender="Other", password=pw, confirm_password=pw)

    op, _ = client()
    st, hd, _ = call(op, "/login")
    check("Login page loads", st == 200, st)
    for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
        check(f"Security header present: {h}", h in hd)

    st, *_ = call(op, "/register", dict(user))
    check("POST without CSRF token is rejected", st == 400, st)

    st, *_ = call(op, "/register", {**user, "csrf_token": token(op, "/register")})
    check("Valid registration accepted", st == 302, st)
    # A second account is the target for password-field injection, so the lockout it
    # triggers does not interfere with the main test account.
    victim = {**user, "email": f"vic{rnd}@example.com", "roll_number": f"VIC{rnd}AB1"[:12]}
    call(op, "/register", {**victim, "csrf_token": token(op, "/register")})

    # --- SQL injection against login ---
    payloads = ["' OR '1'='1", "' OR 1=1 --", "admin'--", "' OR ''='", "') OR ('1'='1",
                "'; DROP TABLE users; --", "\" OR \"1\"=\"1", "' UNION SELECT 1,2,3,4,5,6,7,8,9 --"]
    sqli_ok = True
    for pl in payloads:
        op2, _ = client()
        for fields in ({"email": pl, "password": pl}, {"email": victim["email"], "password": pl}):
            st, _, body = call(op2, "/login", {**fields, "csrf_token": token(op2)})
            # 401 = rejected, 429 = rejected by lockout; a bypass would be 302
            if st not in (401, 429) or "Traceback" in body or "sqlite" in body.lower():
                sqli_ok = False
                print("   leaked or bypassed with:", pl, st)
    check(f"SQL injection on login blocked ({len(payloads)} payloads x 2 fields)", sqli_ok)

    # --- injection / XSS through registration fields ---
    op3, _ = client()
    bad = [("name", "<script>alert(1)</script>"), ("name", "Robert'); DROP TABLE users;--"),
           ("email", "a@b.com' OR '1'='1"), ("roll_number", "' OR '1'='1"), ("semester", "1 OR 1=1"),
           ("branch", "CSE' --"), ("gender", "<img src=x onerror=alert(1)>")]
    all_rejected = True
    for field, value in bad:
        d = {**user, field: value, "email": user["email"] if field != "email" else value,
             "csrf_token": token(op3, "/register")}
        if field != "roll_number":
            d["roll_number"] = "ZZ" + str(rnd) + "Q9"[: 12 - 2 - len(str(rnd))]
        st, _, body = call(op3, "/register", d)
        if st != 400 or value in body:
            all_rejected = False
            print("   not rejected:", field, value, st)
    check("Malicious registration input rejected and never reflected", all_rejected)

    # --- authentication and session behaviour ---
    op4, jar = client()
    st, *_ = call(op4, "/profile")
    check("Profile requires login (redirect)", st == 302, st)
    st, hd, _ = call(op4, "/login", {"email": email, "password": pw, "csrf_token": token(op4)})
    check("Valid login succeeds", st == 302, st)
    cookie = hd.get("Set-Cookie", "")
    check("Session cookie is HttpOnly", "HttpOnly" in cookie)
    check("Session cookie has SameSite", "SameSite" in cookie)
    st, _, body = call(op4, "/profile")
    check("Profile page shows the student's name", st == 200 and "Security Tester" in body, st)
    st, *_ = call(op4, "/profile/edit", {"name": "Hacker", "csrf_token": "forged"})
    check("Profile update with forged CSRF token rejected", st == 400, st)
    st, *_ = call(op4, "/logout")
    check("GET /logout not allowed (must be POST)", st == 405, st)
    st, *_ = call(op4, "/logout", {"csrf_token": token(op4, "/profile")})
    st2, *_ = call(op4, "/profile")
    check("Logout ends the session", st == 302 and st2 == 302, f"{st}/{st2}")

    # --- error handling ---
    st, _, body = call(op4, "/does-not-exist")
    check("404 page is friendly with no stack trace", st == 404 and "Traceback" not in body, st)

    # --- brute force lockout ---
    op5, _ = client()
    codes = [call(op5, "/login", {"email": email, "password": "Wrong" + str(i) + "pass",
                                  "csrf_token": token(op5)})[0] for i in range(6)]
    check("Account locks after 5 failed attempts (HTTP 429)", codes[:5] == [401] * 5 and codes[5] == 429, codes)
    st, *_ = call(op5, "/login", {"email": email, "password": pw, "csrf_token": token(op5)})
    check("Correct password is still refused while locked", st == 429, st)

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    print("Now review logs/security.log for LOGIN_FAILED and LOGIN_BLOCKED entries.")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as exc:
        sys.exit(f"Cannot reach {BASE}: {exc}. Start the app first with: python app.py")
