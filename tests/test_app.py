import os, re, sqlite3, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app

GOOD = dict(name="Asha Verma", email="asha@example.com", roll_number="CS2024A001", branch="CSE",
            semester="3", gender="Female", password="Secret123", confirm_password="Secret123")


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({"TESTING": True, "DATABASE": os.path.join(self.tmp, "t.db"),
                               "LOG_FILE": os.path.join(self.tmp, "t.log")})
        self.c = self.app.test_client()

    def token(self, path="/login"):
        html = self.c.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, path, data, page=None):
        d = dict(data); d["csrf_token"] = self.token(page or path)
        return self.c.post(path, data=d)

    def register(self, **over):
        return self.post("/register", {**GOOD, **over})

    def login(self, email="asha@example.com", pw="Secret123"):
        return self.post("/login", {"email": email, "password": pw})

    def test_register_login_profile(self):
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.login().status_code, 302)
        self.assertIn("Asha Verma", self.c.get("/profile").get_data(as_text=True))

    def test_password_is_hashed(self):
        self.register()
        row = sqlite3.connect(self.app.config["DATABASE"]).execute("SELECT password_hash FROM users").fetchone()
        self.assertNotIn("Secret123", row[0])

    def test_validation_rejects_bad_input(self):
        for field, bad in [("name", "Asha123"), ("email", "not-an-email"), ("roll_number", "short"),
                           ("semester", "9"), ("branch", "XYZ"), ("gender", "Robot"), ("password", "abc")]:
            r = self.register(**{field: bad, "confirm_password": bad if field == "password" else "Secret123"})
            self.assertEqual(r.status_code, 400, field)

    def test_sql_injection_login_fails(self):
        self.register()
        for payload in ["' OR '1'='1", "admin'--", "' OR 1=1 --"]:
            self.assertEqual(self.login(email=payload, pw=payload).status_code, 401)
            self.assertEqual(self.login(pw=payload).status_code, 401)
        self.assertEqual(self.c.get("/profile").status_code, 302)  # still not logged in

    def test_failed_login_logged_and_lockout(self):
        self.register()
        for _ in range(5):
            self.assertEqual(self.login(pw="wrongpass1").status_code, 401)
        self.assertEqual(self.login().status_code, 429)  # locked even with the right password
        with open(self.app.config["LOG_FILE"]) as f:
            self.assertIn("LOGIN_FAILED", f.read())

    def test_profile_requires_login_and_csrf(self):
        self.assertEqual(self.c.get("/profile").status_code, 302)
        self.assertEqual(self.c.post("/register", data=GOOD).status_code, 400)  # no CSRF token

    def test_profile_update_whitelist(self):
        self.register(); self.login()
        r = self.post("/profile/edit", {"name": "Asha V", "branch": "ECE", "semester": "4",
                                        "gender": "Female", "email": "evil@x.com"}, "/profile/edit")
        self.assertEqual(r.status_code, 302)
        page = self.c.get("/profile").get_data(as_text=True)
        self.assertIn("ECE", page); self.assertNotIn("evil@x.com", page)

    def test_session_timeout(self):
        self.register(); self.login()
        with self.c.session_transaction() as s:
            s["last"] = 0
        self.assertEqual(self.c.get("/profile").status_code, 302)

    def test_logout(self):
        self.register(); self.login()
        self.assertEqual(self.post("/logout", {}, "/profile").status_code, 302)
        self.assertEqual(self.c.get("/profile").status_code, 302)

    def test_404_page(self):
        self.assertEqual(self.c.get("/nope").status_code, 404)

    # ---- additional coverage ----
    def test_change_password_flow(self):
        self.register(); self.login()
        bad = self.post("/password", {"current_password": "WrongPass9", "new_password": "NewSecret456",
                                      "confirm_password": "NewSecret456"}, "/password")
        self.assertEqual(bad.status_code, 400)
        weak = self.post("/password", {"current_password": "Secret123", "new_password": "short",
                                       "confirm_password": "short"}, "/password")
        self.assertEqual(weak.status_code, 400)
        ok = self.post("/password", {"current_password": "Secret123", "new_password": "NewSecret456",
                                     "confirm_password": "NewSecret456"}, "/password")
        self.assertEqual(ok.status_code, 302)
        self.assertEqual(self.c.get("/profile").status_code, 302)       # signed out after change
        self.assertEqual(self.login(pw="Secret123").status_code, 401)   # old password dead
        self.assertEqual(self.login(pw="NewSecret456").status_code, 302)

    def test_lockout_resets_after_successful_login(self):
        self.register()
        for _ in range(4):
            self.login(pw="wrongpass1")
        self.assertEqual(self.login().status_code, 302)                 # success clears the count
        self.post("/logout", {}, "/profile")
        for _ in range(4):
            self.assertEqual(self.login(pw="wrongpass1").status_code, 401)

    def test_activity_page_and_device_label(self):
        self.register(); self.login(pw="wrongpass1"); self.login()
        page = self.c.get("/activity").get_data(as_text=True)
        self.assertIn("Failed attempt", page); self.assertIn("Signed in", page)

    def test_session_extend_requires_login_and_csrf(self):
        self.assertEqual(self.c.post("/session/extend", headers={"X-CSRF-Token": "x"}).status_code, 400)
        self.register(); self.login()
        tok = re.search(r'data-csrf="([^"]+)"', self.c.get("/profile").get_data(as_text=True)).group(1)
        r = self.c.post("/session/extend", headers={"X-CSRF-Token": tok})
        self.assertEqual(r.status_code, 200); self.assertEqual(r.get_json()["expires_in"], 600)

    def test_security_headers_and_cookie_flags(self):
        r = self.c.get("/login")
        for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
            self.assertIn(h, r.headers)
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.register()
        cookie = self.login().headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie); self.assertIn("SameSite=Lax", cookie)

    def test_xss_is_escaped_and_rejected(self):
        r = self.register(name="<script>alert(1)</script>")
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("<script>alert(1)</script>", r.get_data(as_text=True))

    def test_log_injection_is_neutralised(self):
        self.login(email="x@y.com\nFAKE LOGIN_OK admin")
        with open(self.app.config["LOG_FILE"]) as f:
            log = f.read()
        self.assertNotIn("\nFAKE", log)

    def test_database_rejects_values_outside_whitelist(self):
        self.register()
        db = sqlite3.connect(self.app.config["DATABASE"])
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE users SET semester = 12")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE users SET branch = 'HACK'")

    def test_duplicate_registration_and_common_password(self):
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.register().status_code, 400)               # duplicate email/roll
        self.assertEqual(self.register(email="b@example.com", roll_number="CS2024A002",
                                       password="password123", confirm_password="password123").status_code, 400)

    def test_wrong_method_and_logged_in_redirects(self):
        self.assertEqual(self.c.get("/logout").status_code, 405)
        self.register(); self.login()
        self.assertEqual(self.c.get("/login").status_code, 302)
        self.assertEqual(self.c.get("/register").status_code, 302)

    def test_unhandled_error_shows_friendly_500_without_traceback(self):
        self.app.view_functions["index"] = lambda: 1 / 0
        r = self.c.get("/")
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 500)
        self.assertIn("internal error", body); self.assertNotIn("ZeroDivisionError", body)
        with open(self.app.config["LOG_FILE"]) as f:
            self.assertIn("UNHANDLED_ERROR", f.read())


if __name__ == "__main__":
    unittest.main()
