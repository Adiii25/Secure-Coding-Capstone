"""Secure Student Registration and Login Portal (Flask + SQLite)."""
import logging
import os
import secrets
import sqlite3
import time
from datetime import timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import validators as v

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SESSION_TIMEOUT_MIN = 10            # automatic logout after 10 idle minutes
MAX_FAILS, LOCK_WINDOW_MIN = 5, 15  # lock after 5 failures within 15 minutes
MAX_PW_CHANGE_FAILS = 5
# Verified when the email is unknown, so response time does not reveal which emails exist.
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def load_secret_key():
    """Secret key from the SECRET_KEY env var, otherwise generated once in instance/."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE_DIR, "instance", "secret.key")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=load_secret_key(),
        DATABASE=os.path.join(BASE_DIR, "instance", "portal.db"),
        LOG_FILE=os.path.join(BASE_DIR, "logs", "security.log"),
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MIN),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",   # set HTTPS=1 behind TLS
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    for path in (app.config["DATABASE"], app.config["LOG_FILE"]):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    # ---------- logging: logs/security.log ----------
    log = logging.getLogger("security")
    log.setLevel(logging.INFO)
    for old in list(log.handlers):
        old.close()
        log.removeHandler(old)
    handler = RotatingFileHandler(app.config["LOG_FILE"], maxBytes=500_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)

    def clean(text, limit=80):
        """Strip control characters so user input cannot forge log lines."""
        return "".join(c for c in str(text) if c.isprintable())[:limit]

    def audit(event, level=logging.INFO, **fields):
        extra = " ".join(f"{k}={clean(val)}" for k, val in fields.items())
        log.log(level, "%s ip=%s %s", event, request.remote_addr, extra)

    # ---------- database ----------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db:
            db.close()

    with app.app_context():
        with open(os.path.join(BASE_DIR, "schema.sql")) as f:
            get_db().executescript(f.read())

    @app.template_filter("bars")
    def bars(text):
        """Turns a roll number into bar widths (1-4) for the ID-card barcode."""
        return [w for c in text for w in (ord(c) % 4 + 1, ord(c) // 4 % 3 + 1, ord(c) % 3 + 1)]

    @app.template_filter("device")
    def device(ua):
        """Short, readable browser/OS label from a User-Agent string."""
        ua = ua or ""
        browser = next((n for k, n in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                                       ("Chrome/", "Chrome"), ("Safari/", "Safari")) if k in ua), "Unknown browser")
        system = next((n for k, n in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"),
                                      ("iPad", "iOS"), ("Mac OS X", "macOS"), ("Linux", "Linux")) if k in ua), "unknown system")
        return f"{browser} on {system}"

    # ---------- CSRF, session timeout, headers ----------
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    @app.context_processor
    def inject():
        left = None
        if "uid" in session:
            left = max(0, int(SESSION_TIMEOUT_MIN * 60 - (time.time() - session.get("last", 0))))
        return {"csrf_token": csrf_token, "seconds_left": left, "timeout_min": SESSION_TIMEOUT_MIN,
                "max_fails": MAX_FAILS, "lock_min": LOCK_WINDOW_MIN}

    @app.before_request
    def protect():
        if request.endpoint == "static":
            return None
        if "uid" in session:
            if time.time() - session.get("last", 0) > SESSION_TIMEOUT_MIN * 60:
                audit("SESSION_TIMEOUT", user_id=session["uid"])
                session.clear()
                if request.path == url_for("extend_session"):
                    return jsonify(error="expired"), 401
                flash("You were signed out after a period of inactivity.", "info")
                return redirect(url_for("login"))
            session["last"] = time.time()
            session.permanent = True
        if request.method == "POST":
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                audit("CSRF_FAILURE", level=logging.WARNING, path=request.path)
                abort(400)
        return None

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def login_required(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if "uid" not in session:
                flash("Please sign in to continue.", "info")
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapped

    # ---------- brute-force lockout ----------
    def lock_seconds_left(email, ip):
        """Seconds until the account/IP pair unlocks, or 0 if not locked.
        Counts failures in the window that happened after the last successful login."""
        rows = get_db().execute(
            "SELECT CAST(strftime('%s', attempted_at) AS INTEGER) AS ts, "
            "CAST(strftime('%s', 'now') AS INTEGER) AS now FROM login_attempts "
            "WHERE email = ? AND ip = ? AND success = 0 AND attempted_at > datetime('now', ?) "
            "AND id > COALESCE((SELECT MAX(id) FROM login_attempts "
            "WHERE email = ? AND ip = ? AND success = 1), 0) ORDER BY id",
            (email, ip, f"-{LOCK_WINDOW_MIN} minutes", email, ip)).fetchall()
        if len(rows) < MAX_FAILS:
            return 0
        unlock = rows[len(rows) - MAX_FAILS]["ts"] + LOCK_WINDOW_MIN * 60
        return max(1, unlock - rows[-1]["now"])

    def record_attempt(email, ip, ok):
        db = get_db()
        db.execute("INSERT INTO login_attempts (email, ip, success, user_agent) VALUES (?, ?, ?, ?)",
                   (email, ip, int(ok), clean(request.headers.get("User-Agent", ""), 120)))
        db.commit()

    # ---------- routes ----------
    @app.route("/")
    def index():
        return redirect(url_for("profile" if "uid" in session else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if "uid" in session:
            return redirect(url_for("profile"))
        if request.method == "POST":
            data, password, errors = v.validate_registration(request.form)
            if not errors:
                db = get_db()
                try:
                    db.execute(  # parameterized: values never become part of the SQL text
                        "INSERT INTO users (name, email, roll_number, branch, semester, gender, password_hash) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (data["name"], data["email"], data["roll_number"], data["branch"],
                         int(data["semester"]), data["gender"], generate_password_hash(password)))
                    db.commit()
                except sqlite3.IntegrityError:
                    errors["email"] = "An account with this email or roll number already exists."
                else:
                    audit("REGISTER", email=data["email"])
                    flash("Account created. Sign in to continue.", "success")
                    return redirect(url_for("login"))
            return render_template("register.html", errors=errors, form=request.form, v=v), 400
        return render_template("register.html", errors={}, form={}, v=v)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "uid" in session:
            return redirect(url_for("profile"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()[:120]
            password = request.form.get("password", "")[:128]
            ip = request.remote_addr or "unknown"
            wait = lock_seconds_left(email, ip)
            if wait:
                audit("LOGIN_BLOCKED", level=logging.WARNING, email=email)
                flash(f"Too many failed attempts. Try again in {-(-wait // 60)} minute(s).", "error")
                return render_template("login.html", email=email), 429
            user = get_db().execute(
                "SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
            ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
            if user and ok:
                record_attempt(email, ip, True)
                session.clear()                    # new session at login prevents fixation
                session.update(uid=user["id"], last=time.time())
                session.permanent = True
                audit("LOGIN_OK", email=email)
                return redirect(url_for("profile"))
            record_attempt(email, ip, False)
            audit("LOGIN_FAILED", level=logging.WARNING, email=email,
                  ua=request.headers.get("User-Agent", ""))
            flash("Incorrect email or password.", "error")    # same message either way
            return render_template("login.html", email=email), 401
        return render_template("login.html", email="")

    @app.route("/logout", methods=["POST"])
    def logout():
        if "uid" in session:
            audit("LOGOUT", user_id=session["uid"])
        session.clear()
        flash("You have been signed out.", "info")
        return redirect(url_for("login"))

    @app.route("/session/extend", methods=["POST"])
    @login_required
    def extend_session():
        return jsonify(expires_in=SESSION_TIMEOUT_MIN * 60)   # before_request refreshed the clock

    def current_user():
        user = get_db().execute(
            "SELECT id, name, email, roll_number, branch, semester, gender, created_at, updated_at "
            "FROM users WHERE id = ?", (session["uid"],)).fetchone()
        if user is None:
            session.clear()
            abort(403)
        return user

    def recent_activity(email, limit):
        return get_db().execute(
            "SELECT success, ip, user_agent, attempted_at FROM login_attempts "
            "WHERE email = ? ORDER BY id DESC LIMIT ?", (email, limit)).fetchall()

    @app.route("/profile")
    @login_required
    def profile():
        user = current_user()
        return render_template("profile.html", user=user, activity=recent_activity(user["email"], 5))

    @app.route("/activity")
    @login_required
    def activity():
        user = current_user()
        return render_template("activity.html", user=user, activity=recent_activity(user["email"], 25))

    @app.route("/profile/edit", methods=["GET", "POST"])
    @login_required
    def edit_profile():
        user = current_user()
        if request.method == "POST":
            data, errors = v.validate_profile(request.form)   # only whitelisted fields are read
            if not errors:
                db = get_db()
                db.execute("UPDATE users SET name = ?, branch = ?, semester = ?, gender = ?, "
                           "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                           (data["name"], data["branch"], int(data["semester"]), data["gender"], user["id"]))
                db.commit()
                audit("PROFILE_UPDATE", user_id=user["id"])
                flash("Profile updated.", "success")
                return redirect(url_for("profile"))
            return render_template("edit_profile.html", user=user, errors=errors, form=request.form, v=v), 400
        form = {"name": user["name"], "branch": user["branch"],
                "semester": str(user["semester"]), "gender": user["gender"]}
        return render_template("edit_profile.html", user=user, errors={}, form=form, v=v)

    @app.route("/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        user = current_user()
        if request.method == "POST":
            current = request.form.get("current_password", "")[:128]
            new = request.form.get("new_password", "")
            errors = v.validate_password_change(current, new, request.form.get("confirm_password", ""),
                                                user["email"])
            if not errors:
                row = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
                if not check_password_hash(row["password_hash"], current):
                    session["pw_fail"] = session.get("pw_fail", 0) + 1
                    audit("PASSWORD_CHANGE_FAILED", level=logging.WARNING, user_id=user["id"])
                    if session["pw_fail"] >= MAX_PW_CHANGE_FAILS:
                        session.clear()
                        flash("Too many wrong passwords. You have been signed out.", "error")
                        return redirect(url_for("login"))
                    errors["current_password"] = "Current password is incorrect."
                else:
                    db = get_db()
                    db.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (generate_password_hash(new), user["id"]))
                    db.commit()
                    audit("PASSWORD_CHANGE", user_id=user["id"])
                    session.clear()                 # force a fresh sign-in with the new password
                    flash("Password changed. Sign in with your new password.", "success")
                    return redirect(url_for("login"))
            return render_template("password.html", user=user, errors=errors), 400
        return render_template("password.html", user=user, errors={})

    # ---------- error handling: friendly pages, no stack traces ----------
    def error_page(code, title, msg):
        return render_template("error.html", code=code, title=title, msg=msg), code

    @app.errorhandler(400)
    def e400(_e):
        return error_page(400, "Request rejected", "The form expired or the request was invalid. Go back and try again.")

    @app.errorhandler(403)
    def e403(_e):
        return error_page(403, "Access denied", "You do not have permission to view this page.")

    @app.errorhandler(404)
    def e404(_e):
        return error_page(404, "Page not found", "That page does not exist.")

    @app.errorhandler(405)
    def e405(_e):
        return error_page(405, "Method not allowed", "That action is not supported for this page.")

    @app.errorhandler(413)
    def e413(_e):
        return error_page(413, "Request too large", "The submitted data was too large.")

    @app.errorhandler(Exception)
    def e500(exc):
        code = getattr(exc, "code", None)
        if isinstance(code, int) and code < 500:
            return error_page(code, "Error", "Something went wrong with that request.")
        log.exception("UNHANDLED_ERROR path=%s", clean(request.path))
        return error_page(500, "Something went wrong", "An internal error occurred. It has been logged.")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)   # never enable debug in production
