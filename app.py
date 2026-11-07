"""Flask app: serves the dashboard page and its JSON data endpoint.

Login: local username/password, plus optional Google sign-in restricted to an
allowlist of verified email addresses (GOOGLE_ALLOWED_EMAILS).
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import timedelta

import click
from authlib.integrations.flask_client import OAuth, OAuthError
from flask import (Flask, abort, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from cowrie_data import snapshot

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],  # fails loudly if unset
    DATABASE=os.environ.get("DATABASE", "/var/lib/cowrie-dashboard/users.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Trust exactly one proxy (nginx) for client IP, scheme, and host.
# Flask must only be reachable through nginx (bind gunicorn to 127.0.0.1).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")

# ---------- Google sign-in (optional) ----------
GOOGLE_ENABLED = bool(os.environ.get("GOOGLE_CLIENT_ID")
                      and os.environ.get("GOOGLE_CLIENT_SECRET"))
# Only these verified Google emails may log in. Comma-separated, case-insensitive.
ALLOWED_GOOGLE = {
    e.strip().lower()
    for e in os.environ.get("GOOGLE_ALLOWED_EMAILS", "").split(",")
    if e.strip()
}

oauth = OAuth(app)
if GOOGLE_ENABLED:
    if not ALLOWED_GOOGLE:
        # Fail closed: without an allowlist, any Google user could get in.
        raise RuntimeError(
            "GOOGLE_ALLOWED_EMAILS must be set when Google login is enabled"
        )
    oauth.register(
        name="google",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url=(
            "https://accounts.google.com/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )

# Hashed against when the username doesn't exist, so timing doesn't leak it.
DUMMY_HASH = generate_password_hash("not-a-real-password")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);
"""

# Everything not listed here requires a logged-in session (deny by default).
PUBLIC_ENDPOINTS = {
    "login",
    "signup",
    "static",
    "google_login",
    "google_callback",
}


def db_connect():
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    """Create the users table and add the Google columns to older databases."""
    conn.executescript(SCHEMA)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "google_sub" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
    if "email" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub "
        "ON users(google_sub)"
    )
    conn.commit()


@app.context_processor
def template_flags():
    return {
        "signup_enabled": bool(os.environ.get("SIGNUP_CODE")),
        "google_enabled": GOOGLE_ENABLED,
    }


@app.before_request
def require_login():
    """Deny by default: only PUBLIC_ENDPOINTS are reachable without a session."""
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if "user_id" not in session:
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized"), 401  # so the page's JS can react
        return redirect(url_for("login"))
    return None


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 30 per hour", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = db_connect()
        try:
            user = conn.execute(
                "SELECT id, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            conn.close()

        # Always run one hash check so timing doesn't reveal valid usernames.
        ok = check_password_hash(
            user["password_hash"] if user else DUMMY_HASH, password
        )
        if user and ok:
            session.clear()  # prevents session fixation
            session.permanent = True
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        return render_template("login.html",
                               error="Invalid username or password"), 401
    return render_template("login.html", error=None)


@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("3 per hour", methods=["POST"])
def signup():
    """Invite-only signup. Disabled (404) unless SIGNUP_CODE is set."""
    code = os.environ.get("SIGNUP_CODE")
    if not code:
        abort(404)

    error = None
    if request.method == "POST":
        invite = request.form.get("invite", "")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not hmac.compare_digest(invite.encode(), code.encode()):
            error = "Invalid invite code"
        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            error = "Username must be 3-32 characters: letters, digits, _ . -"
        elif len(password) < 12:
            error = "Password must be at least 12 characters"
        elif password != confirm:
            error = "Passwords don't match"
        else:
            conn = db_connect()
            try:
                init_db(conn)
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                error = "Username unavailable"
            finally:
                conn.close()
            if not error:
                return redirect(url_for("login"))
        return render_template("signup.html", error=error), 400

    return render_template("signup.html", error=None)


@app.get("/login/google")
@limiter.limit("10 per minute")
def google_login():
    if not GOOGLE_ENABLED:
        abort(404)
    # Optionally pin the redirect URI so it never depends on the Host header.
    redirect_uri = (os.environ.get("GOOGLE_REDIRECT_URI")
                    or url_for("google_callback", _external=True))
    return oauth.google.authorize_redirect(redirect_uri)


@app.get("/auth/google/callback")
@limiter.limit("20 per minute")
def google_callback():
    if not GOOGLE_ENABLED:
        abort(404)
    try:
        token = oauth.google.authorize_access_token()  # checks state, nonce, signature
    except OAuthError:
        return render_template(
            "login.html", error="Google sign-in failed. Please try again."), 400

    info = token.get("userinfo") or {}
    sub = info.get("sub")
    email = (info.get("email") or "").lower()

    # Authorization: Google proves WHO they are, the allowlist decides IF they may enter.
    if not sub or info.get("email_verified") is not True or email not in ALLOWED_GOOGLE:
        app.logger.warning("Google login denied for %r", email)
        return render_template(
            "login.html", error="This Google account is not authorized."), 403

    conn = db_connect()
    try:
        init_db(conn)
        account = conn.execute(
            "SELECT id FROM users WHERE google_sub = ?", (sub,)
        ).fetchone()
        if account is None:
            username = "g_" + hashlib.sha256(sub.encode()).hexdigest()[:30]
            # Google-only accounts get a random password nobody knows.
            conn.execute(
                "INSERT INTO users (username, password_hash, google_sub, email) "
                "VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(secrets.token_urlsafe(32)),
                 sub, email),
            )
            conn.commit()
            account = conn.execute(
                "SELECT id FROM users WHERE google_sub = ?", (sub,)
            ).fetchone()
        session.clear()  # prevents session fixation
        session.permanent = True
        session["user_id"] = account["id"]
    finally:
        conn.close()
    return redirect(url_for("index"))


@app.post("/logout")  # POST + CSRF token, so other sites can't log you out
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    return jsonify(snapshot())


@app.after_request
def add_headers(resp):
    if request.endpoint != "static":  # let the browser cache css/js/map via ETag
        resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # Attackers control the text shown in the feed, so only allow our own files.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    return resp


@app.cli.command("create-user")
@click.argument("username")
@click.password_option()
def create_user(username, password):
    """Create a user from the shell: flask --app app create-user NAME"""
    if len(password) < 12:
        raise click.ClickException("Use at least 12 characters.")
    conn = db_connect()
    init_db(conn)
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, generate_password_hash(password)),
    )
    conn.commit()
    conn.close()
    click.echo(f"Created {username}")


if __name__ == "__main__":
    # Development only. In production, gunicorn runs this app.
    app.run(host="127.0.0.1", port=8080)
