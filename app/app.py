"""
VulnLab — a deliberately vulnerable Flask app for learning web pentesting.

DO NOT deploy this anywhere public. DO NOT reuse this code's patterns in a
real project. Every vulnerability here is intentional and commented with a
LAB tag so you can find it. See VULNERABILITIES.md in the repo root for
write-ups of each one, and a proposed fix.

Run with: docker compose up    (see repo README)
Default URL: http://localhost:5000
"""

import base64
import os
import sqlite3

import requests
from flask import Flask, request, render_template, redirect, url_for, abort

from db import get_db, init_db

app = Flask(__name__)
app.secret_key = "dev-only-not-a-real-secret"  # fine for a local lab, never in prod

UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def current_user():
    """Reads the 'session' cookie and looks up who it claims to be.

    LAB 2 — Broken Authentication:
    The cookie is just base64(username), with no signature or server-side
    session check against a secret. Anyone can forge a cookie for any user,
    including admin, without ever knowing a password.
    """
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        username = base64.b64decode(token).decode()
    except Exception:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return user


def make_session_cookie(username):
    return base64.b64encode(username.encode()).decode()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    user = current_user()
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

    if user is None:
        return render_template("login.html", error="Invalid username or password.")

    resp = redirect(url_for("dashboard"))
    resp.set_cookie("session", make_session_cookie(user["username"]))
    return resp


@app.route("/logout")
def logout():
    resp = redirect(url_for("index"))
    resp.delete_cookie("session")
    return resp


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    db = get_db()
    notes = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return render_template("dashboard.html", user=user, notes=notes)


@app.route("/notes/<int:note_id>")
def view_note(note_id):
    """
    LAB 3 — Insecure Direct Object Reference (IDOR):
    This loads a note by id with no check that the logged-in user actually
    owns it. Any logged-in user can view (or, combined with other bugs,
    infer the contents of) any other user's notes just by changing the id
    in the URL.
    """
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        abort(404)
    return render_template("note.html", user=user, note=note)


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("new_note.html", user=user)

    title = request.form.get("title", "")
    body = request.form.get("body", "")
    db = get_db()
    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], title, body),
    )
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/search")
def search_notes():
    """
    LAB 1 — SQL Injection:
    The query string is spliced directly into the SQL statement instead of
    using a parameterized query. Try a title like:  ' OR '1'='1
    """
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    q = request.args.get("q", "")
    db = get_db()
    sql = "SELECT * FROM notes WHERE title LIKE '%" + q + "%'"
    try:
        notes = db.execute(sql).fetchall()
        error = None
    except sqlite3.OperationalError as e:
        notes = []
        error = str(e)

    return render_template("search.html", user=user, notes=notes, q=q, error=error, sql=sql)


@app.route("/profile/<username>")
def profile(username):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if target is None:
        abort(404)
    viewer = current_user()
    return render_template("profile.html", target=target, viewer=viewer)


@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    """
    LAB 4 — Stored XSS:
    The bio is rendered with the Jinja `|safe` filter in profile.html,
    which disables autoescaping. Any HTML/JS a user puts in their bio runs
    in the browser of anyone who later views that profile.
    """
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("edit_profile.html", user=user)

    bio = request.form.get("bio", "")
    db = get_db()
    db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user["id"]))
    db.commit()
    return redirect(url_for("profile", username=user["username"]))


@app.route("/fetch", methods=["GET", "POST"])
def fetch_url():
    """
    LAB 5 — Server-Side Request Forgery (SSRF):
    "Fetch a preview of a link" feature that lets the server make an HTTP
    request to any URL the user supplies, including internal/cloud-metadata
    addresses like http://169.254.169.254/ or http://localhost:<port>/.
    """
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    result = None
    target_url = ""
    if request.method == "POST":
        target_url = request.form.get("url", "")
        try:
            r = requests.get(target_url, timeout=3)
            result = r.text[:2000]
        except Exception as e:
            result = f"Error fetching URL: {e}"

    return render_template("fetch.html", user=user, result=result, target_url=target_url)


@app.route("/files")
def serve_file():
    """
    LAB 6 — Path Traversal:
    Serves files from the uploads directory by filename, but does not
    validate that the resolved path stays inside that directory. Reads the
    file directly with open() instead of a framework helper, so there is no
    safety net. Try:  /files?name=../../app.py
    """
    name = request.args.get("name", "")
    full_path = os.path.join(UPLOADS_DIR, name)
    if not os.path.isfile(full_path):
        abort(404)
    with open(full_path, "rb") as f:
        data = f.read()
    return data, 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    init_db()
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    seed_path = os.path.join(UPLOADS_DIR, "welcome.txt")
    if not os.path.exists(seed_path):
        with open(seed_path, "w") as f:
            f.write("Welcome to VulnLab. This is a seed file served via /files.\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
