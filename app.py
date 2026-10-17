import os
import sqlite3
import secrets
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, g, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
DATABASE = os.environ.get("DATABASE_PATH", "users.db")

PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Login System</title>
<style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#121c2e;--text:#f4f7fb;--muted:#a7b4c8;--accent:#5b8cff;--line:#2a3a53}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,sans-serif}
main{width:min(100% - 28px,520px);margin:6vh auto}.card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:clamp(20px,5vw,34px)}
h1{margin:0 0 8px;font-size:1.8rem}p{color:var(--muted)}label{display:block;margin:16px 0 6px}
input{width:100%;padding:13px;border-radius:10px;border:1px solid var(--line);background:#0b1424;color:var(--text);font-size:1rem}
button{margin-top:18px;padding:12px 16px;border:0;border-radius:10px;background:var(--accent);color:white;font-weight:700;font-size:1rem}
a{color:#8db1ff}.flash{padding:10px 12px;border-radius:9px;margin:12px 0;background:#26384f}.success{border-left:4px solid #35c98a}.error,.warning{border-left:4px solid #ff8a8a}
.small{font-size:.9rem;color:var(--muted)}li{margin:7px 0}
</style></head><body><main><section class="card">
<h1>🔐 Secure Login System</h1><p>Registration, hashed passwords, input validation, sessions, and parameterized database queries.</p>
{% with messages = get_flashed_messages(with_categories=true) %}
{% for category, message in messages %}<div class="flash {{category}}" role="status">{{message}}</div>{% endfor %}{% endwith %}
{{content|safe}}
</section><p class="small">Educational project. Configure a strong SECRET_KEY and use HTTPS before public deployment.</p></main></body></html>
"""

LOGIN = """
<h2>Log in</h2><form method="post" action="/login">
<label for="username">Username</label><input id="username" name="username" maxlength="30" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Log in</button></form><p>New here? <a href="/register">Create an account</a></p>
"""
REGISTER = """
<h2>Create account</h2><form method="post" action="/register">
<label for="username">Username (3–30 letters, numbers, underscores)</label><input id="username" name="username" minlength="3" maxlength="30" pattern="[A-Za-z0-9_]+" autocomplete="username" required>
<label for="password">Password (minimum 10 characters)</label><input id="password" name="password" type="password" minlength="10" autocomplete="new-password" required>
<button type="submit">Register</button></form><p>Already registered? <a href="/login">Log in</a></p>
"""

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to view that page.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return response

@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 30) or not username.replace("_", "").isalnum():
            flash("Username must be 3–30 characters and use letters, numbers, or underscores.", "error")
        elif len(password) < 10:
            flash("Password must be at least 10 characters.", "error")
        else:
            hashed = generate_password_hash(password, method="scrypt")
            try:
                get_db().execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
                get_db().commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already registered.", "error")
    return render_template_string(PAGE, content=REGISTER)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template_string(PAGE, content=LOGIN)

@app.route("/dashboard")
@login_required
def dashboard():
    username = session.get("username", "User")
    content = f"""<h2>Welcome, {username}!</h2><p>You are logged in to the protected dashboard.</p>
<form method="post" action="/logout"><button type="submit">Log out</button></form>
<h3>Security features</h3><ul><li>Salted scrypt password hashes</li><li>Parameterized SQL queries</li>
<li>Username and password validation</li><li>Protected session dashboard and logout</li><li>Basic security headers</li></ul>"""
    return render_template_string(PAGE, content=content)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
