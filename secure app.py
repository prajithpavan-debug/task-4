from flask import Flask, render_template_string, request, redirect, session
from flask_bcrypt import Bcrypt
import sqlite3
import re
app = Flask(__name__)
app.secret_key = "change_this_secret_key"
bcrypt = Bcrypt(app)

def db():
    return sqlite3.connect("users.db")

def init_db():
    con = db()
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()

def valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)

def valid_password(password):
    return len(password) >= 8

HTML = """
<h2>{{title}}</h2>
<p style="color:red;">{{msg}}</p>
<form method="POST">
  {% if title == "Register" %}
    <input name="username" placeholder="Username" required><br><br>
    <input name="email" placeholder="Email" required><br><br>
  {% endif %}
  <input name="login" placeholder="Username or Email" required><br><br>
  <input name="password" type="password" placeholder="Password" required><br><br>
  <button type="submit">{{title}}</button>
</form>
<br>
<a href="/register">Register</a> |
<a href="/login">Login</a>
"""

@app.route("/")
def home():
    if "user" in session:
        return f"""
        <h2>Welcome, {session['user']}</h2>
        <p>You are securely logged in.</p>
        <a href='/logout'>Logout</a>
        """
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        if not username or not valid_email(email):
            msg = "Invalid username or email"
        elif not valid_password(password):
            msg = "Password must be at least 8 characters"
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

            try:
                con = db()
                con.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password)
                )
                con.commit()
                con.close()
                return redirect("/login")
            except sqlite3.IntegrityError:
                msg = "Username or email already exists"

    return render_template_string(HTML, title="Register", msg=msg)

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""

    if request.method == "POST":
        login = request.form["login"].strip()
        password = request.form["password"]

        con = db()
        user = con.execute(
            "SELECT username, password FROM users WHERE username = ? OR email = ?",
            (login, login)
        ).fetchone()
        con.close()

        if user and bcrypt.check_password_hash(user[1], password):
            session["user"] = user[0]
            return redirect("/")
        else:
            msg = "Invalid login details"

    return render_template_string(HTML, title="Login", msg=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    init_db()
    app.run(debug=True)