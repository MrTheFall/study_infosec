import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["DATABASE"] = os.path.join(app.root_path, "data.db")

if not os.path.exists(app.config["DATABASE"]):
    db = sqlite3.connect(app.config["DATABASE"])
    db.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            text TEXT NOT NULL
        );
    """)
    db.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        ("test", generate_password_hash("password", method="scrypt")),
    )
    db.commit()
    db.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        parts = request.headers.get("Authorization", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify(error="Требуется Bearer-токен"), 401
        try:
            payload = jwt.decode(
                parts[1],
                app.config["SECRET_KEY"],
                algorithms=["HS256"],
                options={"require": ["sub", "exp"]},
            )
        except jwt.InvalidTokenError:
            return jsonify(error="Недействительный или просроченный токен"), 401
        user = get_db().execute(
            "SELECT id FROM users WHERE id = ?", (payload["sub"],)
        ).fetchone()
        if user is None:
            return jsonify(error="Пользователь не найден"), 401
        g.user_id = user["id"]
        return view(*args, **kwargs)

    return wrapped


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Ожидается JSON-объект"), 400
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Нужны строки username и password"), 400
    user = get_db().execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Неверный логин или пароль"), 401
    token = jwt.encode(
        {"sub": str(user["id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    return jsonify(access_token=token)


@app.get("/api/data")
@login_required
def get_data():
    rows = get_db().execute(
        "SELECT id, text FROM notes WHERE user_id = ? ORDER BY id", (g.user_id,)
    ).fetchall()
    return jsonify([{"id": row["id"], "text": str(escape(row["text"]))} for row in rows])


@app.post("/api/data")
@login_required
def create_data():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("text"), str):
        return jsonify(error="Нужно строковое поле text"), 400
    text = data["text"]
    if not text.strip() or len(text) > 1000:
        return jsonify(error="Текст: от 1 до 1000 символов"), 400
    db = get_db()
    cursor = db.execute(
        "INSERT INTO notes (user_id, text) VALUES (?, ?)", (g.user_id, text)
    )
    db.commit()
    return jsonify(id=cursor.lastrowid, text=str(escape(text))), 201
