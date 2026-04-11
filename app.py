import json
import os
import random
import base64
import hashlib
import hmac
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = "supersecretkey"
APP_TOKEN = "yandexlyceum_secret_key"
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
API_KEY = b"2SWbBqWJi4mRTEmnbgSX5j08etbSbQ/w"
UPDATE_FILE_NAME = os.getenv("UPDATE_FILE_NAME", "awesomeProject.exe")
UPDATE_VERSION = os.getenv("UPDATE_VERSION", "1.0.0")
UPDATE_SIGN_SECRET = os.getenv("UPDATE_SIGN_SECRET", "candy_update_sign_secret_v1_change_me")


def _pkcs7_pad(data: bytes, block_size: int = AES.block_size) -> bytes:
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = AES.block_size) -> bytes:
    if not data:
        raise ValueError("empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("bad padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad padding bytes")
    return data[:-pad_len]


def encrypt_payload(obj: dict) -> str:
    plaintext = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(API_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(_pkcs7_pad(plaintext))
    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_payload(data_b64: str) -> dict:
    raw = base64.b64decode(data_b64)
    if len(raw) < AES.block_size:
        raise ValueError("payload too short")
    iv = raw[:AES.block_size]
    ciphertext = raw[AES.block_size:]
    cipher = AES.new(API_KEY, AES.MODE_CBC, iv)
    plain = cipher.decrypt(ciphertext)
    return json.loads(_pkcs7_unpad(plain).decode("utf-8"))


def encrypted_response(payload: dict, status: int = 200):
    return jsonify({"data": encrypt_payload(payload)}), status


def parse_encrypted_request():
    data = request.get_json(silent=True) or {}
    encrypted = data.get("data")
    if not isinstance(encrypted, str) or not encrypted:
        return None, encrypted_response({"success": False, "message": "encrypted field 'data' is required"}, 400)
    try:
        return decrypt_payload(encrypted), None
    except Exception:
        return None, encrypted_response({"success": False, "message": "invalid encrypted payload"}, 400)


def file_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def sign_update_payload(version: str, sha256_hex: str, file_name: str) -> str:
    message = f"{version}|{sha256_hex}|{file_name}".encode("utf-8")
    signature = hmac.new(UPDATE_SIGN_SECRET.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.b64encode(signature).decode("utf-8")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
ADMINS = 5
SYS = 100


# Модели базы данных
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    rank = db.Column(db.Integer, default=0)
    data = db.Column(db.Text, default=json.dumps({}))
    hwid = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<User> {self.id} {self.login} {self.rank} {self.hwid} {self.data}'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def set_hwid(self, hwid):
        self.hwid = hwid

    def check_password(self, password_input):
        return check_password_hash(self.password, password_input)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        if User.query.filter_by(login=login).first():
            error = 'Логин уже существует!'
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(login=login, password=hashed_password, rank=0, data=json.dumps({}))
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('r1.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect("/")
        error = 'Неверные учетные данные!'
    return render_template('l1.html', error=error)


# Для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def clicker():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    user = User.query.get(current_user.id)
    user_data = json.loads(user.data) if user else {}
    clicker_data = user_data.get("clicker", {})

    if request.method == 'POST':
        clicker_data.update({
            "mindel": int(request.form.get('mindel', clicker_data.get("mindel", 1))),
            "maxdel": int(request.form.get('maxdel', clicker_data.get("maxdel", 1))),
            "clickdel": int(request.form.get('clickdel', clicker_data.get("clickdel", 0))),
            "mode": request.form.get('mode', clicker_data.get("mode", "default"))
        })
        user.data = json.dumps(user_data)
        db.session.commit()
        return '<script>location.reload();</script>'

    return render_template('clicker.html', **clicker_data)


from datetime import datetime, timedelta
from collections import defaultdict
import time

# Словарь для хранения времени последних запросов по IP
request_times = defaultdict(list)
# Максимальное количество запросов за интервал (например, 5 запросов за 10 секунд)
MAX_REQUESTS = 5
TIME_LIMIT = 11  # Время в секундах


@app.route('/api/cl', methods=['POST'])
def api_clikcer():
    # Получаем IP-адрес пользователя
    ip_address = request.remote_addr
    current_time = time.time()
    request_times[ip_address] = [t for t in request_times[ip_address] if current_time - t < TIME_LIMIT]
    if len(request_times[ip_address]) >= MAX_REQUESTS:
        return jsonify({"success": False, "message": "Too many requests, please try again later."}), 429

    request_times[ip_address].append(current_time)
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    data = request.get_json()

    ui = data.get('ui')
    id1 = aui[ui]
    id = data.get('id')

    user = User.query.filter(User.id == id1).first()
    user_data = json.loads(user.data)

    if user and user.rank > 0 and user_data:
        return jsonify({"hwid": user.hwid,
                        "id": user.id,
                        "rank": user.rank,
                        "mindel": int(1000 / int(user_data["clicker"]["maxdel"])),
                        "maxdel": int(1000 / int(user_data["clicker"]["mindel"])),
                        "clickdel": int(user_data["clicker"]["clickdel"]),
                        "mode": user_data["clicker"]["mode"], })
    else:
        return jsonify({"success": False, "msg": id}), 401


aui = {}


@app.route('/api/login', methods=['POST'])
def api_login():
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return encrypted_response({"success": False, "message": "Unauthorized"}, 403)

    data, err = parse_encrypted_request()
    if err:
        return err

    email = data.get('email')
    ui = data.get('ui')
    password = data.get('password')

    # Находим пользователя по email
    user = User.query.filter(User.login == email).first()

    if user and user.check_password(password) and user.rank > 0:
        aui[ui] = user.id
        return encrypted_response({"hwid": user.hwid,
                                   "id": user.id,
                                   "rank": user.rank})
    else:
        return encrypted_response({"success": False}, 401)


@app.route('/api/sethwid', methods=['POST'])
def set_hwid():
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return encrypted_response({"success": False, "message": "Unauthorized"}, 403)

    data, err = parse_encrypted_request()
    if err:
        return err

    email = data.get('email')
    hwid = data.get('hwid')
    password = data.get('password')
    user = User.query.filter(User.login == email).first()

    if user:
        if user.check_password(password):
            if user.hwid is None or user.hwid == "None":
                user.set_hwid(hwid)
                db.session.commit()
                return encrypted_response({"success": True, "message": "HWID updated"})
            else:
                return encrypted_response({"success": False, "message": "HWID already set"}, 400)
        else:
            return encrypted_response({"success": False, "message": "Invalid password"}, 401)
    else:
        return encrypted_response({"success": False, "message": "User not found"}, 404)


@app.route('/api/update-manifest', methods=['POST'])
def api_update_manifest():
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return encrypted_response({"success": False, "message": "Unauthorized"}, 403)

    data, err = parse_encrypted_request()
    if err:
        return err

    hwid = data.get('hwid')
    if not hwid:
        return encrypted_response({"success": False, "message": "hwid is required"}, 400)

    file_path = os.path.join(basedir, UPDATE_FILE_NAME)
    if not os.path.exists(file_path):
        return encrypted_response({"success": False, "message": "update file not found"}, 404)

    try:
        sha = file_sha256(file_path)
        sig = sign_update_payload(UPDATE_VERSION, sha, UPDATE_FILE_NAME)
    except Exception as e:
        return encrypted_response({"success": False, "message": f"signing failed: {e}"}, 500)

    return encrypted_response({
        "success": True,
        "latest_version": UPDATE_VERSION,
        "latest_hash": sha,
        "file_name": UPDATE_FILE_NAME,
        "signature": sig
    })


@app.route('/api/update-file', methods=['POST'])
def api_update_file():
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return encrypted_response({"success": False, "message": "Unauthorized"}, 403)

    data, err = parse_encrypted_request()
    if err:
        return err

    hwid = data.get('hwid')
    if not hwid:
        return encrypted_response({"success": False, "message": "hwid is required"}, 400)

    file_path = os.path.join(basedir, UPDATE_FILE_NAME)
    if not os.path.exists(file_path):
        return encrypted_response({"success": False, "message": "update file not found"}, 404)

    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        sha = hashlib.sha256(raw).hexdigest()
        sig = sign_update_payload(UPDATE_VERSION, sha, UPDATE_FILE_NAME)
    except Exception as e:
        return encrypted_response({"success": False, "message": f"failed to prepare update: {e}"}, 500)

    return encrypted_response({
        "success": True,
        "version": UPDATE_VERSION,
        "file_name": UPDATE_FILE_NAME,
        "sha256": sha,
        "signature": sig,
        "file_data": base64.b64encode(raw).decode("utf-8")
    })


a = {
    "clicker": {
        "mindel": 0,
        "maxdel": 0,
        "clickdel": 0,
        "mode": "legit"
    }
}


@app.route('/uedit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.rank < ADMINS:
        return '<script>document.location.href = document.referrer</script>'
    user = User.query.filter(User.id == user_id).first()

    if not user:
        return '<script>document.location.href = document.referrer</script>'

    if request.method == 'POST':
        user.login = request.form.get('login')
        user.hwid = request.form.get('hwid')
        user.rank = int(request.form.get('rank'))

        user.data = request.form.get('data')

        if request.form.get('password'):
            user.set_password(request.form.get('password'))

        db.session.commit()
        return '<script>document.location.href = document.referrer</script>'

    return render_template('users_edit.html', user=user, admin=ADMINS, sys=SYS)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.rank < ADMINS:
        return '<script>document.location.href = document.referrer</script>'

    user = User.query.filter(User.id == user_id).first()

    if user:
        db.session.delete(user)
        db.session.commit()
        return '<script>document.location.href = "/users_list"</script>'  # перенаправление на страницу списка пользователей
    else:
        return '<script>document.location.href = document.referrer</script>'


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Создание таблиц в базе данных

        # Создание пользователей
        users_to_create = [
            {"login": "sleme", "rank": 1, "password": "imamtrash"},
            {"login": "candyvar", "rank": 100, "password": "Lollipop!!123123"}
        ]

        for u in users_to_create:
            if not User.query.filter_by(login=u["login"]).first():
                new_user = User(login=u["login"], rank=u["rank"], data=json.dumps(a))
                new_user.set_password(u["password"])
                db.session.add(new_user)

        db.session.commit()

    app.run(debug=True)
