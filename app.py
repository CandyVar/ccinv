import json
import random
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"
APP_TOKEN = "yandexlyceum_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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
            new_user = User(login=login, password=hashed_password, rank=1, data=json.dumps({}))
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
TIME_LIMIT = 10  # Время в секундах

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
                        "mindel": int(1000/int(user_data["clicker"]["maxdel"])),
                        "maxdel": int(1000/int(user_data["clicker"]["mindel"])),
                        "clickdel": int(user_data["clicker"]["clickdel"]),
                        "mode": user_data["clicker"]["mode"],})
    else:
        return jsonify({"success": False, "msg": id}), 401

aui = {"729CC770": 1}

@app.route('/api/login', methods=['POST'])
def api_login():
    # Проверяем наличие токена в заголовках
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json()

    email = data.get('email')
    ui = data.get('ui')
    password = data.get('password')


    # Находим пользователя по email
    user = User.query.filter(User.login == email).first()

    if user and user.check_password(password) and user.rank > 0:
        aui[ui] = user.id
        return jsonify({"hwid": user.hwid,
                        "id": user.id,
                        "rank": user.rank})
    else:
        return jsonify({"success": False}), 401

@app.route('/api/sethwid', methods=['POST'])
def set_hwid():
    data = request.get_json()

    # Проверяем наличие токена в заголовках
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    email = data.get('email')
    hwid = data.get('hwid')
    password = data.get('password')  # Добавляем поле для пароля

    # Создаем сессию для работы с БД

    # Находим пользователя по email
    user = User.query.filter(User.login == email).first()

    if user:
        # Проверяем правильность пароля
        if user.check_password(password):
            if user.hwid is None or user.hwid == "None":
                user.set_hwid(hwid)
                db.session.commit()
                return jsonify({"success": True, "message": "HWID updated"})
            else:
                return jsonify({"success": False, "message": "HWID already set"}), 400
        else:
            return jsonify({"success": False, "message": "Invalid password"}), 401
    else:
        return jsonify({"success": False, "message": "User not found"}), 404

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
    app.run(debug=True)
