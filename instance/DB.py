import sqlite3

from app import User, db, app


# Функция для изменения поля пользователя
def update_user_field(user_id, field, new_value):
    with app.app_context():  # Ensure the app context is active
        # Получаем пользователя по ID
        user = User.query.get(user_id)
        if user is None:
            print("Пользователь с указанным ID не найден.")
            return

        # Проверяем, существует ли поле в модели
        if hasattr(user, field):
            setattr(user, field, new_value)
            db.session.commit()
            print("Поле '{}' пользователя с ID {} успешно изменено на '{}'.".format(field, user_id, new_value))
        else:
            print(f"Поле '{field}' не существует в модели User.")


def import_history_of_chat(room_code):
    con = sqlite3.connect('db/blogs.db')
    cur = con.cursor()
    dialog = cur.execute(f'SELECT author, recipient, message, sending_date'
                         f' FROM chats WHERE room_code="{room_code}"').fetchall()
    return dialog


import sqlite3

def downoload_users_datum(user_id, flag=True):
    con = sqlite3.connect('db/blogs.db')
    cur = con.cursor()

    # Выполняем основной запрос к таблице users
    if flag:
        user_data = cur.execute('SELECT id, name, about, rank, banner, email FROM users WHERE id=?', (user_id,)).fetchone()
    else:
        user_data = cur.execute('SELECT id, name FROM users WHERE id=?', (user_id,)).fetchone()

    # Если данные из users найдены, выполняем дополнительный запрос к таблице discord_auth
    if user_data:
        discord_data = cur.execute('SELECT discord_id, rank FROM discord_auth WHERE user_id=?', (user_id,)).fetchone()

        # Если discord_data не пусто, добавляем эти данные в результат
        if discord_data:
            return user_data + discord_data  # Объединяем результаты из обеих таблиц

    return user_data  # Если данных из discord_auth нет, возвращаем только данные из users



def find_news_author(news_id):
    con = sqlite3.connect('db/blogs.db')
    cur = con.cursor()
    return cur.execute(f'SELECT user_id FROM news WHERE id={news_id}').fetchone()


def existing_room(f, s):
    con = sqlite3.connect('db/blogs.db')
    cur = con.cursor()
    rooms_id = f"{max(f, s)}:{min(f, s)}"
    return cur.execute(f'SELECT code FROM rooms WHERE members="{rooms_id}"').fetchone()


# Основная функция программы
def main():
    user_id = input("Введите ID пользователя: ")
    field = input("Введите поле для изменения (name, about, rank, email, hashed_password, created_date): ")
    new_value = input("Введите новое значение: ")

    update_user_field(user_id, field, new_value)


if __name__ == "__main__":
    main()