import json
import os
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from werkzeug.security import generate_password_hash

# Import User and db from app.py
from app import app, db, User

def create_users():
    with app.app_context():
        # This logic is copied from app.py
        from app import a
        users_to_create = [
            {"login": "sleme", "rank": 1, "password": "123"},
            {"login": "candyvar", "rank": 100, "password": "222"}
        ]

        for u in users_to_create:
            if not User.query.filter_by(login=u["login"]).first():
                new_user = User(login=u["login"], rank=u["rank"], data=json.dumps(a))
                new_user.set_password(u["password"])
                db.session.add(new_user)
        
        db.session.commit()

def check_users():
    with app.app_context():
        users = User.query.all()
        print(f"Total users: {len(users)}")
        for user in users:
            print(f"ID: {user.id}, Login: {user.login}, Rank: {user.rank}")

if __name__ == "__main__":
    create_users()
    check_users()
