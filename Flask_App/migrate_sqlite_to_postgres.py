"""Copy existing local SQLite users into the configured PostgreSQL database."""

import os
from pathlib import Path

from sqlalchemy import create_engine, text

from app import User, app, db


source_path = Path(__file__).resolve().parent / 'instance' / 'users.db'
database_url = os.environ.get('DATABASE_URL')

if not database_url:
    raise RuntimeError('Set DATABASE_URL to the Render PostgreSQL connection string.')

if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql+psycopg://', 1)
elif database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)

source_engine = create_engine(f'sqlite:///{source_path}')
target_engine = create_engine(database_url)

with source_engine.connect() as source_connection, app.app_context():
    db.create_all()
    users = source_connection.execute(
        text('SELECT id, username, password FROM user')
    ).mappings()

    copied = 0
    for source_user in users:
        exists = db.session.execute(
            db.select(User).where(User.username == source_user['username'])
        ).scalar_one_or_none()
        if exists is None:
            db.session.add(User(
                username=source_user['username'],
                password=source_user['password'],
            ))
            copied += 1

    db.session.commit()
    db.session.execute(text(
        "SELECT setval(pg_get_serial_sequence('user', 'id'), "
        "COALESCE((SELECT MAX(id) FROM \"user\"), 1), "
        "(SELECT COUNT(*) > 0 FROM \"user\"))"
    ))
    db.session.commit()

print(f'Migrated {copied} users from {source_path}. Existing users were preserved.')