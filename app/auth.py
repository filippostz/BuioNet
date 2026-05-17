from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app.db import get_main_db


class User(UserMixin):
    def __init__(self, id, username, role, active):
        self.id = id
        self.username = username
        self.role = role
        self.active = active

    def is_admin(self):
        return self.role == 'admin'

    def is_operator(self):
        return self.role == 'operator'

    def is_api(self):
        return self.role == 'api'

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return bool(self.active)


def load_user(user_id):
    conn = get_main_db()
    row = conn.execute("SELECT id, username, role, active FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if row:
        return User(row['id'], row['username'], row['role'], row['active'])
    return None


def get_user_by_username(username):
    conn = get_main_db()
    row = conn.execute("SELECT id, username, password_hash, role, active FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)


def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256')


def create_default_admin():
    conn = get_main_db()
    existing = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not existing:
        h = hash_password('P4ssw0rd!')
        conn.execute(
            "INSERT INTO users (username, password_hash, role, active) VALUES (?, ?, 'admin', 1)",
            ('admin', h)
        )
        conn.commit()
    conn.close()


def get_user_workspaces(user_id, role):
    conn = get_main_db()
    if role == 'admin':
        rows = conn.execute("SELECT id, name, slug FROM workspaces ORDER BY name").fetchall()
    else:
        rows = conn.execute("""
            SELECT w.id, w.name, w.slug FROM workspaces w
            JOIN user_workspaces uw ON uw.workspace_id = w.id
            WHERE uw.user_id = ? ORDER BY w.name
        """, (user_id,)).fetchall()
    conn.close()
    return rows
