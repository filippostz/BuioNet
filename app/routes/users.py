import hashlib
import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from flask_login import login_required, current_user
from app.db import get_main_db
from app.auth import hash_password

bp = Blueprint('users', __name__)


@bp.route('/users')
@login_required
def index():
    if not current_user.is_admin():
        abort(403)
    conn = get_main_db()
    users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    workspaces = conn.execute("SELECT * FROM workspaces ORDER BY name").fetchall()

    user_ws_map = {}
    for u in users:
        rows = conn.execute(
            "SELECT w.name FROM workspaces w JOIN user_workspaces uw ON uw.workspace_id=w.id WHERE uw.user_id=?",
            (u['id'],)
        ).fetchall()
        user_ws_map[u['id']] = [r['name'] for r in rows]

    new_api_key   = session.pop('pending_api_key',   None)
    new_api_label = session.pop('pending_api_label', None)
    conn.close()
    return render_template('users.html', users=users, workspaces=workspaces,
                           user_ws_map=user_ws_map,
                           new_api_key=new_api_key, new_api_label=new_api_label)


@bp.route('/users/new', methods=['GET', 'POST'])
@login_required
def new():
    if not current_user.is_admin():
        abort(403)
    conn = get_main_db()
    workspaces = conn.execute("SELECT * FROM workspaces ORDER BY name").fetchall()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'operator')
        ws_ids = request.form.getlist('workspace_ids')

        if role not in ('admin', 'operator', 'api'):
            role = 'operator'

        if not username or (not password and role != 'api'):
            flash('Username and password are required', 'danger')
            conn.close()
            return render_template('user_form.html', action='new', workspaces=workspaces)

        existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            flash('Username already exists', 'danger')
            conn.close()
            return render_template('user_form.html', action='new', workspaces=workspaces)

        if role == 'api':
            # API users never log in — generate a random password and an API key
            password = secrets.token_hex(32)
        h = hash_password(password)
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (username, h, role))
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        for wid in ws_ids:
            try:
                conn.execute("INSERT OR IGNORE INTO user_workspaces (user_id, workspace_id) VALUES (?, ?)",
                             (user_id, int(wid)))
            except Exception:
                pass

        if role == 'api':
            raw_key  = 'bn_' + secrets.token_hex(32)
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            conn.execute(
                "INSERT INTO api_keys (user_id, key_hash, label) VALUES (?, ?, ?)",
                (user_id, key_hash, f'{username} (auto)')
            )
            session['pending_api_key']   = raw_key
            session['pending_api_label'] = username

        conn.commit()
        conn.close()
        flash(f'User "{username}" created', 'success')
        return redirect(url_for('users.index'))

    conn.close()
    return render_template('user_form.html', action='new', workspaces=workspaces, user=None)


@bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(user_id):
    if not current_user.is_admin():
        abort(403)
    conn = get_main_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        abort(404)
    workspaces = conn.execute("SELECT * FROM workspaces ORDER BY name").fetchall()
    assigned = {r['workspace_id'] for r in conn.execute(
        "SELECT workspace_id FROM user_workspaces WHERE user_id=?", (user_id,)
    ).fetchall()}

    if request.method == 'POST':
        role = request.form.get('role', user['role'])
        active = 1 if request.form.get('active') else 0
        password = request.form.get('password', '').strip()
        ws_ids = request.form.getlist('workspace_ids')

        if role not in ('admin', 'operator', 'api'):
            role = user['role']

        if password:
            h = hash_password(password)
            conn.execute("UPDATE users SET role=?, active=?, password_hash=? WHERE id=?",
                         (role, active, h, user_id))
        else:
            conn.execute("UPDATE users SET role=?, active=? WHERE id=?",
                         (role, active, user_id))

        conn.execute("DELETE FROM user_workspaces WHERE user_id=?", (user_id,))
        for wid in ws_ids:
            try:
                conn.execute("INSERT OR IGNORE INTO user_workspaces (user_id, workspace_id) VALUES (?, ?)",
                             (user_id, int(wid)))
            except Exception:
                pass

        conn.commit()
        conn.close()
        flash('User updated', 'success')
        return redirect(url_for('users.index'))

    conn.close()
    return render_template('user_form.html', action='edit', user=user,
                           workspaces=workspaces, assigned=assigned)


@bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete(user_id):
    if not current_user.is_admin():
        abort(403)
    if user_id == current_user.id:
        flash('Cannot delete yourself', 'danger')
        return redirect(url_for('users.index'))
    conn = get_main_db()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted', 'success')
    return redirect(url_for('users.index'))
