import hashlib
import secrets
from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user
from app.db import get_main_db

bp = Blueprint('api_keys', __name__)


def _hash_key(raw_key):
    return hashlib.sha256(raw_key.encode()).hexdigest()


@bp.route('/api-keys')
@login_required
def index():
    conn = get_main_db()
    keys = conn.execute(
        "SELECT id, label, created_at, last_used_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
        (current_user.id,)
    ).fetchall()
    conn.close()
    return render_template('api_keys.html', keys=keys)


@bp.route('/api-keys/create', methods=['POST'])
@login_required
def create():
    data  = request.get_json() or {}
    label = data.get('label', '').strip()

    raw_key  = 'bn_' + secrets.token_hex(32)
    key_hash = _hash_key(raw_key)

    conn = get_main_db()
    conn.execute(
        "INSERT INTO api_keys (user_id, key_hash, label) VALUES (?, ?, ?)",
        (current_user.id, key_hash, label)
    )
    key_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()

    return jsonify({'id': key_id, 'key': raw_key, 'label': label}), 201


@bp.route('/api-keys/<int:key_id>/revoke', methods=['POST'])
@login_required
def revoke(key_id):
    conn = get_main_db()
    row = conn.execute("SELECT user_id FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Key not found'}), 404
    if row['user_id'] != current_user.id and not current_user.is_admin():
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'revoked'})
