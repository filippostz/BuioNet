import hashlib
import secrets
from flask import Blueprint, request, jsonify
from functools import wraps
from app.db import get_main_db
from app.auth import get_user_by_username, verify_password, User, get_user_workspaces
from app.nmap_parser import parse_and_store, compute_scan_changes
from app.alerts_engine import generate_alerts

bp = Blueprint('api', __name__, url_prefix='/api/v1')


def _hash_key(raw_key):
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _lookup_api_key(raw_key):
    key_hash = _hash_key(raw_key)
    conn = get_main_db()
    row = conn.execute(
        """SELECT u.id, u.username, u.role, u.active
           FROM api_keys k JOIN users u ON u.id = k.user_id
           WHERE k.key_hash = ?""",
        (key_hash,)
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE api_keys SET last_used_at=CURRENT_TIMESTAMP WHERE key_hash=?",
            (key_hash,)
        )
        conn.commit()
    conn.close()
    return row


def api_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # API key takes priority over Basic Auth
        raw_key = request.headers.get('X-Api-Key')
        if raw_key:
            row = _lookup_api_key(raw_key)
            if not row or not row['active']:
                return jsonify({'error': 'Invalid or inactive API key'}), 401
            user = User(row['id'], row['username'], row['role'], row['active'])
            return f(user, *args, **kwargs)

        # Fall back to HTTP Basic Auth (requires api or admin role)
        auth = request.authorization
        if not auth:
            return jsonify({'error': 'Authentication required'}), 401
        row = get_user_by_username(auth.username)
        if not row or not verify_password(row['password_hash'], auth.password) or not row['active']:
            return jsonify({'error': 'Invalid credentials'}), 401
        if row['role'] not in ('api', 'admin'):
            return jsonify({'error': 'API access not permitted for this role'}), 403
        user = User(row['id'], row['username'], row['role'], row['active'])
        return f(user, *args, **kwargs)
    return decorated


def can_access_workspace(user, slug):
    if user.role == 'admin':
        return True
    allowed = get_user_workspaces(user.id, user.role)
    return any(w['slug'] == slug for w in allowed)


# ── Workspace endpoints ───────────────────────────────────────────────────────

@bp.route('/workspaces')
@api_auth_required
def list_workspaces(user):
    workspaces = get_user_workspaces(user.id, user.role)
    return jsonify([dict(w) for w in workspaces])


@bp.route('/workspace/<slug>/upload', methods=['POST'])
@api_auth_required
def upload_scan(user, slug):
    if not can_access_workspace(user, slug):
        return jsonify({'error': 'Access denied'}), 403

    conn = get_main_db()
    ws = conn.execute("SELECT id FROM workspaces WHERE slug=?", (slug,)).fetchone()
    conn.close()
    if not ws:
        return jsonify({'error': 'Workspace not found'}), 404

    f = request.files.get('scan_file')
    if not f:
        return jsonify({'error': 'No file uploaded'}), 400

    content = f.read()
    try:
        scan_id, new_assets = parse_and_store(content, slug, f.filename or 'upload.xml')
    except ValueError as e:
        return jsonify({'error': str(e)}), 422

    generate_alerts(slug, scan_id, new_assets)
    return jsonify({'scan_id': scan_id, 'status': 'ok'}), 201


@bp.route('/workspace/<slug>/scans')
@api_auth_required
def list_scans(user, slug):
    if not can_access_workspace(user, slug):
        return jsonify({'error': 'Access denied'}), 403

    from app.db import get_workspace_db
    try:
        wconn = get_workspace_db(slug)
        scans = wconn.execute(
            "SELECT id, filename, scan_start, scan_end, total_hosts, upload_time FROM scans ORDER BY upload_time DESC"
        ).fetchall()
        wconn.close()
    except Exception:
        scans = []

    return jsonify([dict(s) for s in scans])


# ── API key management (usable via Basic Auth to bootstrap) ───────────────────

@bp.route('/keys', methods=['GET'])
@api_auth_required
def list_keys(user):
    conn = get_main_db()
    keys = conn.execute(
        "SELECT id, label, created_at, last_used_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
        (user.id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(k) for k in keys])


@bp.route('/keys', methods=['POST'])
@api_auth_required
def create_key(user):
    data  = request.get_json() or {}
    label = data.get('label', '').strip()

    raw_key  = 'bn_' + secrets.token_hex(32)
    key_hash = _hash_key(raw_key)

    conn = get_main_db()
    conn.execute(
        "INSERT INTO api_keys (user_id, key_hash, label) VALUES (?, ?, ?)",
        (user.id, key_hash, label)
    )
    key_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()

    return jsonify({'id': key_id, 'key': raw_key, 'label': label}), 201


@bp.route('/keys/<int:key_id>', methods=['DELETE'])
@api_auth_required
def revoke_key(user, key_id):
    conn = get_main_db()
    row = conn.execute("SELECT user_id FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Key not found'}), 404
    if row['user_id'] != user.id and user.role != 'admin':
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'revoked'})
