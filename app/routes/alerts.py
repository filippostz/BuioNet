from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify
from flask_login import login_required, current_user
from app.db import get_main_db
from app.auth import get_user_workspaces

bp = Blueprint('alerts', __name__)


@bp.route('/alerts')
@login_required
def index():
    conn = get_main_db()
    if current_user.is_admin():
        alerts = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    else:
        allowed = get_user_workspaces(current_user.id, current_user.role)
        ws_ids = [w['id'] for w in allowed]
        if not ws_ids:
            alerts = []
        else:
            placeholders = ','.join('?' * len(ws_ids))
            alerts = conn.execute(
                f"SELECT * FROM alerts WHERE workspace_id IN ({placeholders}) ORDER BY created_at DESC LIMIT 200",
                ws_ids
            ).fetchall()

    unacked_count = sum(1 for a in alerts if not a['acknowledged'])

    # Enrich with hostname + tag via asset_sightings → global_assets
    info_map = {
        (r['last_ip'], r['workspace_slug']): r
        for r in conn.execute("""
            SELECT s.last_ip, s.workspace_slug, ga.hostname, ga.tag
            FROM asset_sightings s
            JOIN global_assets ga ON ga.mac_addr = s.mac_addr
        """).fetchall()
    }
    conn.close()

    enriched = []
    for a in alerts:
        row = dict(a)
        info = dict(info_map.get((a['host_ip'], a['workspace_slug'])) or {})
        row['hostname'] = (info.get('hostname') or '')
        row['tag']      = (info.get('tag')      or '')
        enriched.append(row)

    return render_template('alerts.html', alerts=enriched, unacked_count=unacked_count)


@bp.route('/alerts/<int:alert_id>/ack', methods=['POST'])
@login_required
def acknowledge(alert_id):
    conn = get_main_db()
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('alerts.index'))


@bp.route('/alerts/<int:alert_id>/delete', methods=['POST'])
@login_required
def delete_alert(alert_id):
    conn = get_main_db()
    conn.execute("DELETE FROM alerts WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('alerts.index'))


@bp.route('/alerts/bulk', methods=['POST'])
@login_required
def bulk_action():
    data = request.get_json() or {}
    action = data.get('action')
    ids    = [int(i) for i in data.get('ids', []) if str(i).isdigit()]
    if not ids or action not in ('ack', 'delete'):
        return jsonify({'error': 'invalid request'}), 400
    conn = get_main_db()
    ph   = ','.join('?' * len(ids))
    if action == 'ack':
        conn.execute(f"UPDATE alerts SET acknowledged=1 WHERE id IN ({ph})", ids)
    else:
        conn.execute(f"DELETE FROM alerts WHERE id IN ({ph})", ids)
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@bp.route('/alerts/ack-all', methods=['POST'])
@login_required
def acknowledge_all():
    conn = get_main_db()
    if current_user.is_admin():
        conn.execute("UPDATE alerts SET acknowledged=1")
    else:
        allowed = get_user_workspaces(current_user.id, current_user.role)
        ws_ids = [w['id'] for w in allowed]
        if ws_ids:
            placeholders = ','.join('?' * len(ws_ids))
            conn.execute(
                f"UPDATE alerts SET acknowledged=1 WHERE workspace_id IN ({placeholders})",
                ws_ids
            )
    conn.commit()
    conn.close()
    return redirect(url_for('alerts.index'))


@bp.route('/alerts/count')
@login_required
def count():
    conn = get_main_db()
    if current_user.is_admin():
        c = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
    else:
        allowed = get_user_workspaces(current_user.id, current_user.role)
        ws_ids = [w['id'] for w in allowed]
        if not ws_ids:
            c = 0
        else:
            placeholders = ','.join('?' * len(ws_ids))
            c = conn.execute(
                f"SELECT COUNT(*) FROM alerts WHERE acknowledged=0 AND workspace_id IN ({placeholders})",
                ws_ids
            ).fetchone()[0]
    conn.close()
    return jsonify({'count': c})
