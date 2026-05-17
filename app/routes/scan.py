from flask import Blueprint, render_template, abort, jsonify, redirect, url_for
from flask_login import login_required, current_user
from app.db import get_main_db, get_workspace_db
from app.auth import get_user_workspaces
from app.nmap_parser import get_scan_graph_data, compute_scan_changes

bp = Blueprint('scan', __name__)


def can_access_workspace(slug):
    if current_user.is_admin():
        return True
    allowed = get_user_workspaces(current_user.id, current_user.role)
    return any(w['slug'] == slug for w in allowed)


@bp.route('/workspace/<slug>/scan/<int:scan_id>')
@login_required
def view(slug, scan_id):
    if not can_access_workspace(slug):
        abort(403)

    conn = get_main_db()
    ws = conn.execute("SELECT * FROM workspaces WHERE slug=?", (slug,)).fetchone()
    conn.close()
    if not ws:
        abort(404)

    wconn = get_workspace_db(slug)
    scan = wconn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    wconn.close()
    if not scan:
        abort(404)

    change_count, changes = compute_scan_changes(slug, scan_id)

    return render_template('scan_view.html',
                           workspace=ws,
                           scan=scan,
                           scan_id=scan_id,
                           change_count=change_count,
                           changes=changes)


@bp.route('/workspace/<slug>/scan/<int:scan_id>/graph-data')
@login_required
def graph_data(slug, scan_id):
    if not can_access_workspace(slug):
        abort(403)
    data = get_scan_graph_data(slug, scan_id)
    return jsonify(data)


@bp.route('/workspace/<slug>/scan/<int:scan_id>/hosts')
@login_required
def hosts_list(slug, scan_id):
    if not can_access_workspace(slug):
        abort(403)

    wconn = get_workspace_db(slug)
    hosts = wconn.execute(
        "SELECT h.*, GROUP_CONCAT(p.portid || '/' || COALESCE(p.service_name,'?'), ', ') as open_ports "
        "FROM hosts h LEFT JOIN ports p ON p.host_id=h.id AND p.state='open' "
        "WHERE h.scan_id=? GROUP BY h.id ORDER BY h.ip_addr",
        (scan_id,)
    ).fetchall()
    wconn.close()

    return jsonify([dict(h) for h in hosts])


@bp.route('/workspace/<slug>/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete(slug, scan_id):
    if not current_user.is_admin():
        abort(403)
    if not can_access_workspace(slug):
        abort(403)

    wconn = get_workspace_db(slug)
    # CASCADE in schema deletes hosts → ports → cpes, os_matches automatically
    wconn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    wconn.commit()

    # Rebuild asset_sightings for this workspace from the remaining hosts so the
    # asset count stays in sync after scan deletion.
    remaining_keys = {
        (row['mac_addr'] if row['mac_addr'] else f"ip:{row['ip_addr']}")
        for row in wconn.execute(
            "SELECT DISTINCT ip_addr, mac_addr FROM hosts"
        ).fetchall()
    }
    wconn.close()

    mconn = get_main_db()
    existing_sightings = {
        row['mac_addr']
        for row in mconn.execute(
            "SELECT mac_addr FROM asset_sightings WHERE workspace_slug=?", (slug,)
        ).fetchall()
    }
    orphans = existing_sightings - remaining_keys
    for key in orphans:
        mconn.execute(
            "DELETE FROM asset_sightings WHERE workspace_slug=? AND mac_addr=?",
            (slug, key)
        )
    mconn.commit()
    mconn.close()

    return redirect(url_for('workspace.history', slug=slug))
