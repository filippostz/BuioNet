import os
import re
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, jsonify, g
from flask_login import login_required, current_user
from app.db import get_main_db, get_workspace_db, init_workspace_db
from config import DATA_DIR
from app.auth import get_user_workspaces
from app.nmap_parser import parse_and_store, compute_scan_changes
from app.alerts_engine import generate_alerts

bp = Blueprint('workspace', __name__)


def can_access_workspace(slug):
    if current_user.is_admin():
        return True
    allowed = get_user_workspaces(current_user.id, current_user.role)
    return any(w['slug'] == slug for w in allowed)


@bp.route('/workspace/<slug>')
@login_required
def detail(slug):
    if not can_access_workspace(slug):
        abort(403)

    conn = get_main_db()
    ws = conn.execute("SELECT * FROM workspaces WHERE slug=?", (slug,)).fetchone()
    conn.close()
    if not ws:
        abort(404)

    latest_scan = None
    scan_count  = 0
    stats       = {}
    try:
        wconn = get_workspace_db(slug)
        latest_raw = wconn.execute(
            "SELECT id, filename, scan_start, total_hosts, upload_time FROM scans ORDER BY upload_time DESC LIMIT 1"
        ).fetchone()
        scan_count = wconn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

        if latest_raw:
            change_count, _ = compute_scan_changes(slug, latest_raw['id'])
            latest_scan = {
                'id':          latest_raw['id'],
                'filename':    latest_raw['filename'],
                'scan_start':  latest_raw['scan_start'],
                'total_hosts': latest_raw['total_hosts'],
                'upload_time': latest_raw['upload_time'],
                'changes':     change_count,
            }

            # Stats from latest scan
            mconn = get_main_db()
            asset_count = mconn.execute(
                "SELECT COUNT(*) FROM asset_sightings WHERE workspace_slug=?", (slug,)
            ).fetchone()[0]
            mconn.close()

            # All open ports from latest scan (for donut chart)
            all_ports = wconn.execute(
                """SELECT p.portid, COALESCE(p.service_name, '?') as svc, COUNT(*) as cnt
                   FROM ports p
                   JOIN hosts h ON h.id = p.host_id
                   WHERE h.scan_id = ? AND p.state = 'open'
                   GROUP BY p.portid, svc
                   ORDER BY cnt DESC""",
                (latest_raw['id'],)
            ).fetchall()

            stats = {
                'asset_count': asset_count,
                'all_ports':   [dict(r) for r in all_ports],
            }

        wconn.close()
    except Exception:
        pass

    return render_template('workspace.html', workspace=ws,
                           latest_scan=latest_scan, scan_count=scan_count, stats=stats)


@bp.route('/workspace/<slug>/history')
@login_required
def history(slug):
    if not can_access_workspace(slug):
        abort(403)

    conn = get_main_db()
    ws = conn.execute("SELECT * FROM workspaces WHERE slug=?", (slug,)).fetchone()
    conn.close()
    if not ws:
        abort(404)

    try:
        wconn = get_workspace_db(slug)
        scans_raw = wconn.execute(
            "SELECT id, filename, scan_start, scan_end, total_hosts, upload_time FROM scans ORDER BY upload_time DESC"
        ).fetchall()
        scans = []
        for s in scans_raw:
            change_count, _ = compute_scan_changes(slug, s['id'])
            scans.append({
                'id':          s['id'],
                'filename':    s['filename'],
                'scan_start':  s['scan_start'],
                'scan_end':    s['scan_end'],
                'total_hosts': s['total_hosts'],
                'upload_time': s['upload_time'],
                'changes':     change_count,
            })
        wconn.close()
    except Exception:
        scans = []

    return render_template('workspace_history.html', workspace=ws, scans=scans)


@bp.route('/workspace/<slug>/trend')
@login_required
def trend_data(slug):
    if not can_access_workspace(slug):
        abort(403)

    try:
        wconn = get_workspace_db(slug)
        scans_raw = wconn.execute(
            "SELECT id, upload_time FROM scans ORDER BY upload_time ASC"
        ).fetchall()
        wconn.close()
    except Exception:
        return jsonify([])

    data = []
    for s in scans_raw:
        count, _ = compute_scan_changes(slug, s['id'])
        data.append({'label': s['upload_time'], 'changes': count})

    return jsonify(data)


@bp.route('/workspace/new', methods=['GET', 'POST'])
@login_required
def new():
    if not current_user.is_admin():
        abort(403)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash('Workspace name is required', 'danger')
            return render_template('workspace_form.html', action='new')

        slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
        if not slug:
            flash('Invalid workspace name', 'danger')
            return render_template('workspace_form.html', action='new')

        conn = get_main_db()
        existing = conn.execute("SELECT id FROM workspaces WHERE slug=?", (slug,)).fetchone()
        if existing:
            slug = slug + '-' + str(conn.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0])

        conn.execute("INSERT INTO workspaces (name, slug, description) VALUES (?, ?, ?)",
                     (name, slug, description))
        conn.commit()
        conn.close()
        init_workspace_db(slug)
        flash(f'Workspace "{name}" created', 'success')
        return redirect(url_for('dashboard.index'))

    return render_template('workspace_form.html', action='new')


@bp.route('/workspace/<slug>/delete', methods=['POST'])
@login_required
def delete(slug):
    if not current_user.is_admin():
        abort(403)

    # Remove workspace record and all main-DB data tied to this slug
    conn = get_main_db()
    conn.execute("DELETE FROM workspaces       WHERE slug=?", (slug,))
    conn.execute("DELETE FROM asset_sightings  WHERE workspace_slug=?", (slug,))
    conn.execute("DELETE FROM alerts           WHERE workspace_slug=?", (slug,))
    conn.commit()
    conn.close()

    # Delete the workspace SQLite file so a new workspace with the same slug
    # starts completely empty instead of inheriting old scan data.
    db_path = os.path.join(DATA_DIR, f"{slug}.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    flash('Workspace deleted', 'success')
    return redirect(url_for('dashboard.index'))


@bp.route('/workspace/<slug>/upload', methods=['POST'])
@login_required
def upload(slug):
    if current_user.is_operator():
        flash('Operators cannot upload scans', 'danger')
        return redirect(url_for('workspace.detail', slug=slug))

    if not can_access_workspace(slug):
        abort(403)

    f = request.files.get('scan_file')
    if not f or not f.filename:
        flash('No file selected', 'danger')
        return redirect(url_for('workspace.detail', slug=slug))

    if not f.filename.lower().endswith('.xml'):
        flash('Only XML files are accepted', 'danger')
        return redirect(url_for('workspace.detail', slug=slug))

    content = f.read()
    try:
        scan_id, new_assets = parse_and_store(content, slug, f.filename)
    except ValueError as e:
        flash(str(e), 'danger')
        return redirect(url_for('workspace.detail', slug=slug))

    generate_alerts(slug, scan_id, new_assets)

    flash('Scan uploaded successfully', 'success')
    return redirect(url_for('workspace.detail', slug=slug))


@bp.route('/workspace/<slug>/tag', methods=['POST'])
@login_required
def tag_host(slug):
    if not can_access_workspace(slug):
        abort(403)
    data = request.get_json()
    ip  = (data or {}).get('ip', '').strip()
    mac = (data or {}).get('mac', '').strip()
    tag = (data or {}).get('tag', '').strip()
    if not ip:
        return jsonify({'error': 'ip required'}), 400

    # Use MAC when available, otherwise synthetic key so MAC-less hosts
    # (e.g. the scanning machine) still participate in the global asset cache
    asset_key = mac if mac else f'ip:{ip}'
    mconn = get_main_db()
    mconn.execute(
        "INSERT INTO global_assets (mac_addr, tag) VALUES (?, ?) "
        "ON CONFLICT(mac_addr) DO UPDATE SET tag=excluded.tag, updated_at=CURRENT_TIMESTAMP",
        (asset_key, tag)
    )
    mconn.commit()
    mconn.close()
    if not mac:
        # Also keep host_tags in sync for backwards compat
        wconn = get_workspace_db(slug)
        if tag:
            wconn.execute("INSERT OR REPLACE INTO host_tags (ip_addr, tag) VALUES (?, ?)", (ip, tag))
        else:
            wconn.execute("DELETE FROM host_tags WHERE ip_addr=?", (ip,))
        wconn.commit()
        wconn.close()

    return jsonify({'status': 'ok'})


@bp.route('/workspace/<slug>/promote', methods=['POST'])
@login_required
def promote_host(slug):
    if not can_access_workspace(slug):
        abort(403)
    data = request.get_json()
    ip = (data or {}).get('ip', '').strip()
    label = (data or {}).get('label', '').strip()
    promote = (data or {}).get('promote', True)

    if not ip:
        return jsonify({'error': 'ip required'}), 400

    wconn = get_workspace_db(slug)
    if promote:
        wconn.execute(
            "INSERT OR REPLACE INTO promoted_hosts (ip_addr, label) VALUES (?, ?)",
            (ip, label)
        )
    else:
        wconn.execute("DELETE FROM promoted_hosts WHERE ip_addr=?", (ip,))
    wconn.commit()
    wconn.close()
    return jsonify({'status': 'ok', 'promoted': promote})


