from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app.db import get_main_db
from app.auth import get_user_workspaces
from app.db import get_workspace_db

bp = Blueprint('dashboard', __name__)


@bp.route('/')
@login_required
def index():
    workspaces_raw = get_user_workspaces(current_user.id, current_user.role)
    workspaces = []
    for ws in workspaces_raw:
        try:
            wconn = get_workspace_db(ws['slug'])
            scan_count = wconn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            last_scan = wconn.execute(
                "SELECT upload_time, total_hosts FROM scans ORDER BY upload_time DESC LIMIT 1"
            ).fetchone()
            wconn.close()
        except Exception:
            scan_count = 0
            last_scan = None

        workspaces.append({
            'id': ws['id'],
            'name': ws['name'],
            'slug': ws['slug'],
            'scan_count': scan_count,
            'last_scan': last_scan['upload_time'] if last_scan else None,
            'asset_count': last_scan['total_hosts'] if last_scan else 0
        })

    return render_template('dashboard.html', workspaces=workspaces)
