from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user
from app.db import get_main_db
from app.nmap_parser import is_randomized_mac

bp = Blueprint('assets', __name__)


@bp.route('/categories', methods=['GET'])
@login_required
def list_categories():
    conn = get_main_db()
    cats = conn.execute("SELECT * FROM categories ORDER BY display_order, name").fetchall()
    conn.close()
    return jsonify([dict(c) for c in cats])


@bp.route('/categories/new', methods=['POST'])
@login_required
def new_category():
    if not current_user.is_admin():
        abort(403)
    data = request.get_json()
    name  = (data or {}).get('name', '').strip()
    color = (data or {}).get('color', '#4361ee').strip()
    if not name:
        return jsonify({'error': 'name required'}), 400
    conn = get_main_db()
    try:
        conn.execute("INSERT INTO categories (name, color, display_order) VALUES (?, ?, (SELECT COALESCE(MAX(display_order)+1,0) FROM categories))",
                     (name, color))
        conn.commit()
        cat = conn.execute("SELECT * FROM categories WHERE name=?", (name,)).fetchone()
        conn.close()
        return jsonify(dict(cat)), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 409


@bp.route('/categories/reorder', methods=['POST'])
@login_required
def reorder_categories():
    if not current_user.is_admin():
        abort(403)
    ids = (request.get_json() or {}).get('ids', [])
    if not isinstance(ids, list):
        return jsonify({'error': 'ids list required'}), 400
    conn = get_main_db()
    for idx, cat_id in enumerate(ids):
        conn.execute("UPDATE categories SET display_order=? WHERE id=?", (idx, int(cat_id)))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@bp.route('/categories/<int:cat_id>/update', methods=['POST'])
@login_required
def update_category(cat_id):
    if not current_user.is_admin():
        abort(403)
    data          = request.get_json() or {}
    name          = data.get('name', '').strip()
    color         = data.get('color', '').strip()
    display_order = data.get('display_order')
    if not name:
        return jsonify({'error': 'name required'}), 400
    conn = get_main_db()
    try:
        if display_order is not None:
            conn.execute(
                "UPDATE categories SET name=?, color=?, display_order=? WHERE id=?",
                (name, color, int(display_order), cat_id)
            )
        else:
            conn.execute("UPDATE categories SET name=?, color=? WHERE id=?", (name, color, cat_id))
        conn.commit()
        cat = conn.execute("SELECT * FROM categories WHERE id=?", (cat_id,)).fetchone()
        conn.close()
        return jsonify(dict(cat))
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 409


@bp.route('/categories/<int:cat_id>/delete', methods=['POST'])
@login_required
def delete_category(cat_id):
    if not current_user.is_admin():
        abort(403)
    conn = get_main_db()
    conn.execute("DELETE FROM categories WHERE id=?", (cat_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@bp.route('/assets')
@login_required
def index():
    conn = get_main_db()

    assets = conn.execute(
        """SELECT ga.*, c.name as category_name, c.color as category_color
           FROM global_assets ga
           LEFT JOIN categories c ON c.id = ga.category_id
           ORDER BY ga.updated_at DESC"""
    ).fetchall()

    categories = conn.execute(
        "SELECT * FROM categories ORDER BY display_order, name"
    ).fetchall()

    sightings = conn.execute(
        "SELECT mac_addr, workspace_slug, workspace_name, last_ip, last_seen FROM asset_sightings"
    ).fetchall()

    workspaces = conn.execute(
        """SELECT DISTINCT workspace_slug as slug, workspace_name as name
           FROM asset_sightings ORDER BY workspace_name"""
    ).fetchall()

    ip_conflicts = conn.execute(
        """SELECT workspace_name, last_ip, GROUP_CONCAT(DISTINCT mac_addr) as macs
           FROM asset_sightings
           WHERE last_ip IS NOT NULL AND last_ip != ''
           GROUP BY workspace_slug, last_ip
           HAVING COUNT(DISTINCT mac_addr) > 1
           ORDER BY workspace_name, last_ip"""
    ).fetchall()

    hostname_conflicts = conn.execute(
        """SELECT s.workspace_name, ga.hostname, s.last_ip, GROUP_CONCAT(DISTINCT s.mac_addr) as macs
           FROM asset_sightings s
           JOIN global_assets ga ON ga.mac_addr = s.mac_addr
           WHERE ga.hostname IS NOT NULL AND ga.hostname != ''
           GROUP BY s.workspace_slug, ga.hostname, s.last_ip
           HAVING COUNT(DISTINCT s.mac_addr) > 1
           ORDER BY s.workspace_name, ga.hostname"""
    ).fetchall()

    conn.close()

    # Group sightings by MAC; also track the most-recent sighting per asset
    sightings_map = {}
    latest_ip_map = {}  # mac_addr -> last_ip of the most recently seen sighting
    for s in sorted(sightings, key=lambda x: x['last_seen'] or '', reverse=True):
        mac = s['mac_addr']
        sightings_map.setdefault(mac, []).append(dict(s))
        if mac not in latest_ip_map:
            latest_ip_map[mac] = s['last_ip'] or ''

    # Keys whose MAC is locally-administered (randomized) — covers assets stored
    # before hostname:-prefixed keying was introduced
    randomized_mac_keys = {
        a['mac_addr'] for a in assets if is_randomized_mac(a['mac_addr'])
    }

    return render_template('assets.html', assets=assets, categories=categories,
                           sightings_map=sightings_map, latest_ip_map=latest_ip_map,
                           workspaces=workspaces, randomized_mac_keys=randomized_mac_keys,
                           ip_conflicts=ip_conflicts, hostname_conflicts=hostname_conflicts)


@bp.route('/assets/<path:mac>/set-mac', methods=['POST'])
@login_required
def set_mac(mac):
    """Rename an asset's primary key — used to assign a real MAC to a MAC-less host."""
    if not current_user.is_admin() and not current_user.is_operator():
        abort(403)
    data    = request.get_json() or {}
    new_mac = data.get('new_mac', '').strip().upper()
    if not new_mac:
        return jsonify({'error': 'new_mac required'}), 400

    conn = get_main_db()
    try:
        existing = conn.execute("SELECT * FROM global_assets WHERE mac_addr=?", (mac,)).fetchone()
        if not existing:
            conn.close()
            return jsonify({'error': 'asset not found'}), 404

        conflict = conn.execute("SELECT mac_addr FROM global_assets WHERE mac_addr=?", (new_mac,)).fetchone()
        if conflict:
            conn.close()
            return jsonify({'error': f'{new_mac} already exists'}), 409

        # Copy row with new key, then update sightings, then delete old
        conn.execute(
            """INSERT INTO global_assets (mac_addr, tag, vendor, hostname, os_name, category_id, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (new_mac, existing['tag'], existing['vendor'], existing['hostname'],
             existing['os_name'], existing['category_id'])
        )
        conn.execute("UPDATE asset_sightings SET mac_addr=? WHERE mac_addr=?", (new_mac, mac))
        conn.execute("DELETE FROM global_assets WHERE mac_addr=?", (mac,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok', 'mac_addr': new_mac})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500


@bp.route('/assets/<path:mac>/update', methods=['POST'])
@login_required
def update(mac):
    if not current_user.is_admin() and not current_user.is_operator():
        abort(403)
    data = request.get_json()
    fields = {k: v for k, v in (data or {}).items()
              if k in ('tag', 'vendor', 'hostname', 'os_name', 'category_id')}
    if not fields:
        return jsonify({'error': 'nothing to update'}), 400

    sets   = ', '.join(f"{k}=?" for k in fields)
    values = list(fields.values()) + [mac]
    conn   = get_main_db()
    conn.execute(
        f"UPDATE global_assets SET {sets}, updated_at=CURRENT_TIMESTAMP WHERE mac_addr=?",
        values
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@bp.route('/assets/<path:mac>/delete', methods=['POST'])
@login_required
def delete(mac):
    if not current_user.is_admin():
        abort(403)
    conn = get_main_db()
    conn.execute("DELETE FROM global_assets WHERE mac_addr=?", (mac,))
    conn.execute("DELETE FROM asset_sightings WHERE mac_addr=?", (mac,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@bp.route('/assets/bulk-delete', methods=['POST'])
@login_required
def bulk_delete():
    if not current_user.is_admin():
        abort(403)
    macs = (request.get_json() or {}).get('macs', [])
    if not macs or not isinstance(macs, list):
        return jsonify({'error': 'macs list required'}), 400
    conn = get_main_db()
    placeholders = ','.join('?' * len(macs))
    conn.execute(f"DELETE FROM global_assets   WHERE mac_addr IN ({placeholders})", macs)
    conn.execute(f"DELETE FROM asset_sightings WHERE mac_addr IN ({placeholders})", macs)
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok', 'deleted': len(macs)})


@bp.route('/assets/bulk-update', methods=['POST'])
@login_required
def bulk_update():
    if not current_user.is_admin() and not current_user.is_operator():
        abort(403)
    data     = request.get_json() or {}
    macs     = data.get('macs', [])
    cat_id   = data.get('category_id')
    if not macs or not isinstance(macs, list):
        return jsonify({'error': 'macs list required'}), 400
    conn = get_main_db()
    placeholders = ','.join('?' * len(macs))
    conn.execute(
        f"UPDATE global_assets SET category_id=?, updated_at=CURRENT_TIMESTAMP "
        f"WHERE mac_addr IN ({placeholders})",
        [cat_id] + macs
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok', 'updated': len(macs)})
