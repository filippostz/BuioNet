import json
from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify
from flask_login import login_required, current_user
from app.db import get_main_db

bp = Blueprint('alert_rules', __name__)

EVENT_TYPES = [
    ('new_host',    'New host detected'),
    ('host_gone',   'Host disappeared'),
    ('port_opened', 'Port opened'),
    ('port_closed', 'Port closed'),
    ('new_asset',   'New asset discovered'),
]

FILTER_TYPES = [
    ('hostname_matches',     'Hostname matches (regex)'),
    ('hostname_not_matches', 'Hostname does NOT match (regex)'),
    ('ip_matches',           'IP matches (regex)'),
    ('mac_prefix',           'MAC starts with'),
    ('vendor_matches',       'Vendor matches (regex)'),
]


@bp.route('/alert-rules')
@login_required
def index():
    conn  = get_main_db()
    rules = conn.execute("SELECT * FROM alert_rules ORDER BY event_type, id").fetchall()
    conn.close()
    enriched = []
    for r in rules:
        row = dict(r)
        try:
            row['filters'] = json.loads(r['filter_json']) if r['filter_json'] else {}
        except Exception:
            row['filters'] = {}
        enriched.append(row)
    return render_template('alert_rules.html',
                           rules=enriched,
                           event_types=EVENT_TYPES,
                           filter_types=FILTER_TYPES)


@bp.route('/alert-rules/new', methods=['POST'])
@login_required
def create():
    if not current_user.is_admin():
        abort(403)
    name       = request.form.get('name', '').strip()
    event_type = request.form.get('event_type', '')
    message    = request.form.get('message', '').strip()
    filter_json = _build_filter_json(request.form)
    if not name or not event_type or not message:
        abort(400)
    conn = get_main_db()
    conn.execute(
        "INSERT INTO alert_rules (name, event_type, filter_json, message) VALUES (?,?,?,?)",
        (name, event_type, filter_json, message)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('alert_rules.index'))


@bp.route('/alert-rules/<int:rule_id>/update', methods=['POST'])
@login_required
def update(rule_id):
    if not current_user.is_admin():
        abort(403)
    name        = request.form.get('name', '').strip()
    event_type  = request.form.get('event_type', '')
    message     = request.form.get('message', '').strip()
    filter_json = _build_filter_json(request.form)
    if not name or not event_type or not message:
        abort(400)
    conn = get_main_db()
    conn.execute(
        "UPDATE alert_rules SET name=?, event_type=?, filter_json=?, message=? WHERE id=?",
        (name, event_type, filter_json, message, rule_id)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('alert_rules.index'))


@bp.route('/alert-rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def toggle(rule_id):
    if not current_user.is_admin():
        abort(403)
    conn = get_main_db()
    conn.execute(
        "UPDATE alert_rules SET enabled = 1 - enabled WHERE id=?", (rule_id,)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('alert_rules.index'))


@bp.route('/alert-rules/<int:rule_id>/delete', methods=['POST'])
@login_required
def delete(rule_id):
    if not current_user.is_admin():
        abort(403)
    conn = get_main_db()
    conn.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('alert_rules.index'))


def _build_filter_json(form):
    """Build filter JSON from submitted filter_key[] / filter_value[] arrays."""
    keys   = form.getlist('filter_key[]')
    values = form.getlist('filter_value[]')
    filters = {}
    for k, v in zip(keys, values):
        k = k.strip()
        v = v.strip()
        if k and v:
            filters[k] = v
    return json.dumps(filters) if filters else None
