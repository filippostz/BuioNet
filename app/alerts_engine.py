import json
import re
from app.db import get_main_db
from app.nmap_parser import compute_scan_changes


def _match_filters(change, filter_json):
    if not filter_json:
        return True
    try:
        filters = json.loads(filter_json)
    except Exception:
        return True
    hostname = change.get('hostname') or ''
    ip       = change.get('ip')      or ''
    mac      = change.get('mac')     or ''
    vendor   = change.get('vendor')  or ''
    for key, value in filters.items():
        if key == 'hostname_matches'     and not re.search(value, hostname, re.IGNORECASE):
            return False
        if key == 'hostname_not_matches' and     re.search(value, hostname, re.IGNORECASE):
            return False
        if key == 'ip_matches'           and not re.search(value, ip):
            return False
        if key == 'mac_prefix'           and not mac.upper().startswith(value.upper()):
            return False
        if key == 'vendor_matches'       and not re.search(value, vendor, re.IGNORECASE):
            return False
    return True


def _format_message(template, change):
    try:
        return template.format(
            ip       = change.get('ip',       ''),
            mac      = change.get('mac',      ''),
            hostname = change.get('hostname', ''),
            vendor   = change.get('vendor',   ''),
            port     = change.get('port',     ''),
            service  = change.get('service',  ''),
        )
    except (KeyError, ValueError):
        return template


def generate_alerts(workspace_slug, scan_id, new_assets=None):
    """Evaluate all enabled alert rules against scan changes and new assets."""
    change_count, changes = compute_scan_changes(workspace_slug, scan_id)
    all_events = list(changes) + (new_assets or [])
    if not all_events:
        return

    conn = get_main_db()
    ws = conn.execute(
        "SELECT id, name FROM workspaces WHERE slug=?", (workspace_slug,)
    ).fetchone()
    if not ws:
        conn.close()
        return

    rules = conn.execute("SELECT * FROM alert_rules WHERE enabled=1").fetchall()

    for event in all_events:
        for rule in rules:
            if rule['event_type'] != event['type']:
                continue
            if not _match_filters(event, rule['filter_json']):
                continue
            conn.execute(
                """INSERT INTO alerts (workspace_id, workspace_slug, workspace_name, scan_id,
                   alert_type, message, host_ip) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ws['id'], workspace_slug, ws['name'], scan_id,
                 event['type'], _format_message(rule['message'], event),
                 event.get('ip', ''))
            )

    conn.commit()
    conn.close()
