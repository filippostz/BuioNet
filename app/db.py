import sqlite3
import os
from config import MAIN_DB, DATA_DIR


def get_main_db():
    conn = sqlite3.connect(MAIN_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_workspace_db(workspace_slug):
    path = os.path.join(DATA_DIR, f"{workspace_slug}.db")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_main_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = get_main_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'operator',
            active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_workspaces (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, workspace_id)
        );

        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            color TEXT NOT NULL DEFAULT '#4361ee',
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS global_assets (
            mac_addr TEXT PRIMARY KEY,
            tag TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT '',
            hostname TEXT NOT NULL DEFAULT '',
            os_name TEXT NOT NULL DEFAULT '',
            category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS asset_sightings (
            mac_addr TEXT NOT NULL,
            workspace_slug TEXT NOT NULL,
            workspace_name TEXT NOT NULL,
            last_ip TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (mac_addr, workspace_slug)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            workspace_slug TEXT NOT NULL,
            workspace_name TEXT NOT NULL,
            scan_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            host_ip TEXT,
            detail TEXT,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            enabled     INTEGER NOT NULL DEFAULT 1,
            event_type  TEXT NOT NULL,
            filter_json TEXT,
            message     TEXT NOT NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            key_hash     TEXT NOT NULL UNIQUE,
            label        TEXT NOT NULL DEFAULT '',
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME
        );
    """)
    conn.commit()

    # Migrations: add columns to global_assets if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(global_assets)").fetchall()]
    if 'category_id' not in cols:
        conn.execute("ALTER TABLE global_assets ADD COLUMN category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL")
        conn.commit()
    if 'last_mac' not in cols:
        conn.execute("ALTER TABLE global_assets ADD COLUMN last_mac TEXT")
        conn.commit()

    # Seed default alert rules if table is empty
    if conn.execute("SELECT COUNT(*) FROM alert_rules").fetchone()[0] == 0:
        defaults = [
            ('New host detected',    'new_host',    None, 'New host {mac} seen at {ip}'),
            ('Host disappeared',     'host_gone',   None, 'Host {ip} ({hostname}) disappeared'),
            ('Port opened',          'port_opened', None, 'Port {port}/{service} opened on {ip} ({hostname})'),
            ('Port closed',          'port_closed', None, 'Port {port}/{service} closed on {ip} ({hostname})'),
        ]
        conn.executemany(
            "INSERT INTO alert_rules (name, event_type, filter_json, message) VALUES (?,?,?,?)",
            defaults
        )
        conn.commit()

    _migrate_host_tags(conn)
    _scrub_html_values(conn)

    conn.close()


def _scrub_html_values(mconn):
    """Replace any HTML strings or 'None' that got stored in text fields with ''."""
    for col in ('vendor', 'hostname', 'os_name', 'tag'):
        mconn.execute(
            f"UPDATE global_assets SET {col}='' WHERE {col} LIKE '<%' OR {col}='None'"
        )
    mconn.commit()


def _migrate_host_tags(mconn):
    """Migrate legacy host_tags from workspace DBs into global_assets (idempotent)."""
    ws_rows = mconn.execute("SELECT slug FROM workspaces").fetchall()
    for ws in ws_rows:
        slug = ws['slug']
        db_path = os.path.join(DATA_DIR, f"{slug}.db")
        if not os.path.exists(db_path):
            continue
        try:
            wconn = sqlite3.connect(db_path)
            wconn.row_factory = sqlite3.Row
            tags = wconn.execute(
                "SELECT ip_addr, tag FROM host_tags WHERE tag IS NOT NULL AND tag != ''"
            ).fetchall()
            wconn.close()
        except Exception:
            continue
        for row in tags:
            ip, tag = row['ip_addr'], row['tag']
            sighting = mconn.execute(
                "SELECT mac_addr FROM asset_sightings WHERE workspace_slug=? AND last_ip=?",
                (slug, ip)
            ).fetchone()
            mac = sighting['mac_addr'] if sighting else f'ip:{ip}'
            mconn.execute(
                "UPDATE global_assets SET tag=?, updated_at=CURRENT_TIMESTAMP "
                "WHERE mac_addr=? AND (tag IS NULL OR tag='')",
                (tag, mac)
            )
    mconn.commit()


def init_workspace_db(workspace_slug):
    conn = get_workspace_db(workspace_slug)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            scan_start INTEGER,
            scan_end INTEGER,
            scanner TEXT,
            args TEXT,
            total_hosts INTEGER DEFAULT 0,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            ip_addr TEXT NOT NULL,
            mac_addr TEXT,
            vendor TEXT,
            hostname TEXT,
            status TEXT,
            os_name TEXT,
            os_accuracy INTEGER,
            uptime_seconds INTEGER,
            distance INTEGER,
            starttime INTEGER,
            endtime INTEGER
        );

        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            protocol TEXT,
            portid INTEGER,
            state TEXT,
            service_name TEXT,
            service_product TEXT,
            service_version TEXT,
            service_extra TEXT,
            service_method TEXT,
            service_conf INTEGER
        );

        CREATE TABLE IF NOT EXISTS cpes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER REFERENCES ports(id) ON DELETE CASCADE,
            host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
            cpe_string TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS os_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            name TEXT,
            accuracy INTEGER,
            os_type TEXT,
            os_vendor TEXT,
            os_family TEXT,
            os_gen TEXT
        );

        CREATE TABLE IF NOT EXISTS promoted_hosts (
            ip_addr TEXT PRIMARY KEY,
            label TEXT,
            promoted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS host_tags (
            ip_addr TEXT PRIMARY KEY,
            tag TEXT NOT NULL DEFAULT ''
        );
    """)
    conn.commit()
    conn.close()
