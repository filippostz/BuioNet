import xml.etree.ElementTree as ET
from app.db import get_workspace_db, init_workspace_db, get_main_db


def is_randomized_mac(mac: str) -> bool:
    """Return True if the MAC address uses the locally-administered (randomized) bit."""
    if not mac or ':' not in mac:
        return False
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except ValueError:
        return False


def _resolve_by_hostname(mconn, hostname: str):
    """Find the best stable asset key that already has this hostname.

    Priority: real MAC > hostname: key > ip: key.
    Used to de-duplicate randomized-MAC devices across scans.
    """
    row = mconn.execute(
        """SELECT mac_addr FROM global_assets
           WHERE hostname = ? AND hostname != ''
           ORDER BY CASE
             WHEN mac_addr NOT LIKE 'ip:%' AND mac_addr NOT LIKE 'hostname:%' THEN 0
             WHEN mac_addr LIKE 'hostname:%' THEN 1
             ELSE 2
           END
           LIMIT 1""",
        (hostname,)
    ).fetchone()
    return row['mac_addr'] if row else None


def _upsert_global_asset(mconn, mac, vendor, hostname, os_name, workspace_slug, workspace_name, ip):
    """Insert or carefully update global_assets — never overwrite user-set fields."""
    mconn.execute(
        "INSERT OR IGNORE INTO global_assets (mac_addr, vendor, hostname, os_name) VALUES (?, ?, ?, ?)",
        (mac, vendor, hostname, os_name)
    )
    mconn.execute(
        """UPDATE global_assets SET
             vendor   = CASE WHEN vendor   = '' THEN ? ELSE vendor   END,
             hostname = CASE WHEN hostname = '' THEN ? ELSE hostname END,
             os_name  = CASE WHEN os_name  = '' THEN ? ELSE os_name  END,
             updated_at = CURRENT_TIMESTAMP
           WHERE mac_addr = ?""",
        (vendor, hostname, os_name, mac)
    )
    mconn.execute(
        """INSERT INTO asset_sightings (mac_addr, workspace_slug, workspace_name, last_ip, last_seen)
           VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(mac_addr, workspace_slug) DO UPDATE SET
             last_ip   = excluded.last_ip,
             last_seen = CURRENT_TIMESTAMP""",
        (mac, workspace_slug, workspace_name, ip)
    )


def parse_and_store(xml_content, workspace_slug, filename):
    init_workspace_db(workspace_slug)
    conn = get_workspace_db(workspace_slug)
    mconn = get_main_db()

    ws_row = mconn.execute(
        "SELECT name FROM workspaces WHERE slug=?", (workspace_slug,)
    ).fetchone()
    workspace_name = ws_row['name'] if ws_row else workspace_slug

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        conn.close()
        mconn.close()
        raise ValueError(f"Invalid XML: {e}")

    scanner = root.get('scanner', '')
    args = root.get('args', '')
    start = root.get('start')
    startstr = root.get('startstr', '')

    runstats = root.find('runstats')
    finished = runstats.find('finished') if runstats is not None else None
    scan_end = int(finished.get('time', 0)) if finished is not None else None
    scan_start = int(start) if start else None

    hosts_el = root.findall('host')
    total_hosts = len(hosts_el)

    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (filename, scan_start, scan_end, scanner, args, total_hosts) VALUES (?, ?, ?, ?, ?, ?)",
        (filename, scan_start, scan_end, scanner, args, total_hosts)
    )
    scan_id = c.lastrowid

    for host_el in hosts_el:
        status_el = host_el.find('status')
        status = status_el.get('state', 'unknown') if status_el is not None else 'unknown'

        ip_addr = None
        mac_addr = None
        vendor = None

        for addr_el in host_el.findall('address'):
            atype = addr_el.get('addrtype', '')
            if atype == 'ipv4':
                ip_addr = addr_el.get('addr')
            elif atype == 'mac':
                mac_addr = addr_el.get('addr')
                vendor = addr_el.get('vendor', '')

        if not ip_addr:
            continue

        hostnames_el = host_el.find('hostnames')
        hostname = None
        if hostnames_el is not None:
            hn = hostnames_el.find('hostname')
            if hn is not None:
                hostname = hn.get('name')

        uptime_el = host_el.find('uptime')
        uptime_seconds = int(uptime_el.get('seconds', 0)) if uptime_el is not None else None

        distance_el = host_el.find('distance')
        distance = int(distance_el.get('value', 0)) if distance_el is not None else None

        starttime = host_el.get('starttime')
        endtime = host_el.get('endtime')

        os_name = None
        os_accuracy = None
        os_el = host_el.find('os')

        c.execute(
            """INSERT INTO hosts (scan_id, ip_addr, mac_addr, vendor, hostname, status,
               os_name, os_accuracy, uptime_seconds, distance, starttime, endtime)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, ip_addr, mac_addr, vendor, hostname, status,
             os_name, os_accuracy, uptime_seconds, distance,
             int(starttime) if starttime else None,
             int(endtime) if endtime else None)
        )
        host_id = c.lastrowid

        if os_el is not None:
            for osmatch in os_el.findall('osmatch'):
                m_name = osmatch.get('name')
                m_acc = osmatch.get('accuracy')
                if not os_name:
                    os_name = m_name
                    os_accuracy = int(m_acc) if m_acc else None

                for osclass in osmatch.findall('osclass'):
                    c.execute(
                        """INSERT INTO os_matches (host_id, name, accuracy, os_type, os_vendor, os_family, os_gen)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (host_id, m_name, m_acc,
                         osclass.get('type'), osclass.get('vendor'),
                         osclass.get('osfamily'), osclass.get('osgen'))
                    )

            c.execute("UPDATE hosts SET os_name=?, os_accuracy=? WHERE id=?",
                      (os_name, os_accuracy, host_id))

        ports_el = host_el.find('ports')
        if ports_el is not None:
            for port_el in ports_el.findall('port'):
                protocol = port_el.get('protocol')
                portid = int(port_el.get('portid', 0))

                state_el = port_el.find('state')
                state = state_el.get('state') if state_el is not None else 'unknown'

                svc_el = port_el.find('service')
                svc_name = svc_product = svc_version = svc_extra = svc_method = None
                svc_conf = None
                if svc_el is not None:
                    svc_name = svc_el.get('name')
                    svc_product = svc_el.get('product')
                    svc_version = svc_el.get('version')
                    svc_extra = svc_el.get('extrainfo')
                    svc_method = svc_el.get('method')
                    svc_conf = svc_el.get('conf')

                c.execute(
                    """INSERT INTO ports (host_id, protocol, portid, state, service_name,
                       service_product, service_version, service_extra, service_method, service_conf)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (host_id, protocol, portid, state, svc_name,
                     svc_product, svc_version, svc_extra, svc_method,
                     int(svc_conf) if svc_conf else None)
                )
                port_id = c.lastrowid

                if svc_el is not None:
                    for cpe_el in svc_el.findall('cpe'):
                        c.execute("INSERT INTO cpes (port_id, cpe_string) VALUES (?, ?)",
                                  (port_id, cpe_el.text))

    conn.commit()
    conn.close()

    # Feed global asset cache for every host.
    # Hosts without a MAC (e.g. the scanning machine itself) use a synthetic
    # key "ip:<addr>" so they can still be tagged and categorized.
    hosts_data = get_workspace_db(workspace_slug).execute(
        "SELECT ip_addr, mac_addr, vendor, hostname, os_name FROM hosts WHERE scan_id=?",
        (scan_id,)
    ).fetchall()
    # Fetch workspace-level tags to migrate legacy host_tags → global_assets
    wconn2 = get_workspace_db(workspace_slug)
    local_tags_for_migration = {
        r['ip_addr']: r['tag']
        for r in wconn2.execute(
            "SELECT ip_addr, tag FROM host_tags WHERE tag IS NOT NULL AND tag != ''"
        ).fetchall()
    }
    wconn2.close()

    # Snapshot existing keys so we can detect brand-new assets after upsert
    existing_keys = {
        r[0] for r in mconn.execute("SELECT mac_addr FROM global_assets").fetchall()
    }

    new_assets = []
    for h in hosts_data:
        raw_mac        = h['mac_addr'] or ''
        ip             = h['ip_addr']
        hostname       = h['hostname'] or ''
        last_mac_to_set = None

        if raw_mac and not is_randomized_mac(raw_mac):
            # ── Real, globally-unique MAC ─────────────────────────────────────
            key    = raw_mac
            is_new = key not in existing_keys

        elif raw_mac:
            # ── Randomized (locally-administered) MAC ─────────────────────────
            # The MAC will change on the next rotation; use a stable key instead.

            if raw_mac in existing_keys:
                # Same randomized MAC seen before — reuse the existing asset directly.
                key    = raw_mac
                is_new = False
                resolved = raw_mac
            else:
                # Try to find a stable key via hostname, then via workspace sighting.
                resolved = _resolve_by_hostname(mconn, hostname) if hostname else None
                if not resolved:
                    row = mconn.execute(
                        """SELECT mac_addr FROM asset_sightings
                           WHERE workspace_slug = ? AND last_ip = ?
                           LIMIT 1""",
                        (workspace_slug, ip)
                    ).fetchone()
                    if row:
                        resolved = row['mac_addr']

                if resolved:
                    key    = resolved
                    is_new = False
                else:
                    key    = f'hostname:{hostname}' if hostname else f'ip:{ip}'
                    is_new = key not in existing_keys

            # Clean up a stale ip: entry for this IP if we resolved to something better
            if resolved and resolved != f'ip:{ip}':
                stale = f'ip:{ip}'
                if stale in existing_keys:
                    mconn.execute("DELETE FROM global_assets WHERE mac_addr=?", (stale,))
                    mconn.execute("DELETE FROM asset_sightings WHERE mac_addr=?", (stale,))
                    existing_keys.discard(stale)

            last_mac_to_set = raw_mac  # persist after upsert ensures the row exists

        else:
            # ── No MAC (nmap omits the scanner host's own MAC) ────────────────
            resolved = None

            # 1. Match by hostname + IP (prefers non-ip: keys)
            if hostname:
                row = mconn.execute(
                    """SELECT ga.mac_addr
                       FROM global_assets ga
                       JOIN asset_sightings s ON s.mac_addr = ga.mac_addr
                       WHERE ga.hostname = ? AND s.last_ip = ?
                         AND ga.mac_addr NOT LIKE 'ip:%'
                       LIMIT 1""",
                    (hostname, ip)
                ).fetchone()
                if row:
                    resolved = row['mac_addr']

            # 2. Fallback: any sighting for this workspace with the same IP —
            #    avoids creating a duplicate ip: asset when the host is already
            #    tracked (possibly under a real MAC) in this workspace.
            if not resolved:
                row = mconn.execute(
                    """SELECT mac_addr FROM asset_sightings
                       WHERE workspace_slug = ? AND last_ip = ?
                       LIMIT 1""",
                    (workspace_slug, ip)
                ).fetchone()
                if row:
                    resolved = row['mac_addr']

            if resolved:
                key    = resolved
                is_new = False
                stale  = f'ip:{ip}'
                if stale in existing_keys and stale != resolved:
                    mconn.execute("DELETE FROM global_assets WHERE mac_addr=?", (stale,))
                    mconn.execute("DELETE FROM asset_sightings WHERE mac_addr=?", (stale,))
                    existing_keys.discard(stale)
            else:
                key    = f'ip:{ip}'
                is_new = key not in existing_keys

        _upsert_global_asset(
            mconn,
            key,
            h['vendor'] or '',
            hostname,
            h['os_name'] or '',
            workspace_slug,
            workspace_name,
            ip
        )
        if last_mac_to_set:
            mconn.execute(
                "UPDATE global_assets SET last_mac=? WHERE mac_addr=?",
                (last_mac_to_set, key)
            )
        # Sync any legacy host_tag for this IP into global_assets if tag is empty
        local_tag = local_tags_for_migration.get(ip)
        if local_tag:
            mconn.execute(
                "UPDATE global_assets SET tag=?, updated_at=CURRENT_TIMESTAMP "
                "WHERE mac_addr=? AND (tag IS NULL OR tag='')",
                (local_tag, key)
            )
        if is_new:
            new_assets.append({
                'type':     'new_asset',
                'ip':       ip,
                'mac':      raw_mac,
                'hostname': hostname,
                'vendor':   h['vendor'] or '',
                'port':     '',
                'service':  '',
            })

    mconn.commit()
    mconn.close()

    return scan_id, new_assets


def get_scan_graph_data(workspace_slug, scan_id):
    conn  = get_workspace_db(workspace_slug)
    mconn = get_main_db()

    hosts = conn.execute(
        "SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)
    ).fetchall()

    promoted = {
        r['ip_addr']: True
        for r in conn.execute("SELECT ip_addr FROM promoted_hosts").fetchall()
    }

    # Load full global asset records keyed by MAC
    global_cache = {
        r['mac_addr']: dict(r)
        for r in mconn.execute(
            "SELECT ga.mac_addr, ga.tag, ga.vendor, ga.hostname, ga.os_name, "
            "ga.category_id, c.name as category_name, c.color as category_color "
            "FROM global_assets ga LEFT JOIN categories c ON c.id = ga.category_id"
        ).fetchall()
    }

    # Secondary lookup by last_ip — covers hosts whose MAC was manually assigned
    # after the scan (hosts table still has mac_addr=NULL).
    # Real MACs always win over synthetic ip: keys for the same IP.
    ip_cache = {}
    for r in mconn.execute(
        "SELECT mac_addr, last_ip FROM asset_sightings WHERE workspace_slug=?",
        (workspace_slug,)
    ).fetchall():
        if r['mac_addr'] not in global_cache:
            continue
        existing = ip_cache.get(r['last_ip'])
        # Overwrite only if we don't have an entry yet, or the current best is synthetic
        if existing is None or existing.get('mac_addr', '').startswith('ip:'):
            ip_cache[r['last_ip']] = global_cache[r['mac_addr']]

    categories = [
        dict(r) for r in mconn.execute(
            "SELECT id, name, color, display_order FROM categories ORDER BY display_order, name"
        ).fetchall()
    ]
    # Workspace-level tags keyed by IP (fallback for hosts without MAC)
    local_tags = {
        r['ip_addr']: r['tag']
        for r in conn.execute("SELECT ip_addr, tag FROM host_tags").fetchall()
    }

    mconn.close()

    nodes = []
    for host in hosts:
        ports = conn.execute(
            "SELECT portid, state, service_name, service_product FROM ports WHERE host_id = ? ORDER BY portid",
            (host['id'],)
        ).fetchall()
        open_ports = [p for p in ports if p['state'] == 'open']

        ip       = host['ip_addr']
        scan_mac = host['mac_addr'] or ''
        mac      = scan_mac
        ga       = global_cache.get(mac) or ip_cache.get(ip) or global_cache.get(f'ip:{ip}') or {}

        # For MAC-less or randomized-MAC hosts, surface the stable key from the asset cache
        if (not mac or is_randomized_mac(mac)) and ga:
            candidate = ga.get('mac_addr', '')
            if candidate and not candidate.startswith('ip:'):
                mac = candidate

        # Global asset values take precedence over scan values when non-empty
        vendor   = ga.get('vendor')   or host['vendor']   or ''
        hostname = ga.get('hostname') or host['hostname'] or ''
        os_name  = ga.get('os_name')  or host['os_name']  or ''
        tag      = ga.get('tag')      or local_tags.get(ip, '')

        nodes.append({
            'id':             ip,
            'ip':             ip,
            'mac':            mac,
            'randomized_mac': is_randomized_mac(scan_mac),
            'vendor':         vendor,
            'hostname':       hostname,
            'status':         host['status'],
            'os_name':        os_name,
            'promoted':       ip in promoted,
            'tag':            tag,
            'category_id':    ga.get('category_id'),
            'category_name':  ga.get('category_name') or '',
            'category_color': ga.get('category_color') or '',
            'ghost':          False,
            'ports': [
                {
                    'portid':  p['portid'],
                    'state':   p['state'],
                    'service': p['service_name'] or str(p['portid']),
                    'product': p['service_product'] or ''
                }
                for p in open_ports
            ]
        })

    # ── Ghost nodes: any host ever seen in this workspace but absent now ─────
    curr_keys = {
        (h['mac_addr'] if h['mac_addr'] else f"ip:{h['ip_addr']}")
        for h in hosts
    }

    # All past host records ordered most-recent first; deduplicate by key in Python
    all_past = conn.execute(
        """SELECT h.*, s.upload_time as scan_upload_time
           FROM hosts h
           JOIN scans s ON s.id = h.scan_id
           WHERE h.scan_id != ?
           ORDER BY s.upload_time DESC, h.id DESC""",
        (scan_id,)
    ).fetchall()

    seen_past_keys = set()
    ghost_nodes = []
    for ph in all_past:
        pscan_mac = ph['mac_addr'] or ''
        pmac      = pscan_mac
        pip       = ph['ip_addr']
        pkey      = pmac if pmac else f'ip:{pip}'
        if pkey in seen_past_keys:
            continue           # already have a more-recent record for this host
        seen_past_keys.add(pkey)
        if pkey in curr_keys:
            continue           # still present in current scan

        ga = global_cache.get(pmac) or ip_cache.get(pip) or global_cache.get(f'ip:{pip}') or {}
        if (not pmac or is_randomized_mac(pmac)) and ga:
            candidate = ga.get('mac_addr', '')
            if candidate and not candidate.startswith('ip:'):
                pmac = candidate
        prev_ports = conn.execute(
            "SELECT portid, service_name, service_product FROM ports "
            "WHERE host_id=? AND state='open' ORDER BY portid",
            (ph['id'],)
        ).fetchall()
        ghost_nodes.append({
            'id':             pip,
            'ip':             pip,
            'mac':            pmac,
            'randomized_mac': is_randomized_mac(pscan_mac),
            'vendor':         ga.get('vendor') or ph['vendor'] or '',
            'hostname':       ga.get('hostname') or ph['hostname'] or '',
            'status':         ph['status'],
            'os_name':        ga.get('os_name') or ph['os_name'] or '',
            'promoted':       False,
            'tag':            ga.get('tag') or local_tags.get(pip, ''),
            'category_id':    ga.get('category_id'),
            'category_name':  ga.get('category_name') or '',
            'category_color': ga.get('category_color') or '',
            'ghost':          True,
            'ports': [
                {
                    'portid':  p['portid'],
                    'state':   'open',
                    'service': p['service_name'] or str(p['portid']),
                    'product': p['service_product'] or ''
                }
                for p in prev_ports
            ]
        })

    conn.close()
    return {'nodes': nodes + ghost_nodes, 'categories': categories}


def compute_scan_changes(workspace_slug, scan_id):
    conn = get_workspace_db(workspace_slug)

    scans = conn.execute(
        "SELECT id FROM scans ORDER BY scan_start, upload_time"
    ).fetchall()
    scan_ids = [s['id'] for s in scans]

    if scan_id not in scan_ids:
        conn.close()
        return 0, []

    idx = scan_ids.index(scan_id)
    if idx == 0:
        conn.close()
        return 0, []

    prev_id = scan_ids[idx - 1]

    def get_host_map(sid):
        """Return {identity_key: {ip, mac, hostname, ports}} keyed by MAC when available."""
        result = {}
        hosts = conn.execute(
            "SELECT id, ip_addr, mac_addr, hostname FROM hosts WHERE scan_id=?", (sid,)
        ).fetchall()
        for h in hosts:
            key = h['mac_addr'] if h['mac_addr'] else f"ip:{h['ip_addr']}"
            ports = conn.execute(
                "SELECT portid, service_name FROM ports WHERE host_id=? AND state='open'",
                (h['id'],)
            ).fetchall()
            result[key] = {
                'ip':       h['ip_addr'],
                'mac':      h['mac_addr'] or '',
                'hostname': h['hostname'] or '',
                'ports':    {(p['portid'], p['service_name']) for p in ports}
            }
        return result

    prev_map = get_host_map(prev_id)
    curr_map = get_host_map(scan_id)

    changes = []
    prev_keys = set(prev_map)
    curr_keys = set(curr_map)

    for key in curr_keys - prev_keys:
        h = curr_map[key]
        changes.append({'type': 'new_host', 'ip': h['ip'], 'mac': h['mac'],
                        'hostname': h['hostname'], 'detail': 'New host discovered'})

    for key in prev_keys - curr_keys:
        h = prev_map[key]
        changes.append({'type': 'host_gone', 'ip': h['ip'], 'mac': h['mac'],
                        'hostname': h['hostname'], 'detail': 'Host disappeared'})

    for key in prev_keys & curr_keys:
        h            = curr_map[key]
        prev_ports   = prev_map[key]['ports']
        curr_ports   = h['ports']
        for port, svc in curr_ports - prev_ports:
            changes.append({'type': 'port_opened', 'ip': h['ip'], 'mac': h['mac'],
                            'hostname': h['hostname'], 'port': port, 'service': svc or '',
                            'detail': f"Port {port}/{svc or 'unknown'} opened"})
        for port, svc in prev_ports - curr_ports:
            changes.append({'type': 'port_closed', 'ip': h['ip'], 'mac': h['mac'],
                            'hostname': h['hostname'], 'port': port, 'service': svc or '',
                            'detail': f"Port {port}/{svc or 'unknown'} closed"})

    conn.close()
    return len(changes), changes
