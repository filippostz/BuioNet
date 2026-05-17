# BuioNet

A self-hosted network monitoring dashboard built on top of Nmap. Upload Nmap XML scans to build a live inventory of your network — track assets, detect changes, manage categories, and visualise host relationships as an interactive graph.

<img width="1452" height="864" alt="BuioNet" src="https://github.com/user-attachments/assets/d4857e14-11a7-468d-8f68-23e8e13ff56e" />

---

## Features

- **Interactive network graph** — D3.js force-directed diagram with host details sidebar, port pill badges, ghost nodes for disappeared hosts, and drag-and-drop layout
- **Global asset cache** — MAC-addressed inventory that persists across scans and workspaces; tags and categories survive scan rotation
- **Randomised MAC detection** — iOS / Android private MAC addresses are identified via the locally-administered bit and tracked by hostname instead of rotating MAC
- **Change tracking** — per-scan diff showing new hosts, disappeared hosts, opened and closed ports
- **Alert rules** — configurable event-based alerts (new host, host gone, port opened, port closed) with workspace-scoped acknowledgement
- **Multi-workspace** — isolate different network segments; assign users to specific workspaces
- **Role-based access** — `admin`, `analyst`, and `operator` roles
- **API + API keys** — stream Nmap output directly via `curl` without saving an intermediate XML file
- **Duplicate detection** — alerts for assets sharing the same IP or the same hostname+IP in a workspace

---

## Requirements

- Python 3.10+
- Nmap (installed separately on the host)

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/<your-org>/buionet.git
cd buionet

# 2. Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. (Optional) set a strong secret key
export SECRET_KEY="replace-with-a-long-random-string"

# 4. Run
python run.py
```

Open **http://localhost:5005** and log in with:

| Username | Password   |
|----------|------------|
| `admin`  | `P4ssw0rd!` |

> **Change the default password immediately** after the first login via *Admin → Users*.

---

## Configuration

All configuration is in `config.py` and can be overridden with environment variables:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `buionet-secret-key-change-in-production` | Flask session signing key — **must** be changed in production |
| — | `data/` | SQLite databases are stored here (one `main.db` + one per workspace) |

---

## Uploading scans

### Save to file, then upload via the web UI

```bash
sudo nmap -sS -sV -sC -O \
     --osscan-guess \
     --version-intensity 9 \
     --open \
     -T4 --min-rate 1000 --max-retries 2 \
     -oX "scan_$(date +%Y-%m-%d_%H-%M-%S).xml" \
     192.168.1.0/24
```

Then upload the XML file from the workspace page.

### Stream directly via API (Work in Progress)

```bash
sudo nmap -sS -sV -O -T4 --open 192.168.1.0/24 -oX - | \
  curl -s \
       -H "X-Api-Key: <your-api-key>" \
       -F "scan_file=@-;filename=scan.xml;type=application/xml" \
       http://localhost:5005/api/v1/workspace/<slug>/upload
```

Generate an API key from your profile page.

---


## Licence

see `LICENSE`.
