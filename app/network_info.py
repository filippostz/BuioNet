import socket
import subprocess
import re


def get_network_info():
    info = {
        'host_ip': None,
        'gateway': None,
        'dns_servers': [],
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        info['host_ip'] = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    try:
        result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=3)
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if m:
            info['gateway'] = m.group(1)
    except Exception:
        pass

    if not info['gateway']:
        try:
            result = subprocess.run(['route', '-n'], capture_output=True, text=True, timeout=3)
            for line in result.stdout.splitlines():
                if line.startswith('0.0.0.0'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['gateway'] = parts[1]
                        break
        except Exception:
            pass

    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        info['dns_servers'].append(parts[1])
    except Exception:
        pass

    return info
