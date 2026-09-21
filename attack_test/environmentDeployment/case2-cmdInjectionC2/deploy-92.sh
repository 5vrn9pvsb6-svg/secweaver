#!/bin/bash
# ============================================================
# Command Injection + C2 — Host 92 (CentOS)
# (命令注入 + C2 — 92 部署)
#
# Role: C2 listener (Python HTTP) + file receiver
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

echo "========== [1/4] 安装依赖 =========="
yum install -y python3 curl net-tools socat 2>/dev/null || \
dnf install -y python3 curl net-tools socat 2>/dev/null

echo "========== [2/4] 部署 C2 监听脚本 =========="
lab_claim_directory /opt/c2-listener c2-listener-dir
lab_claim_directory /opt/c2-data c2-data-dir

cat > /opt/c2-listener/server.py << 'PYEOF'
#!/usr/bin/env python3
"""Simple C2/Exfil HTTP listener for attack lab."""
import http.server
import os
import json
from datetime import datetime

LOG_FILE = '/var/log/c2-listener.log'
DATA_DIR = '/opt/c2-data'

class C2Handler(http.server.BaseHTTPRequestHandler):
    def _log(self, event_type, details):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': self.client_address[0],
            'event_type': event_type,
            'path': self.path,
            **details
        }
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def do_GET(self):
        self._log('beacon', {'method': 'GET'})
        self.send_response(200)
        self.end_headers()
        # Return a fake "task" for the beacon
        self.wfile.write(b'{"status":"ok","task":"sleep","interval":300}')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f"{DATA_DIR}/exfil_{ts}_{length}b.bin"
        with open(fname, 'wb') as f:
            f.write(body)

        self._log('exfil_upload', {'method': 'POST', 'bytes': length, 'saved_to': fname})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        pass  # suppress default stderr logging

if __name__ == '__main__':
    port = int(os.environ.get('C2_PORT', '8443'))
    server = http.server.HTTPServer(('0.0.0.0', port), C2Handler)
    print(f'[*] C2/Exfil listener on :{port}')
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps({
            'timestamp': datetime.now().isoformat(),
            'event_type': 'server_start',
            'port': port
        }) + '\n')
    server.serve_forever()
PYEOF
chmod +x /opt/c2-listener/server.py

echo "========== [3/4] 创建 systemd 服务 =========="
if [[ -e /etc/systemd/system/c2-listener.service ]] \
    && ! lab_resource_was_created c2-listener-service; then
    lab_error "refusing to overwrite unowned c2-listener.service"
    exit 2
fi
if [[ ! -e /etc/systemd/system/c2-listener.service ]]; then
    lab_mark_resource_created c2-listener-service
fi
lab_backup_file /etc/systemd/system/c2-listener.service
if [[ ! -e /var/log/c2-listener.log ]]; then
    lab_mark_resource_created c2-listener-log
fi
cat > /etc/systemd/system/c2-listener.service << 'SVCEOF'
[Unit]
Description=C2/Exfil HTTP Listener (Lab)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/c2-listener/server.py
Environment=C2_PORT=8443
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now c2-listener

echo "========== [4/4] 防火墙 =========="
lab_firewall_add port 8443/tcp

echo ""
echo "============================================"
echo "  C2 监听器部署完成 (92)"
echo "  监听: 0.0.0.0:8443"
echo "  日志: /var/log/c2-listener.log"
echo "  接收数据: /opt/c2-data/"
echo "============================================"

echo "[验证] c2-listener: $(systemctl is-active c2-listener)"
curl -s http://127.0.0.1:8443/ && echo ""
