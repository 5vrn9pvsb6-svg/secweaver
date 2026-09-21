#!/bin/bash
# ============================================================
# Data Exfiltration + C2 — Host 92 (CentOS)
# (数据外泄 + C2 — 92 部署)
#
# Role: MariaDB (sensitive data) + C2/Exfil HTTP listener
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

echo "========== [1/5] 安装依赖 =========="
yum install -y mariadb-server mariadb python3 curl net-tools socat 2>/dev/null || \
dnf install -y mariadb-server mariadb python3 curl net-tools socat 2>/dev/null

echo "========== [2/5] 启动 MySQL 并初始化 =========="
systemctl enable --now mariadb
systemctl restart mariadb

# Preserve the ownership boundary when case 1 was not deployed first. Existing
# operator databases/accounts are never populated with vulnerable sample data.
if [[ "$(mysql -u root -NBe "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='prod_db'")" != "0" ]]; then
    lab_resource_was_created mysql-database-prod_db \
        || { lab_error "refusing to reuse unowned MariaDB database prod_db"; exit 2; }
else
    lab_mark_resource_created mysql-database-prod_db
fi
if [[ "$(mysql -u root -NBe "SELECT COUNT(*) FROM mysql.user WHERE User='app_user' AND Host='%'")" != "0" ]]; then
    lab_resource_was_created mysql-user-app_user \
        || { lab_error "refusing to reuse unowned MariaDB account app_user@%"; exit 2; }
else
    lab_mark_resource_created mysql-user-app_user
fi
mysql -u root << 'SQLEOF'
CREATE DATABASE IF NOT EXISTS prod_db;
GRANT ALL PRIVILEGES ON prod_db.* TO 'app_user'@'%' IDENTIFIED BY 'app_pass_2024';
FLUSH PRIVILEGES;

USE prod_db;

# Case 1 and Case 3 intentionally share prod_db on the two-host lab. Keep these
# shared table contracts identical so either deployment order remains valid.
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100),
    role VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS payment_cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    card_number VARCHAR(20),
    cvv VARCHAR(4),
    expiry VARCHAR(7),
    holder_name VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(100),
    api_key VARCHAR(200),
    secret VARCHAR(200),
    created_at DATETIME
);

INSERT IGNORE INTO users VALUES
(1, 'admin',     '$2b$12$LJ3m4ks9Xk2Z', 'admin@corp.local',    'admin'),
(2, 'zhang_wei', '$2b$12$Pq8nR3kL9mX1', 'zhangwei@corp.local', 'manager'),
(3, 'li_na',     '$2b$12$Yt7wQ2jH8nK4', 'lina@corp.local',     'user'),
(4, 'wang_fang', '$2b$12$Kd5uP1eG7jR6', 'wangfang@corp.local', 'user'),
(5, 'chen_ming', '$2b$12$Mn9sT0dF6hQ3', 'chenming@corp.local', 'dba'),
(6, 'svc_backup','$2b$12$Xb3rS9cE5gP2', 'backup@corp.local',   'service');

INSERT IGNORE INTO payment_cards VALUES
(1, 1, '4111-1111-1111-1111', '123', '2027-12', 'Admin User'),
(2, 2, '5500-0000-0000-0004', '456', '2026-08', 'Zhang Wei'),
(3, 3, '3400-0000-0000-009',  '789', '2027-03', 'Li Na'),
(4, 4, '6011-0000-0000-0004', '321', '2026-11', 'Wang Fang');

INSERT IGNORE INTO credentials VALUES
(1, 'AWS S3',     'AKIA-EXAMPLE-ACCESS-KEY-ID-NOT-REAL', 'wJalrEXAMPLEsecretEXAMPLEkeyNOTREAL0123',   '2026-01-15 10:00:00'),
(2, 'Aliyun OSS', 'LTAI5tExampleKey123',  'ExAmPlEsEcReTkEy2024AbCdEfGhIjKl',           '2026-03-01 09:00:00'),
(3, 'Stripe',     'sk_live_51Example',     'whsec_ExampleWebhookSecret2024',              '2026-02-20 14:00:00');
SQLEOF

# 允许远程连接
lab_backup_file /etc/my.cnf
if grep -q 'bind-address' /etc/my.cnf 2>/dev/null; then
    sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/my.cnf
else
    echo -e "\n[mysqld]\nbind-address = 0.0.0.0" >> /etc/my.cnf
fi
systemctl restart mariadb

echo "========== [3/5] 部署 C2/Exfil 监听器 =========="
lab_claim_directory /opt/c2-listener c2-listener-dir
lab_claim_directory /opt/c2-data c2-data-dir

cat > /opt/c2-listener/server.py << 'PYEOF'
#!/usr/bin/env python3
"""C2/Exfil HTTP listener."""
import http.server, os, json
from datetime import datetime

LOG_FILE = '/var/log/c2-listener.log'
DATA_DIR = '/opt/c2-data'

class C2Handler(http.server.BaseHTTPRequestHandler):
    def _log(self, event_type, details):
        entry = {'timestamp': datetime.now().isoformat(), 'src_ip': self.client_address[0],
                 'event_type': event_type, 'path': self.path, **details}
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def do_GET(self):
        self._log('beacon', {'method': 'GET'})
        self.send_response(200)
        self.end_headers()
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

    def log_message(self, fmt, *args): pass

if __name__ == '__main__':
    port = int(os.environ.get('C2_PORT', '8443'))
    server = http.server.HTTPServer(('0.0.0.0', port), C2Handler)
    print(f'[*] C2/Exfil listener on :{port}')
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps({'timestamp': datetime.now().isoformat(),
                            'event_type': 'server_start', 'port': port}) + '\n')
    server.serve_forever()
PYEOF
chmod +x /opt/c2-listener/server.py

echo "========== [4/5] 创建 systemd 服务 =========="
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

echo "========== [5/5] 防火墙 =========="
lab_firewall_add port 3306/tcp
lab_firewall_add port 8443/tcp

echo ""
echo "============================================"
echo "  数据外泄 — DB + C2 部署完成 (92)"
echo "  MySQL: app_user / app_pass_2024 @ :3306"
echo "  C2 监听: :8443"
echo "  日志: /var/log/c2-listener.log"
echo "  接收数据: /opt/c2-data/"
echo "============================================"

echo "[验证] mariadb: $(systemctl is-active mariadb)"
echo "[验证] c2-listener: $(systemctl is-active c2-listener)"
mysql -u app_user -papp_pass_2024 prod_db -e "SELECT COUNT(*) AS user_count FROM users" 2>/dev/null
curl -s http://127.0.0.1:8443/ && echo ""
