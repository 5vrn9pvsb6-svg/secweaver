#!/bin/bash
# ============================================================
# Command Injection + C2 — Host 91 (OpenEuler)
# (命令注入 + C2 — 91 部署)
#
# Prerequisite: deploy-nginx-base.sh
# Deploy path: /var/www/html/cmdi/
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

APP_DIR="/var/www/html/cmdi"

echo "========== 部署 cmdi 应用 → ${APP_DIR} =========="
lab_claim_directory "${APP_DIR}" app-cmdi
mkdir -p "${APP_DIR}/config"

# --- index.php (网络诊断工具) ---
cat > "${APP_DIR}/index.php" << 'PHPEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>NetTools - 网络诊断平台</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }
h1 { color: #2e7d32; }
.card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 24px; margin: 20px 0; }
form { display: flex; gap: 10px; flex-wrap: wrap; }
input[name="host"] { flex: 1; padding: 8px 12px; border: 1px solid #ccc; border-radius: 4px; min-width: 200px; }
select { padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
button { padding: 8px 20px; background: #2e7d32; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
pre { background: #263238; color: #aed581; padding: 16px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; }
footer { text-align: center; color: #999; font-size: 12px; margin-top: 40px; }
</style>
</head>
<body>
<h1>NetTools 网络诊断平台</h1>
<div class="card">
    <h3>网络连通性测试</h3>
    <form action="/cmdi/diag.php" method="GET">
        <input name="host" placeholder="输入 IP 或域名">
        <select name="tool">
            <option value="ping">Ping</option>
            <option value="traceroute">Traceroute</option>
            <option value="nslookup">DNS Lookup</option>
        </select>
        <button type="submit">诊断</button>
    </form>
</div>
<div class="card">
    <h3>系统信息</h3>
    <p>主机名: <?= gethostname() ?> | 内核: <?= php_uname('r') ?></p>
</div>
<footer>NetTools v1.3.2 — PHP <?= phpversion() ?></footer>
</body>
</html>
PHPEOF

# --- diag.php (VULNERABLE: 命令注入) ---
cat > "${APP_DIR}/diag.php" << 'PHPEOF'
<?php
$host = $_GET['host'] ?? '';
$tool = $_GET['tool'] ?? 'ping';

echo "<h2>诊断结果</h2>";
if ($host === '') { echo "<p>请输入目标地址</p>"; }
else {
    echo "<p>工具: <b>" . htmlspecialchars($tool) . "</b> | 目标: <b>" . htmlspecialchars($host) . "</b></p>";
    switch ($tool) {
        case 'ping':       $cmd = "ping -c 3 -W 2 $host 2>&1"; break;
        case 'traceroute': $cmd = "traceroute -m 10 -w 2 $host 2>&1"; break;
        case 'nslookup':   $cmd = "nslookup $host 2>&1"; break;
        default:           $cmd = "echo 'Unknown tool'";
    }
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}
?>
<p><a href="/cmdi/">返回</a></p>
PHPEOF

# --- 敏感配置 ---
cat > "${APP_DIR}/config/app.conf" << 'EOF'
[database]
host = 10.66.6.92
port = 3306
user = app_rw
password = AppDB_rw2024!

[redis]
host = 127.0.0.1
port = 6379

[api]
secret_key = sk-prod-a1b2c3d4e5f6g7h8i9j0
EOF

chown -R nginx:nginx "${APP_DIR}"
chmod 644 "${APP_DIR}/config/app.conf"
nginx -t && systemctl reload nginx

echo "  部署完成: http://10.66.6.91/cmdi/"
curl -s -o /dev/null -w "  验证: HTTP %{http_code}\n" http://127.0.0.1/cmdi/
