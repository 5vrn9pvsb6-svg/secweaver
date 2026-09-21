#!/bin/bash
# ============================================================
# Data Exfiltration + C2 — Host 91 (OpenEuler)
# (数据外泄 + C2 — 91 部署)
#
# Prerequisite: deploy-nginx-base.sh
# Deploy path: /var/www/html/exfil/
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

APP_DIR="/var/www/html/exfil"

echo "========== 部署 exfil 应用 → ${APP_DIR} =========="
lab_claim_directory "${APP_DIR}" app-exfil
mkdir -p "${APP_DIR}/uploads" "${APP_DIR}/config"
chmod 777 "${APP_DIR}/uploads"

# --- index.php ---
cat > "${APP_DIR}/index.php" << 'PHPEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>DataApp Portal</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
h1 { color: #e65100; }
</style>
</head>
<body>
<h1>DataApp Portal</h1>
<h3>File Upload</h3>
<form action="/exfil/upload.php" method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
<p><a href="/exfil/uploads/">Browse uploads</a></p>
<footer><small>PHP <?= phpversion() ?></small></footer>
</body>
</html>
PHPEOF

# --- upload.php (黑名单缺 phtml) ---
cat > "${APP_DIR}/upload.php" << 'PHPEOF'
<?php
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['file'])) { header('Location: /exfil/'); exit; }
$file = $_FILES['file'];
$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
$blocked = ['php','php3','php4','php5','php7','phps'];
if (in_array($ext, $blocked)) { header('HTTP/1.1 302 Found'); header('Location: /exfil/?error=blocked'); exit; }
$allowed_types = ['image/jpeg','image/png','image/gif','text/plain','application/pdf','application/octet-stream'];
if (!in_array($file['type'], $allowed_types)) { header('HTTP/1.1 302 Found'); header('Location: /exfil/?error=type'); exit; }
$dir = __DIR__ . '/uploads/';
move_uploaded_file($file['tmp_name'], $dir . basename($file['name']));
header('Location: /exfil/uploads/' . basename($file['name']));
PHPEOF

# --- 明文凭证 ---
cat > "${APP_DIR}/config/database.yml" << 'EOF'
production:
  adapter: mysql2
  host: 10.66.6.92
  port: 3306
  username: app_user
  password: app_pass_2024
  database: prod_db
  pool: 5
  timeout: 5000
EOF

chown -R nginx:nginx "${APP_DIR}"
chmod 777 "${APP_DIR}/uploads"
chmod 644 "${APP_DIR}/config/database.yml"
nginx -t && systemctl reload nginx

echo "  部署完成: http://10.66.6.91/exfil/"
curl -s -o /dev/null -w "  验证: HTTP %{http_code}\n" http://127.0.0.1/exfil/
