#!/bin/bash
# ============================================================
# SQL Injection Alert Confirmation — Host 91 (OpenEuler)
# (SQL 注入告警确认 — 91 部署)
#
# Prerequisite: deploy-nginx-base.sh
# Deploy path: /var/www/html/sqli/
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

APP_DIR="/var/www/html/sqli"

echo "========== 部署 sqli 应用 → ${APP_DIR} =========="
lab_claim_directory "${APP_DIR}" app-sqli
mkdir -p "${APP_DIR}/templates"

# --- index.php ---
cat > "${APP_DIR}/index.php" << 'PHPEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>Product Search Portal</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
h1 { color: #1a73e8; }
form { margin: 20px 0; }
input[name="q"] { padding: 8px; width: 300px; border: 1px solid #ccc; border-radius: 4px; }
button { padding: 8px 20px; background: #1a73e8; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
footer { margin-top: 40px; color: #999; font-size: 12px; }
</style>
</head>
<body>
<h1>Product Search Portal</h1>
<form action="/sqli/search.php" method="GET">
    <input name="q" placeholder="Search products..." size="40">
    <button type="submit">Search</button>
</form>
<hr>
<p><a href="/sqli/page.php?tpl=about">About Us</a> | <a href="/sqli/page.php?tpl=contact">Contact</a></p>
<footer>Server: Nginx + PHP <?= phpversion() ?></footer>
</body>
</html>
PHPEOF

# --- search.php (SQL 注入 + WAF 模拟) ---
cat > "${APP_DIR}/search.php" << 'PHPEOF'
<?php
$waf_log = '/var/log/waf_alert.log';
$request_uri = $_SERVER['REQUEST_URI'] ?? '';

function waf_check($input, $uri) {
    global $waf_log;
    $ts = date('c');
    $src_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if (preg_match('/union\s+select|or\s+1\s*=\s*1|\'\s*or\s*\'|sleep\s*\(|benchmark\s*\(/i', $input)) {
        file_put_contents($waf_log, json_encode([
            'timestamp' => $ts, 'src_ip' => $src_ip,
            'rule_id' => 'sqli-1001', 'rule_name' => 'SQL Injection detected',
            'action' => 'log', 'severity' => 'CRITICAL',
            'request_uri' => $uri, 'matched_data' => substr($input, 0, 200),
            'tags' => ['sqli', 'owasp-a03']
        ], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
        return 'detected';
    }
    if (preg_match('/<script|javascript:|on\w+\s*=/i', $input)) {
        file_put_contents($waf_log, json_encode([
            'timestamp' => $ts, 'src_ip' => $src_ip,
            'rule_id' => 'xss-1003', 'rule_name' => 'XSS blocked',
            'action' => 'block', 'severity' => 'HIGH',
            'request_uri' => $uri, 'matched_data' => substr($input, 0, 200),
            'tags' => ['xss', 'owasp-a07']
        ], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
        return 'blocked';
    }
    if (preg_match('/\b(SELECT|UNION|DROP|INSERT)\b/i', $input) && !preg_match('/union\s+select/i', $input)) {
        file_put_contents($waf_log, json_encode([
            'timestamp' => $ts, 'src_ip' => $src_ip,
            'rule_id' => 'sqli-1001-fp', 'rule_name' => 'SQL keyword in normal query',
            'action' => 'log', 'severity' => 'LOW',
            'request_uri' => $uri, 'matched_data' => substr($input, 0, 200),
            'tags' => ['sqli', 'possible-false-positive']
        ], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
    }
    return 'pass';
}

$waf_result = waf_check($_GET['q'] ?? '', $request_uri);
if ($waf_result === 'blocked') { http_response_code(403); echo "<h1>403 Forbidden</h1><p>Request blocked by WAF</p>"; exit; }

$conn = new mysqli('10.66.6.92', 'app_user', 'app_pass_2024', 'prod_db');
if ($conn->connect_error) { die("DB connection failed"); }

$q = $_GET['q'] ?? '';
echo "<h2>Search results for: " . htmlspecialchars($q) . "</h2>";
if ($q !== '') {
    $sql = "SELECT id, name, price FROM products WHERE name LIKE '%$q%'";
    $result = $conn->query($sql);
    if ($result && $result->num_rows > 0) {
        echo "<table border='1' cellpadding='6'><tr><th>ID</th><th>Name</th><th>Price</th></tr>";
        while ($row = $result->fetch_assoc()) { echo "<tr><td>{$row['id']}</td><td>{$row['name']}</td><td>{$row['price']}</td></tr>"; }
        echo "</table>";
    } else {
        echo "<p>No results found.</p>";
        if ($conn->error) { echo "<!-- SQL Error: " . $conn->error . " -->"; }
    }
}
$conn->close();
?>
<p><a href="/sqli/">Back</a></p>
PHPEOF

# --- page.php (路径穿越 + WAF 模拟) ---
cat > "${APP_DIR}/page.php" << 'PHPEOF'
<?php
$waf_log = '/var/log/waf_alert.log';
$tpl = $_GET['tpl'] ?? 'about';
$src_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (strpos($tpl, '..') !== false) {
    file_put_contents($waf_log, json_encode([
        'timestamp' => date('c'), 'src_ip' => $src_ip,
        'rule_id' => 'lfi-1002', 'rule_name' => 'Path Traversal detected',
        'action' => 'log', 'severity' => 'HIGH',
        'request_uri' => $_SERVER['REQUEST_URI'] ?? '', 'matched_data' => $tpl,
        'tags' => ['path_traversal', 'lfi', 'owasp-a01']
    ], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
}

$base = dirname(__FILE__) . '/templates';
$file = "$base/$tpl.html";
if (file_exists($file)) { echo "<h2>" . ucfirst(htmlspecialchars(basename($tpl))) . "</h2>"; readfile($file); }
else { $raw = "$base/$tpl"; if (file_exists($raw)) { echo "<pre>" . htmlspecialchars(file_get_contents($raw)) . "</pre>"; } else { echo "<p>Page not found.</p>"; } }
?>
<p><a href="/sqli/">Back</a></p>
PHPEOF

cat > "${APP_DIR}/templates/about.html" << 'EOF'
<p>We are a leading e-commerce platform providing quality products at competitive prices.</p>
EOF
cat > "${APP_DIR}/templates/contact.html" << 'EOF'
<p>Contact us at: support@example.com | Phone: +86-10-12345678</p>
EOF

# WAF 日志
touch /var/log/waf_alert.log
chown nginx:nginx /var/log/waf_alert.log
chmod 666 /var/log/waf_alert.log

chown -R nginx:nginx "${APP_DIR}"
nginx -t && systemctl reload nginx

echo "  部署完成: http://10.66.6.91/sqli/"
curl -s -o /dev/null -w "  验证: HTTP %{http_code}\n" http://127.0.0.1/sqli/
