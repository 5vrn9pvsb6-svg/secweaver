#!/bin/bash
# ============================================================
# Nginx + PHP-FPM Base Configuration — Host 91 (OpenEuler)
# (Nginx + PHP-FPM 基础配置 — 91 主机)
#
# Shared configuration for all 4 lab environments.
# Each environment deploys to a separate subdirectory.
#
# Subdirectory layout:
#   /var/www/html/webshell/  ← webPenetrateToSSH
#   /var/www/html/sqli/      ← sqlInjectionAlertConfirm
#   /var/www/html/cmdi/      ← cmdInjectionC2
#   /var/www/html/exfil/     ← dataExfilC2
#
# Usage: Run once before deploying individual environments.
#        Subsequent deploy-91.sh / deploy-web.sh scripts
#        only deploy application files.
#
# Requires: root privileges on host 91
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/lab-safety.sh"
lab_require_deploy_host

echo "========== [1/5] 安装依赖 =========="
dnf install -y nginx php-fpm php-cli php-mysqlnd mysql curl wget \
    net-tools iproute nmap sshpass tar bind-utils cronie traceroute 2>/dev/null || \
yum install -y nginx php-fpm php-cli php-mysqlnd mysql curl wget \
    net-tools iproute nmap sshpass tar bind-utils cronie traceroute 2>/dev/null

echo "========== [2/5] 配置 Nginx =========="
# 备份将被修改的系统配置（首次快照优先，teardown-lab.sh 恢复）
lab_backup_file /etc/nginx/nginx.conf
lab_backup_file /etc/nginx/default.d/php.conf
# 移除所有旧的 lab 配置
for lab_nginx_config in \
    /etc/nginx/conf.d/secureshare.conf \
    /etc/nginx/conf.d/sqli-lab.conf \
    /etc/nginx/conf.d/cmdi-lab.conf \
    /etc/nginx/conf.d/lateral-lab.conf \
    /etc/nginx/conf.d/exfil-lab.conf \
    /etc/nginx/conf.d/php-fpm.conf \
    /etc/nginx/conf.d/lab-all.conf; do
    lab_backup_file "${lab_nginx_config}"
    rm -f -- "${lab_nginx_config}"
done
# 禁用 default.d 中引用旧 upstream 的 php 配置
mv /etc/nginx/default.d/php.conf /etc/nginx/default.d/php.conf.bak 2>/dev/null || true
# 移除 nginx.conf 中可能冲突的 default server 块
sed -i '/^    server {/,/^    }/d' /etc/nginx/nginx.conf 2>/dev/null || true

cat > /etc/nginx/conf.d/lab-all.conf << 'NGXEOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    index index.php;

    client_max_body_size 10m;

    access_log /var/log/nginx/access.log combined;
    error_log  /var/log/nginx/error.log warn;

    location / {
        try_files $uri $uri/ =404;
    }

    # 所有子目录的 PHP 统一处理 (.php + .phtml)
    location ~ \.(php|phtml)$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass 127.0.0.1:9000;
        fastcgi_read_timeout 300;
    }

    # 所有 uploads 目录开启 autoindex
    location ~ ^/.*/uploads/ {
        autoindex on;
    }
    location /uploads/ {
        autoindex on;
    }

}
NGXEOF

echo "========== [3/5] 配置 PHP-FPM =========="
PHP_POOL=$(find /etc/php* -name www.conf -path "*/php-fpm*" -o -name www.conf -path "*/fpm/*" 2>/dev/null | head -1)
[ -z "$PHP_POOL" ] && PHP_POOL=$(find /etc -name www.conf 2>/dev/null | grep -i fpm | head -1)
if [ -n "$PHP_POOL" ]; then
    lab_backup_file "$PHP_POOL"
    sed -i 's|^listen = .*|listen = 127.0.0.1:9000|' "$PHP_POOL"
    sed -i 's|^user = .*|user = nginx|' "$PHP_POOL"
    sed -i 's|^group = .*|group = nginx|' "$PHP_POOL"
fi
PHP_INI=$(find /etc/php* -name php.ini 2>/dev/null | head -1)
if [ -n "$PHP_INI" ]; then
    lab_backup_file "$PHP_INI"
    sed -i 's/^disable_functions =.*/disable_functions =/' "$PHP_INI"
fi

echo "========== [4/5] 安全策略 =========="
lab_backup_file /etc/selinux/config
setenforce 0 2>/dev/null || true
lab_firewall_add service http

mkdir -p /etc/ssh/ssh_config.d
lab_backup_file /etc/ssh/ssh_config.d/lab.conf
cat > /etc/ssh/ssh_config.d/lab.conf << 'SSHEOF'
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
SSHEOF

echo "========== [5/5] 启动服务 =========="
systemctl enable --now php-fpm nginx crond 2>/dev/null || true
systemctl restart php-fpm nginx

echo ""
echo "============================================"
echo "  Nginx + PHP-FPM 基础配置完成 (91)"
echo "  根目录: /var/www/html/"
echo "  子目录: webshell/ sqli/ cmdi/ exfil/"
echo "  日志: /var/log/nginx/access.log"
echo "============================================"
echo "[验证] nginx: $(systemctl is-active nginx)"
echo "[验证] php-fpm: $(systemctl is-active php-fpm)"
curl -s -o /dev/null -w "[验证] HTTP: %{http_code}\n" http://127.0.0.1/
