#!/bin/bash
# ============================================================
# Attack Lab 范围化清理/配置恢复脚本
#
# 清理部署脚本明确声明为实验所有的资源，并恢复有快照的配置：
#   - 停止并移除 lab systemd 服务 (c2-listener)
#   - 删除 lab 应用目录 (/var/www/html/{webshell,sqli,cmdi,exfil})
#   - 仅删除由 lab 创建的用户 (devops) 及其植入文件
#   - 删除 C2 监听器 (/opt/c2-listener, /opt/c2-data)
#   - 恢复备份的系统配置 (nginx.conf, my.cnf, sshd_config,
#     /etc/selinux/config, php-fpm www.conf, default.d/php.conf)
#   - 删除 lab 专用的 nginx conf 与 ssh_config.d 条目
#   - 恢复文件快照和实验新增的防火墙规则
#
# 软件包安装和通用服务的启用状态不由此脚本猜测回滚；需要完全复原
# 时应销毁并重建一次性虚机/容器。
#
# 在 91 / 92 两台靶机上分别以 root 执行。
#
# Usage: sudo bash teardown-lab.sh
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/lab-safety.sh"
lab_require_deploy_host

BACKUP_DIR="${LAB_BACKUP_DIR}"

echo "========== [1/7] 停止并移除 lab systemd 服务 =========="
if lab_resource_was_created c2-listener-service; then
    systemctl disable --now c2-listener 2>/dev/null || true
fi
systemctl daemon-reload 2>/dev/null || true

echo "========== [2/7] 删除 lab Web 应用目录 =========="
lab_remove_created_path app-webshell /var/www/html/webshell
lab_remove_created_path app-sqli /var/www/html/sqli
lab_remove_created_path app-cmdi /var/www/html/cmdi
lab_remove_created_path app-exfil /var/www/html/exfil

echo "========== [3/7] 删除 lab 用户与植入数据 =========="
if lab_resource_was_created user-devops && id devops &>/dev/null; then
    userdel -r devops 2>/dev/null || { userdel devops || true; rm -rf /home/devops; }
elif id devops &>/dev/null; then
    echo "保留未由 Attack Lab 创建的 devops 用户"
fi
# 攻击命令以 Web 服务账户运行；只移除带显式 lab 标记的条目。
for lab_web_user in nginx apache www-data; do
    lab_remove_marked_cron "${lab_web_user}"
done

echo "========== [4/7] 删除 C2 监听器与外传数据 =========="
lab_remove_created_path c2-listener-dir /opt/c2-listener
lab_remove_created_path c2-data-dir /opt/c2-data
if lab_resource_was_created c2-listener-log; then
    rm -f /var/log/c2-listener.log
fi

echo "========== [5/7] 删除 lab nginx/ssh 配置 =========="
# File ownership is encoded by the backup manifest; restoration below either
# restores the original bytes or removes a file that was originally absent.

echo "========== [6/7] 恢复备份的系统配置 =========="
if [[ -d "${BACKUP_DIR}" ]]; then
    lab_restore_all_files
    # Compatibility with backups made before files.manifest was introduced.
    lab_restore_file /etc/nginx/nginx.conf
    lab_restore_file /etc/nginx/default.d/php.conf
    lab_restore_file /etc/my.cnf
    lab_restore_file /etc/ssh/sshd_config
    lab_restore_file /etc/selinux/config
    # 删除内存马残留 (/dev/shm tmpfs, 重启即消失, 但仍主动清理)
    rm -f /dev/shm/.sess_* /dev/shm/.webshell* 2>/dev/null || true
else
    echo "警告: 未找到备份目录 ${BACKUP_DIR}，跳过配置恢复"
fi

echo "========== [7/7] 回退防火墙、数据库并重载服务 =========="
lab_firewall_remove_if_added service http
lab_firewall_remove_if_added service ssh
lab_firewall_remove_if_added port 3306/tcp
lab_firewall_remove_if_added port 8443/tcp
if command -v mysql >/dev/null 2>&1; then
    if lab_resource_was_created mysql-database-prod_db; then
        mysql -u root -e 'DROP DATABASE IF EXISTS prod_db' 2>/dev/null || true
    fi
    if lab_resource_was_created mysql-user-app_user; then
        mysql -u root -e "DROP USER IF EXISTS 'app_user'@'%'" 2>/dev/null || true
    fi
fi
if command -v setenforce &>/dev/null && grep -q '^SELINUX=enforcing' /etc/selinux/config 2>/dev/null; then
    setenforce 1 2>/dev/null || true
fi
systemctl restart nginx 2>/dev/null || true
systemctl restart mariadb 2>/dev/null || true
systemctl restart sshd 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

# Ownership markers are valid for exactly one deployment lifecycle. Archive the
# consumed state outside the active path so a repeated teardown cannot apply old
# ownership decisions to resources an operator created later.
ARCHIVED_BACKUP_DIR=""
if [[ -d "${BACKUP_DIR}" ]]; then
    ARCHIVED_BACKUP_DIR="${BACKUP_DIR}.restored-$(date +%Y%m%d%H%M%S)-$$"
    mv -- "${BACKUP_DIR}" "${ARCHIVED_BACKUP_DIR}"
fi

echo ""
echo "============================================"
echo "  Attack Lab 范围化清理完成"
if [[ -n "${ARCHIVED_BACKUP_DIR}" ]]; then
    echo "  已消费的恢复状态保留于 ${ARCHIVED_BACKUP_DIR}"
fi
echo "  软件包和通用服务启用状态未自动回滚；完全复原请重建实验主机"
echo "============================================"
