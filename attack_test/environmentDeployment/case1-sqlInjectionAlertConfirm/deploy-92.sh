#!/bin/bash
# ============================================================
# SQL Injection Alert Confirmation — Host 92 (CentOS)
# (SQL 注入告警确认 — 92 部署)
#
# Role: MySQL database with sensitive user/payment/credential tables
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

echo "========== [1/4] 安装 MySQL =========="
# CentOS 7: 使用 MariaDB (兼容 MySQL)
yum install -y mariadb-server mariadb 2>/dev/null || \
dnf install -y mariadb-server mariadb 2>/dev/null

echo "========== [2/4] 启动 MySQL =========="
systemctl enable --now mariadb
systemctl restart mariadb

echo "========== [3/4] 初始化数据库 =========="
# A pre-existing database or account is outside lab ownership. Refuse it rather
# than merging synthetic vulnerable data into operator-managed MariaDB state.
if [[ "$(mysql -u root -NBe "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='prod_db'")" != "0" ]]; then
    lab_resource_was_created mysql-database-prod_db \
        || { lab_error "refusing to reuse unowned MariaDB database prod_db"; exit 2; }
else
    lab_mark_resource_created mysql-database-prod_db
fi
if [[ "$(mysql -u root -NBe "SELECT COUNT(*) FROM mysql.user WHERE User='app_user' AND Host='%'")" != "0" ]]; then
    lab_resource_was_created mysql-user-app_user \
        || { lab_error "refusing to reuse unowned MariaDB account app_user@%"; exit 2; }
else
    lab_mark_resource_created mysql-user-app_user
fi
mysql -u root << 'SQLEOF'
-- 创建数据库和用户
CREATE DATABASE IF NOT EXISTS prod_db;
GRANT ALL PRIVILEGES ON prod_db.* TO 'app_user'@'%' IDENTIFIED BY 'app_pass_2024';
FLUSH PRIVILEGES;

USE prod_db;

-- 产品表
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    price DECIMAL(10,2),
    category VARCHAR(50)
);

-- 用户表 (敏感)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100),
    role VARCHAR(20)
);

-- 支付卡表 (敏感)
CREATE TABLE IF NOT EXISTS payment_cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    card_number VARCHAR(20),
    cvv VARCHAR(4),
    expiry VARCHAR(7),
    holder_name VARCHAR(100)
);

-- 插入产品数据
INSERT IGNORE INTO products VALUES
(1, 'Wireless Mouse', 29.99, 'electronics'),
(2, 'USB-C Cable', 12.50, 'electronics'),
(3, 'Laptop Stand', 45.00, 'accessories'),
(4, 'Mechanical Keyboard', 89.99, 'electronics'),
(5, 'Monitor Light Bar', 55.00, 'accessories'),
(6, 'Webcam HD', 39.99, 'electronics'),
(7, 'Desk Pad', 19.99, 'accessories'),
(8, 'Phone Holder', 15.00, 'accessories');

-- 插入用户数据 (攻击目标)
INSERT IGNORE INTO users VALUES
(1, 'admin', 'admin@2024!', 'admin@example.com', 'admin'),
(2, 'zhang_wei', 'Zw123456', 'zhangwei@example.com', 'user'),
(3, 'li_na', 'LiNa#2024', 'lina@example.com', 'user'),
(4, 'devops_bot', 'D3v0ps!svc', 'devops@example.com', 'service'),
(5, 'backup_svc', 'Bkp_r0tate', 'backup@example.com', 'service');

-- 插入支付卡数据 (攻击目标)
INSERT IGNORE INTO payment_cards VALUES
(1, 1, '4111-1111-1111-1111', '123', '2026-12', 'Admin User'),
(2, 2, '5500-0000-0000-0004', '456', '2025-08', 'Zhang Wei'),
(3, 3, '3400-0000-0000-009',  '789', '2027-03', 'Li Na');
SQLEOF

echo "========== [4/4] 配置远程访问 =========="
# 允许远程连接 (绑定所有网卡)
lab_backup_file /etc/my.cnf
if grep -q 'bind-address' /etc/my.cnf 2>/dev/null; then
    sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/my.cnf
else
    echo -e "\n[mysqld]\nbind-address = 0.0.0.0" >> /etc/my.cnf
fi

systemctl restart mariadb

# 防火墙放通 3306
lab_firewall_add port 3306/tcp

echo ""
echo "============================================"
echo "  MySQL 数据库部署完成 (92)"
echo "  地址: 10.66.6.92:3306"
echo "  用户: app_user / app_pass_2024"
echo "  数据库: prod_db"
echo "  表: products, users, payment_cards"
echo "============================================"

echo ""
echo "[验证] MariaDB: $(systemctl is-active mariadb)"
echo "[验证] 远程登录:"
mysql -u app_user -papp_pass_2024 prod_db -e "SELECT COUNT(*) AS product_count FROM products" 2>/dev/null || echo "FAIL"
