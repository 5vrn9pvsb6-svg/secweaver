#!/bin/bash
# ============================================================
# SSH Lateral Target — Host 92 (CentOS)
# (SSH 横向目标部署 — 92)
#
# Role: Weak-password SSH service + planted sensitive data
#       for lateral movement simulation
# ============================================================
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lab-safety.sh"
lab_require_deploy_host

# Never reset or later delete an operator-managed account with the same name.
if id devops &>/dev/null && ! lab_resource_was_created user-devops; then
    lab_error "refusing to reuse pre-existing devops user"
    exit 2
fi

echo "========== [1/5] 安装依赖 =========="
yum install -y openssh-server rsyslog sudo curl net-tools 2>/dev/null || \
dnf install -y openssh-server rsyslog sudo curl net-tools 2>/dev/null || true

echo "========== [2/5] 创建弱口令用户 =========="
# 检查用户是否已存在
if id devops &>/dev/null; then
    echo "复用由 Attack Lab 创建的 devops 用户并重置实验密码"
    echo 'devops:devops123' | chpasswd
else
    useradd -m -s /bin/bash devops
    lab_mark_resource_created user-devops
    echo 'devops:devops123' | chpasswd
    echo "用户 devops 已创建 (密码: devops123)"
fi

# 加入 sudo/wheel 组
usermod -aG wheel devops 2>/dev/null || usermod -aG sudo devops 2>/dev/null || true

echo "========== [3/5] 植入敏感数据（攻击目标）=========="
mkdir -p /home/devops/projects /home/devops/.config

cat > /home/devops/projects/db-credentials.conf << 'EOF'
[production]
db_host = prod-mysql-01.corp.internal
db_port = 3306
db_user = app_admin
db_pass = Pr0d_MySQL_2026!xKz
db_name = customer_data

[backup]
s3_bucket = s3://corp-db-backup-prod
aws_access_key = AKIA-EXAMPLE-ACCESS-KEY-ID-NOT-REAL
aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

cat > /home/devops/.config/deploy-token.json << 'EOF'
{
  "gitlab_token": "glpat-xxFakeTokenForLabxx",
  "registry": "registry.corp.internal:5000",
  "deploy_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE deploy@prod"
}
EOF

cat > /home/devops/.bash_history << 'EOF'
mysql -u app_admin -pPr0d_MySQL_2026!xKz -h prod-mysql-01 customer_data
mysqldump -u app_admin -pPr0d_MySQL_2026!xKz customer_data > /tmp/backup.sql
scp /tmp/backup.sql admin@10.0.5.100:/backup/
aws s3 cp /tmp/backup.sql s3://corp-db-backup-prod/
kubectl get secrets -n production
cat /etc/kubernetes/admin.conf
EOF

chown -R devops:devops /home/devops
chmod 600 /home/devops/projects/db-credentials.conf \
          /home/devops/.config/deploy-token.json \
          /home/devops/.bash_history

echo "========== [4/5] 配置 SSH =========="
SSHD_CONFIG="/etc/ssh/sshd_config"
lab_backup_file "$SSHD_CONFIG"

# 确保密码认证开启
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
sed -i 's/^#*UsePAM.*/UsePAM yes/' "$SSHD_CONFIG"
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"

# 确保 SSH 主机密钥存在
ssh-keygen -A 2>/dev/null || true

# SELinux permissive（靶机环境）
if command -v setenforce &>/dev/null; then
    setenforce 0 2>/dev/null || true
fi

# Firewall: 确保 SSH 放通
lab_firewall_add service ssh

echo "========== [5/5] 启动服务 =========="
systemctl enable --now sshd rsyslog
systemctl restart sshd

echo ""
echo "============================================"
echo "  SSH 目标靶机部署完成"
echo "  地址: 10.66.6.92:22"
echo "  弱口令: devops / devops123"
echo "  敏感文件:"
echo "    /home/devops/projects/db-credentials.conf"
echo "    /home/devops/.config/deploy-token.json"
echo "    /home/devops/.bash_history"
echo "  日志: /var/log/secure 或 /var/log/auth.log"
echo "============================================"

# 验证
echo ""
echo "[验证] sshd 状态:"
systemctl is-active sshd
echo "[验证] devops 用户:"
id devops
echo "[验证] SSH 密码认证:"
grep "^PasswordAuthentication" "$SSHD_CONFIG"
echo "[验证] 网络连通性 → Web 靶机:"
ping -c 1 -W 2 10.66.6.91 2>/dev/null && echo "OK" || echo "UNREACHABLE"
