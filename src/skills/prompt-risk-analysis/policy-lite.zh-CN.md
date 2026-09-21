# 轻量研判口径（开源提示词版）

**语言：** [English](policy-lite.md) | 简体中文（本文）

> **定位：参考基线，非唯一依据。**  
> 供团队统一默认口径与示例；AI 应以 **资深安全专家** 身份研判，可结合 ATT&CK、狩猎经验与现场上下文 **偏离** 下文条目，但须在报告中说明理由。  
> 本文件 **不能替代** 对 `evidence_bundles` 的深入分析与主动关联。

## 1. 默认告警（alert_required）

满足任一即建议 **告警**，并标 P0 或 P1：

### Web / 应用层

- 对外监听进程（nginx、php-fpm、httpd 等）子进程执行 **交互式 Shell** 或 **系统探测**（`id`、`whoami`、`cat /etc/passwd|shadow`、`find` 密钥、`curl|wget` 下载可执行文件）。
- 访问 **已知 WebShell 路径**（如 `*.phtml`、`cmd.jsp`、`eval(`）且伴随命令执行日志。
- **disable_functions**、**open_basedir** 等 PHP 安全限制被修改或绕过。

### 凭据与账号

- 读取 `/etc/shadow`、批量 `find` SSH 私钥、`sshpass` / 明文密码横向登录。
- **新建** root 或 sudo 用户、`usermod -aG wheel|sudo`、`chmod 777` 敏感目录（uploads、webroot）且非变更窗口说明。

### 持久化与防御规避

- `crontab -e`、systemd unit、`.bashrc` 写入反弹或下载逻辑。
- `setenforce 0`、`systemctl stop auditd|rsyslog`、清空日志（`> /var/log/`、`history -c`）。

### 外连（若有 host_connect）

- 监听进程对外连 **非常规端口**、已知 C2 模式、或与刚执行的下载/解码命令时间邻近（±5 分钟）。

### Syslog / 平台告警

- 平台 `syslog_risk_alert` 中 **WEB-SHELL**、**反弹 Shell**、**暴力破解成功**、**异常账号** 类规则命中，且与 host_exec 时间可关联 → 提升置信度，不单独作为 P0 除非无 exec 佐证时标 P1。

## 2. 默认抑制（suppress）

以下 **单独出现** 时倾向抑制或 P3，除非与上节组合：

| 模式 | 说明 |
|------|------|
| 包管理 | `yum install` / `apt-get` 官方源、常规 nginx/php 安装（无后续 WebShell） |
| 监控探活 | 固定源 IP 的 HTTP health check、Zabbix/Prometheus 拉取 |
| 日志采集 | `ilogtail`、`filebeat` 安装与配置（无异常外连） |
| 单次失败 SSH | 1–2 次 `Failed password`，无成功跟进 |
| 已标注演练 | 日志或上下文出现 drill/red team 且行为符合剧本 |

抑制时必须写 **`suppress_reason`**（如 `routine_package_install`）。

## 3. 观察（monitor）

- 侦察但未触及敏感文件：`uname -a`、`netstat`、`ps` 单次。
- 新进程外连但目标为已知 SaaS API（需结合资产 CMDB，无则标 `medium` 置信度）。

## 4. 关联加分

多信号同时出现时 **上调一级**（不超过 P0）：

```text
HTTP 上传/访问脚本 + nginx 子进程 shell + 读 shadow + sshpass 横向
```

## 5. 环境/演练判断

- 内网固定 IP（如 10.0.0.2）在攻击前 **批量装环境、chmod 777、关 SELinux** → 叙事中标注「可能为实验/演练环境准备」，**不**因此降低已发生 WebShell/横向的级别，但影响处置优先级说明。

## 6. 输出字段约定

与 `output-schema.json` 对齐：

- `severity`: P0|P1|P2|P3
- `disposition`: alert_required | suppress | monitor
- `confidence`: high | medium | low
- `evidence_refs`: 至少一条，含 `asset_type` + `time` + 关键字段
