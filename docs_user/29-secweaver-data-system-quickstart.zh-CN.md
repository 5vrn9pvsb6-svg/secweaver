# SecWeaver Data Cloud 客户快速上手

**语言：** [English](29-secweaver-data-system-quickstart.md) | 简体中文（本页）

产品入口为企业工作台：查询凭证在“智能体配置”，采集端安装在“secweaver-agent”页面的“一键安装”。本手册面向已经开通 SecWeaver Data Cloud 的客户、安全运营同学和最终用户，只说明两件事：

1. 在需要采集主机数据的 Linux 或 Windows 主机上安装 `secweaver-agent`。
2. 使用 SecWeaver Skills 做数据体检、告警确认、主机风险分析和攻击溯源。

**阅读前确认：**“无需配置查询凭证”仅适用于管理员已交付分析环境、DataAsset 和查询权限的用户。
自己下载 Community、在本地 智能体中运行的用户，安装主机 Agent 后仍须完成
[SLS Proxy 本地客户端接入](30-sls-proxy-onboarding.zh-CN.md)，不会自动获得本地查询权限。
先向本企业 Data Cloud 管理员取得平台登录地址、账号和分析环境入口；
查询地址 `https://sls-proxy.id-net.cn:30443` 不是 企业工作台登录页，也不自动开通 SaaS。
没有已开通企业和管理员交付时，可先体验公开离线案例，不要猜测安装域名或令牌。

SecWeaver Data Cloud 是托管且治理好的安全数据底座。SLS、SLS Proxy、租户隔离、字段治理、
查询凭证、DataAsset 和发布服务均由平台侧准备，普通用户不需要搭建这些服务。

> 服务端由平台运营方维护，不随 Community 提供，客户无需部署。

SecWeaver 还支持笔记本便携 ES、Linux 服务器 ES 和客户自有 ES。需要选择其他数据底座时，
参见[数据底座四种部署模式](36-data-foundation-deployment-modes.zh-CN.md)。

## 1. 普通用户只做两件事

| 任务 | 什么时候做 | 用户需要做什么 |
|---|---|---|
| 安装客户端 | 需要补充主机命令、认证、持久化、进程和状态数据时 | 从 Data Cloud 复制一键安装命令并在目标主机执行 |
| 使用 Skills | 需要研判告警、检查数据完整性、分析主机风险或溯源时 | 提供目标、准确时间窗和调查问题 |

如果 WEB/网关告警、网关访问日志、DNS、EDR 或其他数据已经由 Data Cloud 接入，用户不需要
为了查询这些数据而重复安装 Agent。`secweaver-agent` 只安装在需要采集主机侧数据的机器上。

普通用户不需要：

- 安装 SLS Proxy、数据库或 Docker 服务端组件。
- 创建 SLS Project、Logstore、索引、机器组、Connector 或 Asset。
- 获取或配置 SLS RAM AK/SK、Proxy AK/SK、`enterprise_id`、AliUid、region 或 Logstore。
- 修改 Bootstrap、Agent 配置文件或查询中的企业隔离条件。

## 2. 安装客户端

### 2.1 安装前确认

开始前只确认三件事：

1. 企业已经开通 SecWeaver Data Cloud，订阅和设备额度有效。
2. 目标主机可以访问 Data Cloud 的 HTTPS 地址。
3. Linux 用户拥有 `sudo`；Windows 用户使用管理员 PowerShell。

同一个企业安装命令可以在授权范围内安装多台主机，不需要逐台制作安装包。不要把安装命令
或企业安装令牌发送给企业外人员；怀疑泄露时联系平台运营人员停用并重新签发。

### 2.2 Linux 一键安装

1. 打开[企业工作台](https://sc.id-net.cn:30443/)（`https://sc.id-net.cn:30443/`），使用企业账号登录。
2. 进入 **企业工作台 → secweaver-agent → 一键安装**。
3. 选择企业和 Linux 目标平台，复制页面中的安装命令。版本和 CPU 架构由 Bootstrap 安装器决定。
4. 通过 SSH 登录目标主机，粘贴并完整执行页面生成的命令。

页面生成的命令形态如下，实际域名和令牌由平台自动填写：

```bash
curl -fsSL 'https://<DATA_CLOUD_HOST>:30443/secweaver-agent/install.sh' \
  | sudo bash -s -- \
      --enterprise-enrollment-token '<企业安装令牌>'
```

不要手工增加 `enterprise_id`、SLS AK/SK、AliUid、region、Logstore 或机器组参数。授权地址、
Agent 版本、Logtail/LoongCollector 和公共接入参数已经由厂家运营人员写入发布物。

### 2.3 Windows 一键安装

1. 在 **企业工作台 → secweaver-agent → 一键安装**中选择 Windows 目标平台。
2. 点击**复制安装命令**。
3. 打开管理员 PowerShell，完整执行页面生成的命令。

Windows 安装命令会下载并校验 `install.ps1` 和 Agent ZIP，完成设备注册并安装
`SecWeaverAgent` 服务。不要自行使用 `Invoke-Expression` 执行来源不明的远程脚本。

### 2.4 安装器会自动完成什么

用户执行一条命令后，安装器会自动：

- 识别主机架构，下载并校验对应的 Agent 发布包。
- 生成与硬件相关的 `device_id` 和设备独立密钥。
- 使用企业安装令牌完成设备注册并取得服务端确认的企业归属。
- 安装统一 Agent、采集模块和系统服务。
- Linux 安装或复用 Logtail/LoongCollector，并接入平台预置的上传链路。
- 启动服务、执行严格 preflight，并把设备状态上报到 Data Cloud。
- 写入厂家签名升级地址和公钥；后续版本由 Data Cloud 分批下发，用户不需要修改配置。

自动升级只接受厂家 Ed25519 签名发布物和设备密钥认证后的企业策略。新版本通过模块健康
观察后才生效，启动失败或模块不健康会自动恢复上一版。用户无需手工执行升级命令；异常时
把 Data Cloud 中的 `update_status` 交给运营人员处理。

### 2.5 验证安装结果

先回到 Data Cloud 主机列表，确认：

```text
主机状态 = 在线
Agent 状态 = 运行中
数据延迟 = 正常
```

Linux 可进一步检查：

```bash
sudo secweaver-agent preflight \
  -config /opt/secweaver-agent/etc/config.json \
  -strict

sudo systemctl status secweaver-agent
```

Windows 可进一步检查：

```powershell
Get-Service SecWeaverAgent
```

Linux Agent 默认产生以下主机数据：

| 数据 | 本地文件 | 用途 |
|---|---|---|
| 命令与连接事件 | `/opt/secweaver-agent/logs/audit-port-execmon.log` | 命令执行、主动外连和文件操作 |
| 系统风险事件 | `/opt/secweaver-agent/logs/syslog-risk-json.log` | SSH、sudo、root 会话和系统风险 |
| 持久化变化 | `/opt/secweaver-agent/logs/host-persistence.log` | cron、systemd、authorized_keys 等变化 |
| 进程基线与变化 | `/opt/secweaver-agent/logs/host-process-snapshot.log` | 每日全量基线及每 10 分钟启动、退出、关键属性变化 |
| 主机状态快照 | `/opt/secweaver-agent/logs/host-state-snapshot.log` | 端口、用户、登录和基础主机状态 |

最终以 Data Cloud 中对应 Asset 能查询到新数据为准。普通用户不需要查看或修改事件中的
内部租户字段。

## 3. 使用 Skills

### 3.1 在哪里使用

在已经加载 SecWeaver 项目、并由管理员配置好客户 DataAsset 和查询权限的 AI Agent 中，
可以直接用自然语言调用 Skills，例如 Codex、Cursor、Claude Code 或 OpenClaw。平台如果提供
SecWeaver 分析页面，也可以在该页面提出同样的问题。

普通用户不需要指定 Connector、Logstore、AK/SK 或企业过滤条件。Skill 会通过已授权的
DataAsset 获取数据。

### 3.2 提问时提供什么

一次有效调查至少提供：

| 信息 | 示例 |
|---|---|
| 调查目标 | 主机名、资产 ID、攻击 IP、账号或告警 ID |
| 准确时间窗 | `2026-07-24 13:47:00 ~ 13:50:34 +08:00` |
| 调查问题 | 是否攻击成功、影响哪些主机、是否存在横向移动 |
| 已知上下文 | 演练、变更窗口、业务用途或已确认的告警 |

不要只说“查一下最近的风险”。明确时区和时间范围可以减少无关数据，也能让证据链更容易复核。

### 3.3 推荐执行顺序

```text
data-source-completeness
  -> alert-confirmation 或 risk-identification
  -> traceability-analysis
  -> 根据 data_gaps 补充数据后复查
```

先检查数据是否足够，再做结论；确认攻击成功或高度可疑后，再进入完整溯源。

### 3.4 可直接使用的提问模板

**数据完整性检查**

```text
请使用 data-source-completeness Skill，检查当前企业在 2026-07-24 13:47:00 到
13:50:34（Asia/Shanghai）的数据是否足以分析主机 web-01。请实际查询已配置的
DataAsset，并输出可用数据源、缺失数据、阻断项和建议的下一步 Skill。
```

**告警确认**

```text
请使用 alert-confirmation Skill，分析告警 ID ALERT-001 在 2026-07-24 13:47:00 到
13:50:34（Asia/Shanghai）的相关数据，判断是误报、真实攻击还是攻击成功。
请输出证据链、置信度、数据缺口和处置建议，不要用缺少证据的推测补全结论。
```

**主机风险分析**

```text
请使用 risk-identification Skill，分析主机 web-01 在 2026-07-24 13:47:00 到
13:50:34（Asia/Shanghai）的命令、外连、认证、持久化、进程和主机状态数据，
列出高风险行为、证据引用、可能影响和建议动作。
```

**攻击溯源**

```text
请使用 traceability-analysis Skill，以攻击 IP 203.0.113.10 为线索，分析
2026-07-24 13:47:00 到 13:50:34（Asia/Shanghai）的 WEB/网关告警、网关访问、
DNS 和主机数据，还原初始入口、命令执行、横向移动、影响范围和处置建议。
请同时输出未覆盖的数据源和结论置信度。
```

### 3.5 如何阅读结果

| 输出 | 重点 |
|---|---|
| `overall_verdict` / `alert_verdict` | 总体判断或告警结论 |
| `confidence` | 当前证据能够支撑结论的程度 |
| `evidence_refs` | 结论引用的原始证据 |
| `join_edges` | 不同数据源如何关联 |
| `data_gaps` | 缺少哪些数据，缺口如何限制结论 |
| `recommended_actions` | 建议的处置、补数和复查动作 |
| `next_skill` | 建议继续使用的 Skill |

没有 `evidence_refs` 的强结论不应直接用于处置。存在关键 `data_gaps` 时，应先补齐数据或
缩小结论范围，再由安全运营人员结合业务上下文做最终判断。

### 3.6 命令行离线体验

需要在本地先体验 Skills 时，可在项目根目录运行公开样例：

```bash
make quickstart
.venv/bin/python src/secweaver.py list

.venv/bin/python src/secweaver.py skill alert-confirmation \
  -i examples/alert-confirmation/s4-webshell-attack-success.json

.venv/bin/python src/secweaver.py skill traceability-analysis \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json
```

这些命令使用公开离线样例，不会查询客户 Data Cloud。正式调查应使用已经配置好客户
DataAsset 和查询权限的分析环境。

## 4. 客户侧常见问题

| 现象 | 处理方式 |
|---|---|
| 安装命令仍有 `<...>` 或 `YOUR_...` | 不要执行，回到 Data Cloud 重新生成；仍存在占位符时联系平台运营人员 |
| 安装时报令牌无效 | 令牌可能过期、暂停或撤销，请平台运营人员重新签发 |
| 安装时报订阅或设备额度错误 | 联系平台运营人员续订或增加设备额度 |
| Linux Agent 未运行 | 执行 `systemctl status secweaver-agent` 和严格 preflight，将输出交给平台运营人员 |
| Windows Agent 未运行 | 执行 `Get-Service SecWeaverAgent`，确认使用管理员 PowerShell 安装 |
| 主机在线但没有数据 | 先等待一个采集周期；仍无数据时在 Data Cloud 查看数据延迟并联系平台运营人员 |
| Skill 返回证据不足 | 查看 `data_gaps`，先运行 `data-source-completeness`，不要强行要求确定结论 |
| Skill 查不到目标 | 核对主机名、资产 ID、时间窗和时区，确认目标主机在 Data Cloud 中在线 |

生产环境不应通过 `curl -k` 或关闭 HTTPS 校验规避证书问题。遇到证书错误时，停止安装并
联系平台运营人员修复 Data Cloud 的受信任证书。

## 5. 进一步阅读

- [项目 Skills 与使用方式](06-skills-and-usage.zh-CN.md)
- [数据源完整性](15-data-source-completeness.zh-CN.md)
- [告警确认](17-alert-confirmation.zh-CN.md)
- [溯源分析](18-traceability-analysis.zh-CN.md)
- [风险识别](19-risk-identification.zh-CN.md)
- [日常运营检查与排错](09-operations-troubleshooting.zh-CN.md)
- [secweaver-agent 部署手册](../src/tools/secweaver-agent/README.zh-CN.md)
