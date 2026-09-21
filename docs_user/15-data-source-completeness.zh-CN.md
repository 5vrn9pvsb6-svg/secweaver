# 数据源完整性分析

**语言：** [English](15-data-source-completeness.md) | 简体中文（本文）

> SecWeaver Skill 文档
> 用途：网络安全事件溯源 / 告警深度确认**之前**，检测已接入数据源是否完整，并给出接入建议  
> Agent Skill：`src/skills/data-source-completeness/SKILL.md`  
> 评估脚本：`src/skills/data-source-completeness/scripts/check.py`

---

## 先体验：证据不完整时会怎样？

完成 `make quickstart` 后，在 智能体中输入：

```text
运行 SecWeaver 离线案例 missing-host-exec-data。
说明缺少哪些证据、哪些结论不能作出，以及应该先接入什么数据。
```

输入是[缺失主机执行证据的固定样例](../examples/data-source-completeness/s1-not-traceable-missing-exec.json)，
预期 `overall_verdict=not_traceable`、`can_trace=false`、`can_confirm_breach=false`。
JSON 位于 `outputs/ai-showcase/missing-host-exec-data.json`，AI 报告保存于旁边。
缺口报告是本例的正确结果，不是产品故障；不应为了得到攻击链而跳过门禁。

无智能体时可以运行 `make ai-showcase CASE=missing-host-exec-data`，默认生成 JSON 和可读的 Markdown 结构化结果报告。
真实环境先[接入数据](30-sls-proxy-onboarding.zh-CN.md)，再指定实际 Asset/Bundle 和带时区
的时间窗；样例中的固定值不代表你的生产资产。下面是完整规则与判断参考。

### 精确主机覆盖

对于 `target_hosts` 和 `jump_hosts`，资产与调查都列出主机时，按集合匹配：
覆盖全部目标为 `full`，仅覆盖部分为 `partial`，完全不匹配为 `none`。
匹配的 `coverage.hosts` 不需要额外添加区域标签；明确的主机列表约束宽泛的区域声明，
不代表覆盖整个网络。调查未列明主机时，保留已有区域匹配逻辑。
单个数据源的主机覆盖完整，不等于整项调查完整，仍需检查字段、其他数据源和查询完整性。

## 一、技能定位

### 1.1 解决什么问题

溯源调查常见困境：

| 现象 | 根因 |
|---|---|
| 知道外网攻击 IP，查不出横向范围 | 缺 SSH 日志或 WEB 主机 exec |
| WAF 有告警，不知道有没有打穿 | 缺主机行为数据（D2） |
| AI 给出「已确认入侵」但无证据 | 数据不足时仍强行下结论 |

本 Skill 在调查开始前回答三个问题：

1. **现有数据能查到什么程度？**
2. **缺什么数据源？缺了会查不出什么？**
3. **应该先接入哪些数据源？怎么接？**

### 1.2 在六大能力中的位置

```text
资产/数据管理 → 【数据源完整性分析】→ 溯源分析 / 告警确认 / 风险识别
```

**原则**：P0 数据源缺失时，**阻断**下游溯源 Skill，避免过度自信的错误结论。

---

## 二、对话框使用方式

### 2.1 基本操作

1. 在 智能体中指定已注册的资产或 Bundle、目标及时间窗
2. 选择 Skill：**数据源完整性分析**（或自然语言描述意图）
3. 填入调查参数，例如：

```text
报警时间 2026-06-21 10:00，黑客 IP 203.0.113.10
可能已被打穿，查第一个攻破点和横向范围
你缺少什么数据告诉我
```

### 2.2 输出内容

智能体 输出两部分：

- **结构化 JSON**：供平台流水线、报告、下游 Skill 消费
- **Markdown 摘要**：给安全同学直接阅读

---

## 三、调查场景

| ID | 场景 | 典型表述 |
|---|---|---|
| S1 | 外网攻击 IP 溯源 | 已知黑客 IP，查打穿点与横向 |
| S2 | WEB 入侵溯源 | WebShell、漏洞利用、网站被黑 |
| S3 | 横向移动调查 | SSH/RDP 内网扩散 |
| S4 | WEB 告警确认 | WAF 告警误报还是真实攻击 |
| S5 | 主机异常行为 | 对外监听进程 exec/connect |
| S6 | 账号失陷 | 异常登录、暴力破解 |
| S7 | 数据外传 | 大量下载、异常外连 |
| S8 | C2 通信检测 | 可疑回连、反弹 Shell、C2/DGA 域名 |

场景可多选叠加；智能体合并 P0 需求后取最严格结论。

### S8 数据需求

以下要求与 `src/skills/data-source-completeness/scenarios.json` 一致：

| 优先级 | 资产类型 | 最小字段 |
|---|---|---|
| P0 | `host_connect` | `host`、`dst_ip`、`dst_port`、`timestamp` |
| P1（二选一） | `network_traffic_audit` 或 `proxy_log` | 流量审计：`src_ip`、`dst_ip`、`dst_port`、`bytes`、`timestamp`；代理：`src_ip`、`dst_ip`、`timestamp` |
| P1 | `dns_log` | `client_ip`、`query`、`timestamp` |
| P1 | `host_exec` | `host`、`command`、`timestamp` |
| P2 | `syslog_risk_alert` | `host_ip`、`event_type`、`timestamp` |

P0 缺失会阻塞下游分析；P1 缺失应说明覆盖限制。DNS 不能替代网络会话证据。

---

## 四、数据域与资产类型

### 4.1 七大数据域

| 域 | 说明 | 典型来源 |
|---|---|---|
| D1 | 边界与 WEB | WAF、CDN、WEB 访问日志 |
| D2 | 主机行为 | exec、connect、file、EDR |
| D3 | 认证访问 | SSH、VPN、AD、堡垒机 |
| D4 | 网络 | 防火墙、NetFlow、DNS、代理 |
| D5 | 安全告警 | IDS、SOC 平台 |
| D6 | 资产配置 | CMDB、漏洞扫描 |
| D7 | 应用业务 | 应用日志、DB 审计 |

### 4.2 SecWeaver 已支持资产类型

| asset_type | 名称 | 采集方式 |
|---|---|---|
| `waf_alert` | WAF/WEB 安全告警 | 产品 API/syslog |
| `web_access_log` | WEB 访问日志 | Nginx/Apache/IIS |
| `host_exec` | 主机命令执行 | **audit-port-execmon** |
| `host_connect` | 主机主动外连 | **audit-port-execmon** (connect) |
| `host_file_op` | 主机文件操作 | **audit-port-execmon** (file_op) |
| `windows_event_log` | Windows 系统/安全/应用事件日志 | Winlogbeat、WEF、NXLog → SLS |
| `linux_syslog` | Linux 系统/syslog 日志 | rsyslog、journald、Filebeat → SLS |
| `ssh_auth` | SSH 认证日志 | auth.log / journald |
| `firewall_log` | 防火墙日志 | syslog / NetFlow |
| `network_traffic_audit` | 全流量审计（NDR/TAP 会话/流） | NDR 平台、TAP 镜像分析 → SLS/ES |
| `dns_log` | DNS 查询 | DNS 服务器 / 安全网关 |
| `asset_inventory` | 资产清单 | CMDB |

---

## 五、完整性评估四维

对每个已注册数据源评估：

| 维度 | 说明 |
|---|---|
| **覆盖度** | 调查涉及的主机/网段是否都有数据 |
| **关联键** | src_ip、host、timestamp 等能否跨源 join |
| **时间窗** | 是否覆盖调查时段（默认告警前 24h ~ 后 6h） |
| **字段粒度** | 如 WAF 是否含 payload、SSH 是否含 src_ip |

单项结论：`ready` / `partial` / `missing`

---

## 六、实战：外网 IP 溯源

### 6.1 事件背景

- WEB 服务器（有 WEB 安全日志）+ 内网 SSH 服务器
- 攻击链：WebShell → curl 下载 SSH 暴力破解工具 → SSH 横向
- 已知：外网黑客 IP、事件时间 A

### 6.2 P0 最低要求

| 数据源 | 用途 |
|---|---|
| WAF/WEB 日志 | 确认攻击 IP 首次出现、命中 URL |
| **WEB 主机 exec** | 确认 WebShell、curl/bash 下载 |
| SSH auth 日志 | 追踪横向登录 |

### 6.3 仅有 WAF + 部分 SSH 时

智能体 应输出：

```markdown
## 数据源完整性评估

**结论**：不可完整溯源（缺少 P0：WEB 服务器进程命令执行）

### 关键缺口
1. **WEB 服务器进程命令执行**（P0）
   - 缺了会导致：无法确认 WebShell、curl 下载 SSH 工具，不能证明打穿
   - 建议接入：在 WEB 服务器部署 audit-port-execmon

### 下一步
请先接入 WEB 主机 exec 后再启动溯源分析。
```

---

## 七、整体结论说明

以下结论评估注册元数据，不代表本次实际返回的事件。取数后还要检查
`fetch_summary.evidence_readiness` 和 `query_integrity`：即使元数据为
`full_traceable`，实际证据仍可能是 `no_evidence` 或 `partial`。附带预检以
`assessment_basis=registry_metadata`、`metadata_readiness` 标明此区别，保留旧字段兼容。
查询成功但无数据不是查询失败，也不能支持“安全无异常”的结论；未查询的声明资产标为
`not_queried`。

| overall_verdict | 含义 | 动作 |
|---|---|---|
| `full_traceable` | 注册需求已满足 | 取数并检查实际证据后再形成溯源结论 |
| `partial_traceable` | 可部分溯源 | 启动溯源，标注置信度上限 |
| `not_traceable` | P0 缺失 | **先补数据** |
| `alert_triage_only` | 仅 WEB/WAF | 只能告警分类，不能证明打穿 |

---

## 八、确定性评估脚本

平台或流水线可调用 Python 脚本，与 智能体 使用同一套 `scenarios.json`：

```bash
.venv/bin/python src/skills/data-source-completeness/scripts/check.py \
  -i src/skills/data-source-completeness/scripts/input.example.json
```

输入示例见 `src/skills/data-source-completeness/scripts/input.example.json`。

---

## 九、与下游 Skill 衔接

| 上游结论 | 下游 Skill |
|---|---|
| S1/S2/S3/S6/S7 且未 blocked | 溯源分析 `traceability-analysis` |
| S4 且未 blocked | 告警确认 `alert-confirmation` |
| S5 且未 blocked | 风险识别 `risk-identification`（主机异常行为） |
| S8 且未 blocked | 风险识别 `risk-identification`（C2 通信风险） |
| blocked | 仅输出接入建议，不启动下游 |

上述为 Skill 目录名；脚本输出的 `next_skill` 对溯源和告警分别使用
`traceability_analysis`、`alert_confirmation`。多场景输入按输入顺序选择首个已配置的下游入口。
即使 `next_skill` 非空，也必须检查 `next_skill_blocked`，不能把入口建议当成执行许可。

---

## 十、相关文件

| 文件 | 说明 |
|---|---|
| `src/skills/data-source-completeness/SKILL.md` | 智能体 执行入口 |
| `src/skills/data-source-completeness/rules.md` | P0/P1/P2 规则矩阵 |
| `src/skills/data-source-completeness/scenarios.json` | 机器可读场景需求 |
| `src/skills/data-source-completeness/examples.md` | 输入输出样例 |
| `docs_dev/13-data-source-completeness-skill-design.md` | 详细设计文档 |
| `src/skills/data-source-completeness/scripts/check.py` | 确定性评估脚本 |

---

*文档版本：v1.1 | 更新日期：2026-09-16*
