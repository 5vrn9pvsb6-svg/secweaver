# 数据源完整性分析技能设计

> 公开案例与输入输出见[技能示例](../src/skills/data-source-completeness/examples.zh-CN.md)，无需内部产品规划材料。

**语言：** [English](13-data-source-completeness-skill-design.md) | 简体中文（本文）

> SecWeaver 六大核心能力之一  
> 用途：在**网络安全事件溯源调查**或**告警深度确认**前，检测已接入数据源是否足够支撑分析，并给出缺失数据源的接入建议

---

## 一、技能定位

### 1.1 解决什么问题

安全同学发起调查时常遇到：

- 「只有 WAF 告警，不知道有没有打穿」
- 「知道外网攻击 IP，但查不出横向到哪几台机器」
- 「有 SSH 登录失败日志，但不知道最初从哪台 Web 进来的」

根因往往不是 AI 不会分析，而是**数据源不完整、关联键缺失、时间窗口不够**。

本 Skill 的职责：

```text
输入：调查场景 + 已注册的数据资产清单 +（可选）调查参数（攻击 IP、时间、主机）
输出：完整性评估 + 能否支撑溯源/确认 + 缺失数据源清单 + 接入优先级建议
```

### 1.2 与其他 Skill 的关系

| 顺序 | Skill | 关系 |
|---|---|---|
| 1 | **数据源完整性分析** | 先判断「能不能查」 |
| 2 | 告警确认 | 数据够才做误报/真实攻击研判 |
| 3 | 溯源分析 | 数据够才还原攻击链 |
| 4 | 风险识别 | 主机侧 exec/connect 是完整性的一部分 |

---

## 二、调查场景模型

Claw 首先识别用户意图属于哪类场景（可多选）：

| 场景 ID | 场景名称 | 典型用户表述 |
|---|---|---|
| `S1` | 外网攻击 IP 溯源 | 已知黑客 IP，查打穿点和横向范围 |
| `S2` | WEB 入侵溯源 | WebShell、漏洞利用、网站被篡改 |
| `S3` | 横向移动调查 | SSH/RDP/SMB 内网扩散 |
| `S4` | WEB 告警确认 | WAF/WEB 安全告警是否真实、是否成功 |
| `S5` | 主机异常行为调查 | 对外服务进程执行命令、主动外连 |
| `S6` | 账号失陷调查 | 异常登录、暴力破解、特权账号 |
| `S7` | 数据外传调查 | 大量下载、异常外连、敏感文件打包 |
| `S8` | C2 通信检测 | 可疑回连、反弹 Shell、C2/DGA 域名 |

---

## 三、数据源 taxonomy（标准清单）

### 3.1 七大数据域

| 数据域 | 说明 | 典型数据源 |
|---|---|---|
| **D1 边界与 WEB** | 对外攻击入口 | WAF、CDN、负载均衡、WEB 访问/错误日志 |
| **D2 主机行为** | 服务器上发生了什么 | exec 命令、主动外连、文件创建删除、EDR |
| **D3 认证与访问** | 谁登录了谁 | SSH/auth.log、VPN、AD、堡垒机、RADIUS |
| **D4 网络流量** | 谁连了谁 | 防火墙、NetFlow/sFlow、全流量、DNS、代理 |
| **D5 安全告警** | 各安全产品结论 | IDS/IPS、HIDS、AV、SOC 平台告警 |
| **D6 资产与配置** | 上下文 | CMDB、资产清单、端口服务、漏洞扫描 |
| **D7 应用与业务** | 业务侧证据 | 应用日志、数据库审计、API 网关 |

### 3.2 SecWeaver 已落地/规划数据源

| 数据源 | 数据域 | 采集方式 | 关联键 |
|---|---|---|---|
| WEB 安全告警/WAF | D1/D5 | 产品接入 | src_ip, time, url, rule_id |
| 进程命令执行 exec | D2 | audit-port-execmon | host, pid, time, command |
| 进程主动外连 connect | D2 | audit-port-execmon | host, pid, dst_ip, dst_port, time |
| 文件创建删除 file_op | D2 | audit-port-execmon | host, path, time, pid |
| SSH 认证日志 | D3 | syslog/rsyslog | host, src_ip, user, time, result |
| 防火墙/边界日志 | D4 | syslog/API | src_ip, dst_ip, port, time |
| DNS 日志 | D4 | 专用采集 | query, client_ip, time |
| 资产清单 | D6 | CMDB/手动注册 | hostname, ip, owner, zone |

---

## 四、完整性评估维度

对每个已注册数据源，评估四个维度：

| 维度 | 说明 | 等级 |
|---|---|---|
| **覆盖度 Coverage** | 相关主机/网段/业务是否都有 | 全量 / 部分 / 缺失 |
| **关联键 Keys** | 能否与 IP、时间、主机、用户关联 | 完备 / 部分 / 缺失 |
| **时间窗 Time** | 是否覆盖调查时间段 ± 缓冲 | 满足 / 不足 / 未知 |
| **粒度 Granularity** | 字段是否够分析（如 WAF 有无 payload） | 够 / 不够 / 未知 |

### 4.1 关联键最低要求

溯源调查至少需要以下关联能力中的 **3 项**：

```text
src_ip（攻击源）
dst_ip / host（受害目标）
timestamp（统一时区，精度到秒）
user / account（账号维度）
process / command（主机行为）
session / flow（网络会话）
```

---

## 五、场景 × 数据源需求矩阵

### S1 外网攻击 IP 溯源（公开调查示例）

**事件**：黑客 IP A，时间 A，可能已打穿，查第一个攻破点 + 横向范围。

| 优先级 | 必需数据源 | 用途 | 缺失影响 |
|---|---|---|---|
| P0 | WEB/WAF 日志（D1） | 确认是否命中 Web、首次出现时间 | 无法定位入口 |
| P0 | WEB 服务器主机 exec（D2） | 确认 WebShell、curl/wget 下载 | 无法证明打穿 |
| P0 | SSH 认证日志（D3） | 横向登录、暴力破解 | 无法追踪横向 |
| P1 | 主机主动外连 connect（D2） | 下载工具、C2 外连 | 攻击链不完整 |
| P1 | 防火墙/内网流量（D4） | Web→内网 SSH 连接 | 横向路径不清 |
| P1 | DNS 日志（D4） | 下载域名、C2 域名 | 只能看到 IP |
| P2 | 文件操作 file_op（D2） | WebShell 落地路径 | 难证明持久化 |
| P2 | EDR（D2） | 统一主机行为视图 | 依赖单点工具 |
| P2 | 资产清单（D6） | 知道有哪些 SSH 服务器 | 横向范围漏扫 |

**最低可分析条件（MVP）**：

> WAF/WEB 日志 + WEB 主机 exec + 至少一台 SSH auth 日志 + 统一时间窗

---

### S4 WEB 告警确认

| 优先级 | 必需数据源 | 用途 |
|---|---|---|
| P0 | WEB/WAF 告警含 payload | 判断是否真实攻击载荷 |
| P0 | WEB 访问日志 | 告警前后请求上下文 |
| P1 | WEB 主机 exec/connect | 确认是否攻击成功（有无 shell、外连） |
| P1 | 文件操作 | 是否落地 WebShell |
| P2 | 漏洞扫描/资产 | 被攻击 URL 对应组件版本 |

---

### S5 主机异常行为（对接 audit-port-execmon）

| 优先级 | 必需数据源 | 用途 |
|---|---|---|
| P0 | 进程命令执行 exec | 核心分析对象 |
| P1 | 主动外连 connect | 下载、C2 |
| P1 | 文件操作 file_op | WebShell、落地 |
| P2 | WEB/WAF | 解释「谁触发了异常命令」 |

---

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

S8 未被阻塞时，`next_skill_map` 指向 `risk-identification`；输出仍须遵守
`next_skill_blocked`。调查提问与链路示例见[调查场景 S8](../docs_user/08-investigation-scenarios.zh-CN.md#s8c2-通信检测)。

---

## 六、完整性评分模型

### 6.1 单数据源状态

| 状态 | 含义 |
|---|---|
| `ready` | 已接入且满足场景需求 |
| `partial` | 已接入但覆盖/字段/时间窗不足 |
| `missing` | 场景需要但未接入 |
| `optional` | 有则更好，无也可降级分析 |

### 6.2 场景整体结论

下表按 [overall_verdict](../src/skills/data-source-completeness/scripts/check.py) 的判定顺序排列；这些是预检枚举，不是攻击结论。

| 顺序 | 条件 | 输出与下游行为 |
|---|---|---|
| 1 | 任一 P0 为 `missing` | `not_traceable`，阻断下游 |
| 2 | 包含 S4，有 WAF/WEB 资产但没有 D2 资产 | `alert_triage_only`，阻断自动下游；单独的告警初筛需明确能力边界 |
| 3 | P0 均为 `ready` 或 `partial`，P1 数量大于 0，且 `(P1_ready + 0.5 × P1_partial) / P1_total ≥ 0.8` | `full_traceable`，允许按场景衔接 |
| 4 | P0 均为 `ready` 或 `partial`，但不满足上一项 | `partial_traceable`，保留缺口后分析 |
| 5 | 其他情况 | `not_traceable`，阻断下游 |

P0 `partial` 不等于 `missing`，不会仅因此阻断；`full_traceable` 也不保证每项字段和覆盖完整。消费者仍须展示逐项缺口与 `next_skill_blocked`。P1 为零时不会进入第三行。

### 6.3 置信度

```text
P0_ready_rate = P0_ready / max(P0_total, 1)
P1_weighted_rate = (P1_ready + 0.5 × P1_partial) / max(P1_total, 1)
confidence = round(clamp(0.40 × P0_ready_rate + 0.35 × P1_weighted_rate
                        + 0.15 × key_score + 0.10 × time_score, 0, 1), 2)
若 key_score < 0.7：confidence = min(confidence, 0.75)
```

P0 `partial` 可通过门禁，但不计入置信度的 P0_ready；P1 `partial` 按半项计分。
`key_score` 来自已注册字段的关联键覆盖；存在 `retention_insufficient` 时 `time_score=0.6`，否则为 `1.0`。该评分不等同于攻击发生概率。

**评分示例**：S8 的 1 项 P0 为 `partial`，3 项 P1 全部 `ready`，`key_score=1`、`time_score=1`，且已注册 `host_connect`：结论为 `full_traceable`、`next_skill_blocked=false`，置信度为 `0.60`。P0 缺口仍应展示；把同一项改为 `missing` 后会先进入阻断分支。

---

## 七、Claw 研判流程

```text
1. 解析调查意图 → 匹配场景 S1-S8（可多选）
2. 读取用户选择的「已注册数据资产」清单
3. 提取调查参数：攻击 IP、时间范围、涉及主机/业务、告警 ID 等
4. 按场景矩阵逐项对照：ready / partial / missing
5. 检查关联键：src_ip、host、timestamp 能否跨源 join
6. 检查时间窗：是否覆盖 [T-Δ, T+Δ]（默认告警前 24h ~ 后 6h）
7. 输出整体结论 + 缺失清单 + 按优先级排序的接入建议
8. 若用户问「缺少什么数据」→ 明确列出，并说明「缺了会导致查不出什么」
```

---

## 八、接入建议模板

每条建议包含：

| 字段 | 说明 |
|---|---|
| `source_name` | 建议接入的数据源名称 |
| `domain` | D1-D7 |
| `priority` | P0/P1/P2 |
| `reason` | 为什么需要 |
| `impact_if_missing` | 缺失导致查不出什么 |
| `collection_hint` | 怎么接（产品/API/auditd/syslog） |
| `correlation_keys` | 接入后提供的关联键 |
| `tiger_brain_asset_type` | 注册到平台时的资产类型建议 |

### 示例建议

```json
{
  "source_name": "WEB服务器进程命令执行",
  "domain": "D2",
  "priority": "P0",
  "reason": "S1 外网 IP 溯源需确认 Web 打穿后是否执行 curl/bash",
  "impact_if_missing": "无法证明攻击成功，只能看到 WAF 告警无法形成攻击链",
  "collection_hint": "Linux 主机部署 audit-port-execmon，开启 exec 监控",
  "correlation_keys": ["host", "timestamp", "pid", "command"],
  "tiger_brain_asset_type": "host_exec"
}
```

---

## 九、Claw 输出 JSON 模板

以下是[缺少 P0 主机执行数据的公开合成样例](../examples/data-source-completeness/s1-not-traceable-missing-exec.json)经当前评估脚本生成的实际输出摘录，只保留结论、缺失项和下游门禁字段。完整输出还包含逐项评估、已注册资产、接入建议等字段。

完成 `make quickstart` 后，在仓库根目录运行：

```bash
make ai-showcase CASE=missing-host-exec-data
```

查看 `outputs/ai-showcase/missing-host-exec-data.json`。该命令生成确定性 JSON；智能体调查报告需按 Skill 另行生成。此例只有 S1，数值只适用于该固定样例。

```json
{
  "alert_type": "data_source_completeness",
  "scenario": [
    "S1"
  ],
  "overall_verdict": "not_traceable",
  "confidence": 0.38,
  "can_trace": false,
  "can_confirm_breach": false,
  "missing_critical": [
    {
      "source_name": "WEB 服务器进程命令执行",
      "priority": "P0",
      "requirement_id": "S1-P0-exec",
      "impact_if_missing": "无法确认 WebShell、curl/wget 下载、命令执行链，不能证明攻击成功"
    },
    {
      "source_name": "WEB 服务器主动外连",
      "priority": "P1",
      "requirement_id": "S1-P1-connect",
      "impact_if_missing": "无法关联下载域名与 C2，攻击链缺少外连证据"
    },
    {
      "source_name": "防火墙/全流量内网连接",
      "priority": "P1",
      "requirement_id": "S1-P1-fw",
      "impact_if_missing": "无法可视化内网连接路径（如 WEB→SSH）"
    },
    {
      "source_name": "DNS 查询日志",
      "priority": "P1",
      "requirement_id": "S1-P1-dns",
      "impact_if_missing": "只能看到 IP 无法解析下载/C2 域名"
    }
  ],
  "next_skill": "traceability_analysis",
  "next_skill_blocked": true,
  "block_reason": "缺少 P0 数据源: WEB 服务器进程命令执行"
}
```

`next_skill` 表示建议衔接的技能，即使被阻断也可能有值；调用方必须先检查 `next_skill_blocked`。本例缺少 P0，故 `can_trace=false`、`can_confirm_breach=false`，并提供 `block_reason`；不能因为有技能名称或非零置信度就自动继续。这里评估的是数据完整性，不是攻击是否发生。

---

## 十、公开场景与验收示例

### 实战：外网 IP 溯源（S1 + S3）

用户操作：

```text
选择全部资产
报警时间 A，黑客 IP 为 A，可能已被打穿
分析第一个攻破点 + 横向攻击事件
你缺少什么数据告诉我
```

Claw 应输出：

1. 当前资产中哪些满足 S1+S3
2. 明确说「缺少 WEB 主机 exec，因此无法确认 curl 下载 SSH 工具」
3. 明确说「缺少内网 SSH 全集覆盖，横向结论可能不完整」
4. 给出 audit-port-execmon、SSH syslog、防火墙接入建议
5. 若 P0 缺失 → `next_skill_blocked: true`，建议先补再接溯源 Skill

### 实战：WEB 告警确认（S4）

Claw 先检查：

- WAF 是否有 payload 字段
- 是否有 WEB 主机 exec 证明攻击成功
- 无 D2 → 结论只能是「疑似真实攻击，无法确认是否成功」

---

## 十一、一句话总结

**数据源完整性分析 Skill = 调查前的「体检」**：先告诉安全同学「现有数据能查到什么程度、缺什么、先接什么」，再决定是否启动溯源或告警确认，避免 AI 在数据不足时给出过度自信的错误结论。

---

*文档版本：v1.2 | 更新日期：2026-09-16*
