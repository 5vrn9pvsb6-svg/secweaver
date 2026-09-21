# 05. Scenario Pattern 详解：告诉 AI 先查什么

**语言：** [English](05-scenario-patterns.md) | 简体中文（本文）

> 本文是场景编排的概念入门；字段、运行时行为和维护规则见[场景配置参考](22-scenario-patterns.zh-CN.md)。

`Scenario Pattern` 是 SecWeaver 里最重要的配置之一。它的作用是把安全运营经验变成机器可读的“调查剧本”。

如果你只记一句话：

```text
Scenario Pattern 不负责判断结论，它负责告诉系统：遇到某类问题，应该从哪里开始查、查哪些数据、按什么链路查。
```

对应配置文件：

```text
dataasset/scenarios/anchor-patterns.json
```

本文负责概念与阅读示例。字段、运行时支持、配置新增与校验统一维护在 [详细配置参考](22-scenario-patterns.zh-CN.md)，避免两处维护同一契约。
## 1. 为什么需要 Scenario Pattern？

很多安全调查不是“查一个日志”就能完成，而是一条路径。

例如一条 WAF 告警：

```text
WAF 告警
→ Web 访问日志
→ 主机命令执行
→ 文件操作
→ 主机外连
```

如果没有 Scenario Pattern，大模型可能每次都自己判断先查什么。这样会有几个问题：

| 问题 | 后果 |
|---|---|
| 每次调查顺序不同 | 同一事件可能得出不同结论 |
| 模型不知道你有哪些数据 | 容易建议不存在的数据源 |
| 取数范围不固定 | 复核困难 |
| 时间窗靠模型猜 | 容易误关联或漏关联 |
| 缺少数据时说不清 | 不能稳定输出 data_gaps |

所以 Scenario Pattern 的价值是：

```text
把“运营专家会怎么查”固化成配置，让 AI 沿着可靠路径执行。
```

## 2. Scenario Pattern 和大模型怎么分工？

不要把 Scenario Pattern 理解成替代大模型。

更合理的分工是：

| 角色 | 负责什么 |
|---|---|
| 大模型 | 理解用户问题、选择可能的场景、解释证据、输出研判 |
| Scenario Pattern | 指定调查入口、默认时间窗、推荐数据链路、资产包 |
| Correlation Matrix | 指定证据之间怎么 Join |
| Query Template | 指定实际怎么查数据 |
| Fetch Plan | 把调查链路变成可执行取数任务 |

也就是说：

```text
大模型负责“理解和解释”；
Scenario Pattern 负责“调查路径”；
Correlation Matrix 负责“证据关联规则”。
```

## 3. 一次调查中 Scenario Pattern 在哪里生效？

典型流程：

```text
用户问题
  ↓
大模型或系统识别场景，例如 S4 告警确认
  ↓
选择 Scenario Pattern，例如 S4_alert_confirmation
  ↓
读取 anchor、investigation_window、recommended_chain、bundle_id
  ↓
根据 recommended_chain 到 Correlation Matrix 找 Join
  ↓
根据 Join.fetch_plan 生成取数任务
  ↓
Fetch 拉取 evidence
  ↓
Correlation Engine 生成 join_edges / data_gaps
  ↓
大模型解释证据并输出结论
```

所以 Scenario Pattern 是“场景 → 数据 → 关联链”的入口。

## 4. 一个 Scenario Pattern 长什么样？

简化示例：

```json
{
  "S1_external_ip_trace": {
    "label": "外网 IP 溯源",
    "investigation_window": "trace_default",
    "anchor": {
      "field": "src_ip",
      "field_variants": ["ip", "client_ip"],
      "from": "params.attacker_ip",
      "fallback_asset_types": ["waf_alert", "web_access_log"]
    },
    "recommended_chain": [
      "waf_to_web_access_by_ip",
      "web_access_to_host_exec",
      "attacker_ip_to_ssh_auth",
      "host_ip_to_ssh_auth_lateral",
      "firewall_web_to_internal"
    ],
    "bundle_id": "bundle-incident-trace-default"
  }
}
```

这段配置表达的是：

```text
如果用户要做外网 IP 溯源：
1. 从 attacker_ip 入手；
2. 默认使用 trace_default 时间窗；
3. 先查 WAF / Web；
4. 再沿着 Web → 主机执行 → SSH → 防火墙链路关联；
5. 使用 bundle-incident-trace-default 这个资产包。
```

---

## 5. 当前 S1-S8 场景怎么理解？

| 场景 | 名称 | 常见锚点 | 主要目标 |
|---|---|---|---|
| S1 | 外网 IP 溯源 | `attacker_ip` / `src_ip` | 查攻击 IP 是否打进来、影响哪些主机 |
| S2 | WEB 入侵 / WebShell | `url` / `src_ip` | 查 Web 攻击是否打穿、是否落地 |
| S3 | 横向移动追踪 | `host_ip` / `user` | 查是否从一台机器扩散到其他机器 |
| S4 | 告警确认 | WAF 告警字段 | 判断误报、真实攻击、是否成功 |
| S5 | 主机行为风险 | `host` | 查主机命令、外连、文件操作风险 |
| S6 | 账号失陷追踪 | `user` | 查账号是否异常登录和后续行为 |
| S7 | 数据外传追踪 | `host` / `dst_ip` / `domain` | 查外连、DNS、流量、数据库访问 |
| S8 | C2 通信检测 | `host` / `dst_ip` / `domain` | 识别可疑回连、关联进程和 DNS，并补充网络会话证据 |

## 6. 配置与验证

默认配置位于 `dataasset/`；需要隔离时可复制为 `dataasset_my/` 并设置 `DATAASSET_ROOT`。修改前先在[配置参考](22-scenario-patterns.zh-CN.md)确认字段与运行时支持，再运行 `python3 src/secweaver.py validate` 和对应离线示例。关联命中不是攻击成功证明，未命中也不能替代数据完整性检查。
