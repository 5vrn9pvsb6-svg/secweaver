# 07. 如何使用

**语言：** [English](07-how-to-use.md) | 简体中文（本文）

> 本文是日常调查操作指南；技能清单以[技能参考](06-skills-and-usage.zh-CN.md)为准，具体任务参数见各技能专题。

本文说明普通运营同学如何使用 SecWeaver。重点不是“和大模型随便聊”，而是：

```text
用自然语言触发合适的 Skill，
让 Skill 按固定流程取数、关联、研判、输出报告。
```

建议先阅读：[06. 项目技能与使用方式](06-skills-and-usage.zh-CN.md)。那篇文章介绍有哪些 Skill；本文讲你在日常工作中应该怎么用。

本页负责提问、执行、复核和下一步；技能选择统一见 [06 技能目录](06-skills-and-usage.zh-CN.md)。

## 1. 使用前需要确认什么？

在运行 Skill 前，最好确认：

1. 相关数据源已经配置为 `active`。
2. 数据源已经加入合适的 Bundle。
3. 查询模板能查到数据。
4. Scenario Pattern 已覆盖你的调查场景。
5. `validate.py` 没有 blocking error。
6. 如果是正式研判，最好先跑数据源完整性分析。

如果这些没有准备好，Skill 可能会输出：

```text
证据不足
数据源缺失
只能做初步判断
无法确认攻击是否成功
```

这不是坏事。好的 Skill 应该在证据不足时明确告诉你缺什么，而不是硬下结论。

## 2. 执行顺序

1. 离线初体验先完成 [快速上手](00-security-operator-quickstart.zh-CN.md)。真实查询先确认数据源、只读凭证、主机和带时区的时间窗。
2. 运行完整性预检，确认数据缺口与查询截断；授权范围内取数。
3. 按任务选择纯提示词研判或确定性规则研判；跨源调查使用告警确认或溯源分析。两条研判路径均包含在 Community。
4. 用原始证据引用复核结论，区分已证实、推测与无法判断。只在证据支持时继续下一步。
5. 本地生成报告；向钉钉等外部渠道发送必须单独明确授权。


## 3. 提问时最好提供哪些参数？

问题越具体，Skill 越容易快速取到正确数据。

建议提供：

| 参数 | 示例 | 常用 Skill | 作用 |
|---|---|---|---|
| 攻击 IP | `203.0.113.10` | `alert-confirmation`、`traceability-analysis` | 外部 IP 溯源、告警确认 |
| 告警时间 | `2026-06-28 10:00` | 所有调查类 Skill | 推导默认时间窗 |
| URL | `/upload.php` | `alert-confirmation` | 判断 Web 攻击上下文 |
| 主机名 | `web-01` | `risk-identification`、`traceability-analysis` | 主机行为调查 |
| 主机 IP | `10.0.1.5` | `traceability-analysis` | 横向移动、外连分析 |
| 账号 | `admin` | `traceability-analysis` | 账号失陷、登录行为 |
| 目标 IP / 域名 | `8.8.8.8` / `example.com` | `traceability-analysis` | 外连和外传分析 |
| 时间范围 | `10:00-12:00` | 所有取数类 Skill | 控制查询范围 |

如果你只提供一部分，Scenario Pattern 会尝试根据默认时间窗补齐，但越明确越好。

## 4. 推荐提问模板

### 4.1 数据源完整性分析模板

```text
请使用 data-source-completeness Skill 做数据源完整性分析。
场景是：外部 IP 溯源 / 告警确认 / 主机风险 / 数据外传。
已知参数：攻击 IP=...，主机=...，告警时间=...。
请告诉我：当前数据能支持什么结论、缺哪些数据、下一步应该运行哪个 Skill。
```

### 4.2 告警确认模板

```text
请使用 alert-confirmation Skill 确认这条告警。
告警类型：WAF / WEB / IDS。
攻击 IP：...
告警时间：...
URL / payload：...
请输出：是否误报、是否真实攻击、是否攻击成功、证据链、data_gaps 和处置建议。
```

### 4.3 溯源分析模板

```text
请使用 traceability-analysis Skill 做溯源分析。
攻击 IP：...
告警时间：...
已知受害主机：...
请重点回答：第一攻破点、攻击链时间线、横向移动路径、影响范围、证据链和数据缺口。
```

### 4.4 风险识别模板

```text
请使用 risk-identification Skill 分析主机风险。
主机：...
时间范围：...
请重点查看 host_exec、host_connect、host_file_op，输出 P0-P3 风险项、命中的规则、证据和处置建议。
```

### 4.5 配置校验模板

```text
请使用 dataasset-validation-advisor Skill 检查 dataasset 配置。
请区分 blocking、error、warning，并告诉我哪些必须修、哪些是 example 噪声、最小修复路径是什么。
```

### 4.6 连接性巡检模板

```text
请使用 dataasset-connectivity-check Skill 检查 active 资产连接性。
请告诉我哪些资产可以连接并取到数据，哪些是凭证问题、连接问题、模板问题或无数据。
```

## 5. 一次 Skill 调用的输入和输出

### 输入

可以是自然语言，也可以是结构化参数。

自然语言示例：

```text
用告警确认 Skill 分析 203.0.113.10 在 2026-06-28 10:00 的 WAF 告警是否攻击成功。
```

结构化示例：

```json
{
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-28T10:00:00+08:00",
    "url": "/login"
  }
}
```

### 输出

不同 Skill 输出不同，但通常包括：

- `overall_verdict`：总体结论。
- `confidence`：置信度。
- `evidence_bundles`：取回的证据集合。
- `join_edges`：证据之间的关联边。
- `data_gaps`：缺失数据或未命中的关联。
- `next_skill`：建议下一步使用哪个 Skill。
- `user_reminders`：给运营同学的提醒。
- `markdown_report`：面向人阅读的报告。

## 6. 如何理解 evidence_bundles？

`evidence_bundles` 是按数据类型分组的证据。

例如：

```text
waf_alert: WAF 告警证据
web_access_log: Web 访问证据
host_exec: 主机命令执行证据
ssh_auth: SSH 登录证据
firewall_log: 防火墙访问证据
```

你可以把它理解成：

```text
Skill 查回来的原始证据集合。
```

## 7. 如何理解 join_edges？

`join_edges` 是证据之间的关联边。

例如：

```text
WAF 告警 A 和 Web 访问 B 使用 src_ip 关联成功。
Web 访问 B 和主机命令 C 使用 host 关联成功。
SSH 登录 D 和防火墙日志 E 使用 src_ip/dst_ip 关联成功。
```

这比只看单条日志更重要，因为安全调查关注的是链路。

Skill 输出结论时，应该尽量基于 `join_edges`，而不是单条孤立日志。

## 8. 如何理解 data_gaps？

`data_gaps` 表示缺失的数据或没有命中的关联。

例如：

```text
no_match:web_access_to_host_exec
```

表示系统尝试把 Web 访问和主机命令关联起来，但没有找到匹配证据。

这不一定代表没有攻击成功，可能有几种情况：

1. 真的没有主机命令执行。
2. 主机日志没有接入。
3. 时间窗不够。
4. 字段映射不正确。
5. 查询模板没有查到对应数据。

所以看到 `data_gaps` 时，要结合数据源完整性一起判断。

## 9. 如何复核 Skill 输出？

建议按这几个问题复核：

1. 结论是否引用了具体 evidence？
2. 证据是否在合理时间窗内？
3. 关键 Join 是否成功？
4. 有没有只靠单条日志下结论？
5. 有没有明确说明 data_gaps？
6. 如果证据不足，是否给出了补充采集建议？
7. 是否建议了合理的 next_skill？

一个好的 Skill 输出应该是：

```text
有证据时说清楚证据链；
没证据时说清楚缺什么；
不确定时不要硬下结论；
需要继续调查时明确建议下一个 Skill。
```

## 10. 下一步

继续阅读：[08. 调查场景说明](08-investigation-scenarios.zh-CN.md)
