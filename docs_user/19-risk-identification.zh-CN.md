# 风险识别

**语言：** [English](19-risk-identification.md) | 简体中文（本文）

已经观察到的主机行为中，哪些需要优先处理，为什么？

## 1. 先运行固定离线样例

先在仓库根目录完成 `make quickstart`，然后在 智能体中输入：

```text
运行 SecWeaver 离线案例 reverse-shell-risk。
解释反弹 Shell 行为、严重级别、证据、MITRE 映射和处置优先级，不执行处置操作。
```

该案例使用 [examples/risk-identification/s5-reverse-shell-p0.json](../examples/risk-identification/s5-reverse-shell-p0.json)，由 `risk-identification` 分析。
输入是合成证据，不读取生产数据；AI 必须遵循对应 Skill，不能只复述脚本输出。

没有 智能体时可先运行确定性分析：

```bash
make ai-showcase CASE=reverse-shell-risk
```

## 2. 结果怎么看

JSON 位于 `outputs/ai-showcase/reverse-shell-risk.json`；智能体按 Skill 撰写的
Markdown 报告保存在旁边。CLI 默认也生成可读的 Markdown 结构化结果报告；
智能体继续完成证据复核与完整 Skill 报告，不需要追加报告指令。

固定样例的预期为 `overall_verdict=high_risk_detected`、`summary.p0=1`，不是对其他数据的预设答案。

| 检查项 | 验收要求 |
|---|---|
| 结论 | 明确说明发生了什么，而不只给严重级别 |
| 证据 | 关键判断对应事件引用，并核对目标主机及时间 |
| 关联 | 说明为什么这些事件有关联，不把相邻时间当成因果 |
| 缺口 | 明确哪些范围无法确认，不能把没有日志解释为没有攻击 |
| 建议 | 区分补充取证和需人工授权的处置 |

## 3. 换成真实数据

先按 [SaaS SLS Proxy 指南](30-sls-proxy-onboarding.zh-CN.md) 或
[自有数据源指南](03-configure-data-sources.zh-CN.md)完成接入与只读查询验收。
指定实际 Asset/Bundle、资产根目录、主机或 IP、带时区的起止时间。
不要复制样例的固定日期或资产 ID 后直接查询生产环境。

向 AI 提出：

```text
使用 risk-identification 分析我指定的已授权资产和时间窗。
先检查数据完整性，再按 Skill 检索证据；所有关键判断引用证据并说明缺口。
不要执行封禁、删除或隔离等处置动作。
```

尚未指定目标或时间窗时应先补齐，不能默认全量扫描。
查询凭证由本地凭证存储提供，不应出现在提示词中。

## 4. 证据不足时

该技能评估已观察到的事件及同主机上下文，不等同于完整跨主机攻击链。缺失主机日志必须体现在覆盖提醒或数据缺口中；P0 应优先调查，但有破坏性的处置仍需明确授权。

如果样例结果不符合预期，先确认选对案例和输入，再看 CLI 错误与依赖；
如果真实数据无结果，检查时间字段、别名、权限和传输延迟，不先修改判定规则。

## 5. 进阶参考

- [risk-identification 规范](../src/skills/risk-identification/SKILL.md)
- [设计与实现](../docs_dev/17-risk-identification-skill-design.zh-CN.md)
- [数据完整性](15-data-source-completeness.zh-CN.md)
- [离线案例索引](../examples/ai-showcase/README.zh-CN.md)

## 运营规则的维护边界

日常检测模式维护 `src/skills/risk-identification/rules/*.json`，告警、抑制和例外
维护 `behavior-policy.md`；按[规则说明](../src/skills/risk-identification/rules/README.zh-CN.md)
和[运营手册](../src/skills/risk-identification/OPS-HANDBOOK.zh-CN.md)操作。
普通规则调整不需要直接修改 Python。平台告警/降噪策略同步维护 `behavior-policy.md` 和
`rules/behavior-policy.rules.json`；环境范围例外使用仍默认启用的 `whitelist.json`，
按[白名单指南](../src/skills/risk-identification/whitelist.zh-CN.md)限定适用范围。
跨主机调查转交 [溯源分析](18-traceability-analysis.zh-CN.md)。
