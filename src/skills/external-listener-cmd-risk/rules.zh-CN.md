# 命令风险规则参考

本页说明规则分工，不是运行时加载文件。统一执行入口是 [risk-identification](../risk-identification/SKILL.zh-CN.md)。

| 层 | 权威配置 | 职责 |
|---|---|---|
| 检测 | [exec-rules.json](../risk-identification/rules/exec-rules.json) | 按 pipeline 生成检测命中、初判等级与标签 |
| 行为策略 | [behavior-policy.rules.json](../risk-identification/rules/behavior-policy.rules.json) | 硬护栏、强制告警、运营降噪与默认裁决 |
| 环境白名单 | [whitelist.json](../risk-identification/whitelist.json) | 在策略之后按环境范围抑制或降级，保留证据与护栏 |

## 理解结果

- shell、反弹、下载执行、持久化修改、敏感文件读取等是不同检测线索；不要只按工具名推断最终等级或攻击结果。
- `matched_rules` 记录检测命中；`policy_rule_id` 说明策略裁决，两者不能互相冒充。
- 普通命令没有检测命中，也可能被 `DEFAULT-ALERT` 判为 P1。样例中的 nginx → ls 即属此类。
- `scp`、DNS、外连只提供传输或网络线索，不能独立证明数据外传。
- 同窗 connect/file_op 可以补充上下文，不能在模型侧任意增加 severity/confidence；最终结果由父引擎产生。

## 修改与复验

规则 ID、具体模式和当前检测等级查 [检测目录](../risk-identification/detection-catalog.zh-CN.md)，JSON 语法查 [规则包参考](../risk-identification/rules/README.zh-CN.md)。策略理由与 JSON 必须同步维护，环境例外见 [白名单说明](../risk-identification/whitelist.zh-CN.md)。

使用 [可复现样例](examples.zh-CN.md) 验证最终裁决。变更还应覆盖应命中与不应命中的输入；不要把此文中的模式解释当成可导入的规则文件。
