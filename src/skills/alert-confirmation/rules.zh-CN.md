# 告警确认 — 判定规则参考

本文解释确定性引擎的判定顺序；执行入口为 [confirm.py](scripts/confirm.py)，攻击类型、指标和推荐动作配置见 [attack-types.json](attack-types.json)，误报模式见 [fp-patterns.json](fp-patterns.json)。

## 1. 两层研判

先判断 `alert_verdict`（误报、扫描、可疑、真实攻击），再判断 `attack_outcome`（是否成功）。命中攻击载荷不等于攻击成功；缺少 payload 时也不能直接套用成功结论。载荷解码、规则命中与关联升级条件见 [实现设计](../../../docs_dev/14-alert-confirmation-skill-design.zh-CN.md)和 [layer1.py](scripts/alert_confirmation/layer1.py)。

## 2. 单条告警的结果顺序

以下顺序与 [layer2_outcome()](scripts/alert_confirmation/success.py) 一致：

1. `false_positive` → `not_applicable`。
2. 不属于 suspicious/scanning_or_probe/confirmed_attack 的其他输入 → `success_unknown`。
3. `mode=triage_only` → `success_unknown`，即使传入候选 D2，也不确认成功。
4. full 模式且存在经过归属检查的 `success_refs` → `success_confirmed`。
5. 无成功证据、`confirmed_attack` 且 WAF action 命中 `blocked_actions` → `blocked`。
6. 无成功证据、无 D2 → `success_unknown`。
7. 有 D2 但无成功证据 → `attempt_failed`。

`attempt_failed` 描述当前输入未找到成功指标，不保证整个环境安全。`campaign_success` 是独立的活动级结果，不能用于声称每条告警均已成功。

## 3. 哪些证据可以确认成功

窗口来自 [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json) 的 `time_windows.attack_success`，当前默认 **前 5 分钟、后 30 分钟**。匹配目标主机是前提；存在 WEB 日志时，还必须匹配成功请求上下文及其目标和时间。详细范围与回退行为由 `find_d2_success()` 实现。

| D2 来源 | 攻击类型兼容条件 |
|---|---|
| host_exec | SQLi 仅接受 database 类指标；路径遍历接受 file_read/sensitive_file_read；RCE/WebShell 接受 shell/download/webshell_cmd/file_read/sensitive_file_read；SSRF 接受 download/shell |
| host_connect | 出站指标只支持 RCE/WebShell/SSRF |
| host_file_op | 文件指标只支持 RCE/WebShell/路径遍历 |
| host_persistence | 持久化指标只支持 RCE/WebShell；未知类型与扫描指纹走通用兼容分支 |

unknown/scanner_fingerprint 的指标兼容范围较宽，但仍须经过归属与窗口检查。具体指标由 `success_indicators` 配置，兼容分支见 `_indicator_compatible()`。

**WEB 状态码不是 D2。** HTTP 200/500、异常响应体或 WAF 放行只提供上下文/候选线索，不能单独确认成功。`gateway_success_hint` 属于 D1.5 提示，可影响人工复核建议，不改写单条告警的最终结果。

## 4. 动作、置信度与下游

推荐动作依次考虑误报、已确认成功、重复真实攻击、阻断、扫描和可疑线索；`recommended_action_map`、网关提示和 IP 封禁保护会影响最终建议。成功默认建议 `escalate_investigate`，重复攻击的封禁建议还须经过 IP 属性保护，不应自动执行封禁或隔离。

置信度是规则分数。有效上限可能按 `layer1_upgrade` 中的已确认攻击/D2 成功 floor 提升，再约束最终分数；不是简单地永远取上游原始 confidence。计算公式与默认值统一见[设计文档的置信度说明](../../../docs_dev/14-alert-confirmation-skill-design.zh-CN.md)。

需要跨主机攻击链时转 `traceability-analysis`；缺数据时补做 `data-source-completeness`。本技能不做横向 BFS。命令风险由父级 `risk-identification` 的检测、策略和白名单流程研判，不将命令风险等级直接当作本告警成功证据。

## 5. 离线验收与反例

| 用例及前提 | 预期 |
|---|---|
| full + SQLi + blocked，无成功证据 | confirmed_attack / blocked |
| triage_only + 同一 SQLi 告警 | confirmed_attack / success_unknown |
| 业务 UUID 误命中，无 exploit | false_positive / not_applicable |
| SQLi + 同主机同窗 curl，无数据库指标 | curl 仅为 supporting；不能据此 success_confirmed；full/未阻断且有 D2 时为 attempt_failed |
| RCE/WebShell + 符合归属、窗口和类型的 exec 指标 | full 模式可 success_confirmed |
| 只有 WEB 500 或 DNS/外连上下文 | 不单独构成成功证明 |

从仓库根目录运行公开合成样例，无需凭证：

```bash
python3 src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json
```
