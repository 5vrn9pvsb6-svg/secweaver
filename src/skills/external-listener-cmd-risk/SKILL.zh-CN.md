---
name: external-listener-cmd-risk
description: >-
  Exec sub-module of risk-identification for commands run by externally
  listening processes. Use the parent deterministic engine for host_exec
  evidence, Web/API process abuse, WebShell and reverse-shell triage.
---

# 对外监听进程命令风险

本技能是 `risk-identification` 的 exec 子模块。原始 exec 事件先经 DataAsset 归一化，再放入父级输入的 `evidence_bundles.host_exec`；直接把 JSON Lines 交给 `assess.py` 不是其输入契约。

## 执行与输出

从仓库根目录运行公开离线样例：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json \
  -o /tmp/secweaver-exec-risk.json
```

该公开样例还包含 connect。仅检查 exec 时，在自定义 payload 顶层设置 `"risk_modules": ["exec"]`；主机、时间范围等放入 `params`。完整输入与输出例子见 [examples.zh-CN.md](examples.zh-CN.md)。

父引擎按 **JSON 检测规则 → behavior-policy 裁决 → 环境白名单** 处理。检测初判不等于最终等级；使用最终 `risk_items[]` 中的 `severity`、`policy_rule_id`、`recommended_action` 和证据引用报告结果。不要通过手工匹配 Markdown、增加固定置信度或跳过策略层重算告警。

例如 nginx 子进程执行普通 `ls`，即使没有命中检测规则，默认策略仍可能判 P1，不能据“普通命令”一概写 P2/观察。实际结果以当前规则和授权环境配置为准。

## 按需参考

- [规则职责与配置入口](rules.zh-CN.md)：检测、策略、白名单各自负责什么。
- [父级技能](../risk-identification/SKILL.zh-CN.md)：完整性、取数、最终报告及下游流程。
- [运营手册](../risk-identification/OPS-HANDBOOK.zh-CN.md)：规则维护与验证。

本技能评估命令风险；是否导致本条攻击成功、是否形成横向链，分别由告警确认与溯源技能结合关联证据判断。
