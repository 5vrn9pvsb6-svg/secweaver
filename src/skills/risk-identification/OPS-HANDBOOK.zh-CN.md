# 风险识别运营手册

**语言：** [English](OPS-HANDBOOK.md) | 简体中文。更新：2026-09-18。

面向修改检测特征、告警策略和环境例外的安全运营人员。安装与首次研判见 [用户指南](../../../docs_user/19-risk-identification.zh-CN.md)，模块职责见 [DESIGN](DESIGN.zh-CN.md)。本页负责操作 Playbook；JSON 字段语法统一见 [规则参考](rules/README.zh-CN.md)。

## 一、先定位要改的层

| 现象 | 维护入口 | 验证重点 |
|---|---|---|
| 事件没有正确检测标签 | `rules/exec-rules.json`、`connect-rules.json`、`dns-rules.json`、`persistence-rules.json`、`ssh-rules.json`、`syslog-rules.json` | `matched_rules` 与初判等级 |
| 已检出但告警或等级不合适 | `behavior-policy.md` **和** `rules/behavior-policy.rules.json` | `policy_rule_id`、`alert_required`、最终等级与硬护栏 |
| 仅特定环境允许的行为 | `whitelist.json` | scope、有效期及范围外反例；见 [白名单指南](whitelist.zh-CN.md) |
| 跨阶段剧本需要调整 | `rules/chain-patterns.json` | 溯源输出的剧本匹配，不代表单事件裁决已变化 |
| 跨主机链路缺失 | `traceability-analysis` 与关联矩阵 | 数据完整性、关联字段、时间窗 |

智能体按本 Skill 调用 `assess.py`，与直接 CLI 使用同一 JSON 引擎。MD 负责理由、说明和审计；只改 MD 不会改变默认运行结果。独立的纯提示词试验必须注明方法，不算规则包已生效。

## 二、先回放再修改

从仓库根目录、完成 Python 依赖安装后运行合成样例：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i src/skills/risk-identification/scripts/input.example.json \
  -o /tmp/secweaver-risk-review.json
```

这是离线分析，不连接真实数据源、不发送通知。真实查询先完成只读接入验收；默认 `dataasset/`，隔离时使用 `DATAASSET_ROOT=dataasset_my`。设置授权 Bundle 及包含明确主机和带时区时间窗的参数文件后：

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  --from-bundle --bundle "${RISK_BUNDLE_ID:?Set an authorized bundle ID}" \
  --params-file "${RISK_PARAMS_FILE:?Set a scoped params JSON file}" --fetch
```

不要为得到结论跳过完整性预检。结果复核：`risk_items` 保留单项证据，`top_incidents` 聚合展示，`matched_rules` 是检测标签，`policy_rule_id` 解释策略裁决。`alert_required` 是决策标志，不等于已经向外部渠道发送。

## 三、Playbook：误报与降噪

1. 保存脱敏输入和原始输出，确定误报发生在检测、策略还是白名单层。
2. 全平台策略同步修改 MD 与 JSON，使用同一规则 ID；局部例外限制在白名单的具体 scope，不能宽泛允许同名命令。
3. 保留一个应降噪样例，以及 Web 入口命令执行、反弹 shell、持久化等不应被降噪的反例。
4. 回放比较 `original_risk`、最终 `severity`、`alert_required`、`policy_rule_id` 与 `alert_suppressed`。硬护栏和 force-alert 优先于 suppress。
5. 更新 MD 修订记录，通过第五节检查后提交。不得通过删除通用检测模式隐藏误报。

## 四、Playbook：漏报与聚合异常

- 新命令没有标签：先检查字段归一，再按规则参考扩展检测 JSON；已有标签但未告警则查 JSON 策略与白名单。
- SSH 暴破：`assess.py` 使用 `params.ssh_brute_threshold` 和 `params.ssh_brute_window_sec` 控制成波阈值和窗口。规则包 `thresholds` 决定检测等级，随后策略可能覆盖；检查全部 `ssh_brute_waves`。
- Syslog：SSH 失败原始事件由 SSH 模块聚合；账号、sudo、防火墙等由 syslog 模块处理，不要为增加计数重复归类。
- 无 TTY：`has_tty=false` 是上下文，cron/MOTD 同样可能无 TTY；必须结合监听进程、命令与证据，不能独立确认 WebShell。
- 剧本：更新 `chain-patterns.json` 后用公开溯源样例验证，不能只检查取数成功。规则语法见规则参考，跨主机叙事由溯源负责。

## 五、变更验收与回滚

```bash
python3 src/skills/risk-identification/scripts/validate_policy_sync.py --strict
python3 -m unittest discover -s src/skills/risk-identification/tests -p 'test_*.py'
```

同步检查仅能发现规则 ID 等一致性问题，不能证明 MD 与 JSON 语义相同；必须同时回放应命中与不应命中的样例。PR 记录修改理由、样例预期、实际结果及修订记录，工程变更还要运行完整 CI。

自定义策略可通过 `--behavior-policy` 与 `--behavior-policy-rules` 同时指定配套文件；默认策略是否启用及白名单开关见 [Skill](SKILL.zh-CN.md)。自定义检测目录使用 payload 的 `detection_rules.rules_dir`，应从完整规则包复制后修改。规则加载错误应修复配置；不要用关闭策略或白名单掩盖失败。

若验证不符合预期，恢复本次修改前的 MD 与 JSON 配套版本并重跑同一组样例，确认恢复结果。不要覆盖他人的未提交工作。

## 六、维护参考

- [检测标签目录](detection-catalog.zh-CN.md)：解释标签和等级。
- [策略正文](behavior-policy.md)与[维护说明](behavior-policy.zh-CN.md)：自然语言规则与审计。
- [策略引擎设计](../../../docs_dev/19-behavior-policy-engine-design.zh-CN.md)：条件、优先级和扩展边界。
- [规则参考](rules/README.zh-CN.md)：检测规则、策略 JSON 和剧本的字段定义。
