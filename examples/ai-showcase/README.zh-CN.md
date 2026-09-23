# SecWeaver 离线智能体 Showcase

无需接入 ES、SLS 或生产数据，即可在 Codex、Cursor、Claude Code、OpenClaw 或
WorkBuddy 中体验 SecWeaver。

## 最短路径

在仓库根目录执行：

```bash
make quickstart
```

然后使用 智能体打开当前仓库，只需输入：

```text
运行 SecWeaver 离线案例
```

未指定案例时，按目录顺序运行全部 27 个可执行评估案例。指定案例 ID 时只运行该例，
已有 ID 保持兼容。可读报告是默认交付，不需要额外补充“形成可读的报告”。

`offline-showcase` 读取选定案例的离线输入，再调用对应分析 Skill：攻击链交给
`traceability-analysis`，主机风险交给 `risk-identification`。智能体按该 Skill
的工作流完成分析，将完整 Markdown 报告与 JSON 一起保存在 `outputs/ai-showcase/`。
告警和数据缺口案例分别使用告警确认与完整性 Skill。预期结论校验只用于验证脚本
结果，智能体的证据梳理和报告仍是完整体验的必要步骤。

## 案例

| 案例 ID | 场景 | Skill |
|---|---|---|
| `webshell-attack-confirmation` | 确认 WebShell 攻击是否成功 | `alert-confirmation` |
| `false-positive-parameter` | 识别请求参数误报 | `alert-confirmation` |
| `webshell-to-ssh-lateral` | 还原 WebShell 到 SSH 横向移动 | `traceability-analysis` |
| `reverse-shell-risk` | 从主机证据识别反弹 Shell | `risk-identification` |
| `missing-host-exec-data` | 主机证据缺失时阻止过度结论 | `data-source-completeness` |
| `s1-full-traceable` | 溯源数据源齐备 | `data-source-completeness` |
| `s4-alert-triage-only` | 仅能告警分类 | `data-source-completeness` |
| `s4-partial-missing-connect` | 缺少主机连接证据 | `data-source-completeness` |
| `s4-scanner-generic-no-payload` | 无载荷的扫描器告警 | `alert-confirmation` |
| `s4-sqli-blocked-no-breach` | SQL 注入被拦截 | `alert-confirmation` |
| `s1-scan-only-no-host-exec` | 仅扫描无主机执行 | `traceability-analysis` |
| `s2-initial-access-no-lateral` | 主机执行但无确认横向 | `traceability-analysis` |
| `s5-curl-download-exec-p0` | Web 进程下载执行 | `risk-identification` |
| `s5-external-connect-p0` | Web 监听进程主动外连 | `risk-identification` |
| `s5-nginx-config-test-whitelisted` | nginx 配置检查白名单 | `risk-identification` |
| `s5-persistence-authorized-keys-p0` | SSH 授权密钥变更 | `risk-identification` |
| `s5-ssh-bruteforce-p0` | SSH 十次失败达到阈值 | `risk-identification` |
| `s5-ssh-nine-failures-below-threshold` | SSH 九次失败未达阈值 | `risk-identification` |
| `s5-whoami-recon-p0` | Web 进程 shell 侦察 | `risk-identification` |
| `s8-dns-dga-p1` | 异常 DNS 且缺少外连证据 | `risk-identification` |
| `s6-full-traceable` | 账号失陷调查数据源齐备 | `data-source-completeness` |
| `s6-not-traceable-missing-auth` | 账号调查缺少认证日志 | `data-source-completeness` |
| `s7-full-traceable` | 数据外传调查数据源齐备 | `data-source-completeness` |
| `s7-partial-missing-traffic-volume` | 外传调查缺少流量体量 | `data-source-completeness` |
| `s4-batch-mixed-with-query-gap` | 混合告警批次与查询缺口 | `alert-confirmation` |
| `s6-root-ssh-login-p1` | 异常 root SSH 登录 | `risk-identification` |
| `s7-data-staging-and-scp-p0` | 数据暂存与 SCP 外发候选 | `risk-identification` |

示例：

```text
运行 SecWeaver 离线案例 webshell-to-ssh-lateral，说明攻击入口、命令执行、
横向路径、关键证据和数据缺口。
```

机器可读目录见 [`cases.json`](cases.json)。案例复用 `examples/` 中保存的合成
证据，生成结果写入 Git 忽略的 `outputs/ai-showcase/`。
WebShell 到 SSH 案例会显示已观察到的 WebShell 控制点和横向登录，但不能由此确定原始攻破方式。
运行器强制禁止实时取数、通知和溯源 IP 在线情报查询；手工运行溯源脚本时需添加
`--no-ip-intel --no-notify` 才具有相同的离线边界。

## 不使用智能体

确定性分析和预期结论校验也可以通过 CLI 运行。该命令默认生成 JSON 和可读的
Markdown 结构化结果报告；智能体继续按 Skill 规范完成证据复核与叙事分析：

```bash
make ai-showcase
make ai-showcase CASE=false-positive-parameter
```

所有案例均不需要凭证，也不会查询真实网络数据源。

## 批次行为与验证

按项目说明完成快速上手后，macOS/Linux 使用 `make ai-showcase` 或
`.venv/bin/python src/scripts/run_ai_showcase.py --all`，原生 Windows PowerShell 使用
`.venv\Scripts\python.exe src\scripts\run_ai_showcase.py --all`，均按目录顺序执行
全部案例，每例最多 60 秒。依赖安装后无需联网。

每个通过案例写入 `<case_id>.json` 和 `<case_id>.md`，`suite-summary.json` 与
`suite-summary.md` 记录所有案例、计数、失败及报告链接。
单例失败或超时会继续下一例，任何失败均使最终退出码非零。失败案例可能留有旧文件，
应以本次汇总为准。显式指定 ID 保留单例 JSON 输出并新增 Markdown 报告；`--list` 只列出、不运行。

报告默认使用中文，包含取数统计、判定、原始记录、规则或完整性需求、缺口和处置建议。
样例预录的查询失败会标明为回放元数据，不会描述成真实联网。自动报告明确标记为
待智能体复核的结构化结果，不冒充智能体撰写的调查报告。报告写入失败计入失败，退出码非零。
`--json` 只改变控制台格式，仍会生成 Markdown；控制台输出 `Report:` 路径，
JSON 汇总新增 `report` 和 `report_kind`。重跑会覆盖 JSON 和 Markdown，包括旧的叙事报告。
智能体须复核最新证据，将基础报告补全为对应 Skill 的分析报告，完善可读汇总并提供链接后
才能结束任务。批次覆盖 27 份评估输入（完整性 8、告警 5、
溯源 3、风险 11）；另有 2 份纯提示词 fetch 输入和 6 份原始格式样本，它们的独立验证
流程见[完整样例目录](../CASE-CATALOG.zh-CN.md)。

验证默认选择、失败续跑和全部预期结论：

```bash
.venv/bin/python -m unittest discover -s tests -p test_ai_showcase.py -v
```

新增评估输入时须登记到 `cases.json`，提供 Skill、离线参数及预期字段；覆盖检查
会拒绝未登记输入。依赖旧单例默认行为的自动化应改为显式传入案例 ID。
