# SecWeaver 项目 Skills

本目录存放随仓库共享的 **Agent Skills**。每个技能以 `SKILL.md` 定义工作流；确定性技能提供 `scripts/`，纯提示词技能可只包含提示词与参考资料。贡献方式分别见[开发者指南](../../docs_dev/02-developer-guide.zh-CN.md)。

**与智能体无关：** 同一套 Skill 可用于 **Cursor、Codex、Claude Code（CC）、OpenClaw、WorkBuddy** 等支持 Skill / 规则加载的 AI Agent，**不是 Cursor 专有**。`src/skills/` 是唯一规范实现；各智能体使用薄适配器引用该目录，不复制内容。

**平台架构**：[docs_dev/06-secweaver-architecture-and-features.md](../../docs_dev/06-secweaver-architecture-and-features.md)

## Agent 智能体与加载方式

| 智能体 | 典型加载方式 |
|------|----------------|
| **Cursor** | Skills 在 `src/skills/`；对话中 `@src/skills/<name>/SKILL.md` 引用，或在项目 Rules 中说明路径（不再使用 `.cursor/skills` 符号链接） |
| **Claude Code（CC）** | 项目 `CLAUDE.md` / skills 配置指向本目录，或对话中 `@` 引用 `SKILL.md` |
| **Codex** | 工作区规则或 skill 清单包含 `src/skills` |
| **OpenClaw** | Claw / skill 注册表挂载本仓库 skills 路径 |
| **WorkBuddy** | 本地项目 Skill 适配器指向本仓库；不作为独立市场包上传 |
| **无 Agent** | 直接运行 `scripts/*.py` 或 `src/secweaver.py skill …`（与 Agent 无关） |

使用 `make ai-setup HOST=<host>` 生成仓库本地适配器。可复制配置、逐屏操作、
预期结果和排错见 [智能体配置指南](../../docs_user/38-ai-agent-host-setup.zh-CN.md)。

**分工：**

```text
Skill（SKILL.md + scripts）  →  能力契约，智能体无关
Agent（Cursor / CC / Codex / OpenClaw / WorkBuddy …）  →  读 SKILL.md、调脚本、可选 LLM 叙事
CLI（secweaver.py）          →  无 Agent 时的确定性入口
```

新增或修改 Skill 时，只维护 **一份** `SKILL.md`；勿为每个 Agent 复制逻辑。

如果某个 Skill 需要通过本地 CLI 运行（`secweaver skill ...` 或 `secweaver demo ...`），请注册到 [`manifest.json`](manifest.json)。贡献流程见 [`docs_dev/02-developer-guide.zh-CN.md`](../../docs_dev/02-developer-guide.zh-CN.md)。

`manifest.json` 是全部 Skill 的单一目录。每个顶层 Skill 都在其中声明
`kind`（`assessment`、`fetch`、`operation`、`prompt`、`router` 或 `subskill`）、
规范文档路径和是否有 CLI 入口。可机器执行的 Skill 还要声明
`output_schema`；对外提供稳定 JSON 契约的 Skill 才配置该字段，纯提示词和路由 Skill
有意不配置脚本。新增 Skill 目录前先补目录项，确保 `secweaver list`、文档检查和
契约测试看到同一套能力面。

共用 Python 代码分两层：[_shared/data-access/](_shared/data-access/README.zh-CN.md)
负责证据传输/归一化与场景取数扩展；
[_shared/skill_runtime/](_shared/skill_runtime/README.zh-CN.md) 负责 Skill 输入适配、
完整性预检和跨 Skill 调用。各 Skill 保留自己的规则。原 `skill_input`、准备脚本
和流水线入口继续兼容。

| Skill | 目录 | 说明 |
|---|---|---|
| 数据源完整性分析 | [data-source-completeness/](data-source-completeness/SKILL.md) | 溯源/告警确认前评估数据是否完整 |
| 溯源分析 | [traceability-analysis/](traceability-analysis/SKILL.md) | 跨源还原攻击链与横向路径 |
| **告警确认** | [alert-confirmation/](alert-confirmation/SKILL.md) | WAF/WEB 告警误报·真实·成功研判 |
| **数据资产连接性** | [dataasset-connectivity-check/](dataasset-connectivity-check/SKILL.md) | 探测 active 资产，区分连接成功、有数据和未评估的场景覆盖 |
| **风险识别** | [risk-identification/](risk-identification/SKILL.md) | 主机 exec/connect P0–P3 分级与攻击链 |
| 对外监听进程命令高危识别 | [external-listener-cmd-risk/](external-listener-cmd-risk/SKILL.md) | exec 子模块规则 |
| 对外监听进程主动外连高危识别 | [external-listener-connect-risk/](external-listener-connect-risk/SKILL.md) | connect 子模块规则 |
| **数据访问层** | [_shared/data-access/](_shared/data-access/README.zh-CN.md) | dataasset + SOPS Vault → 归一化证据；含 **correlation_engine** |
| **证据取数** | [evidence-fetch/](evidence-fetch/SKILL.md) | **只拉 evidence_bundles，不研判**；供大模型或下游 Skill |
| **提示词研判（开源）** | [prompt-risk-analysis/](prompt-risk-analysis/SKILL.md) | evidence-fetch 后纯 PROMPT 研判，无脚本 |
| **离线 Showcase** | [offline-showcase/](offline-showcase/SKILL.md) | 无需 ES、SLS 或凭证运行内置合成案例 |
| **数据资产校验与建议** | [dataasset-validation-advisor/](dataasset-validation-advisor/SKILL.md) | 运行 validate.py，归类错误并给出修复建议 |
| **跨源关联** | [docs_user/21-cross-source-field-correlation.md](../../docs_user/21-cross-source-field-correlation.md) | 字段 Join 规则与溯源拼链 |
| **示例数据** | [examples/](../../examples/) | 项目根目录离线测试 payload（各 Skill） |
| **格式发现** | [log-format-discovery/](log-format-discovery/SKILL.md) | 仅处理 dataasset **`status=discovery`** 队列（[设计](../../docs_dev/20-log-format-discovery-design.md)） |

## 技能链

```text
【新 log】注册 discovery 资产 → log-format-discovery（--asset-id）
                              ↓
dataasset/bundles + SOPS Vault
        ↓
_shared/data-access/  或  evidence-fetch（--from-bundle）
        ↓
evidence_bundles ──┬──▶ prompt-risk-analysis（开源提示词研判）
                   ├──▶ 风险识别 / assess.py（企业规则引擎）
                   ├──▶ 数据源完整性分析
                   ├──▶ 告警确认 ──(成功)──▶ 溯源分析
                   ├──▶ 溯源分析
                   └──▶ 风险识别(S5) ──(P0/P1)──▶ 溯源分析
```

## 凭证规则

- 资产定义：[`dataasset/`](../../dataasset/)
- 本地 Vault：[`dataasset/credentials/`](../../dataasset/credentials/)
- Skill / 大模型：**只见** `credentials_ref`，不见明文密钥
- 解密与查库：`_shared/data-access/vault.py` + `fetch.py`（平台侧）

## 目录结构

```text
src/skills/
├── README.md
├── _shared/data-access/     # registry / vault / fetch / 场景取数计划
├── _shared/skill_runtime/   # 输入适配 / 研判调用 / 流水线
├── evidence-fetch/          # 多源取数（不研判）
├── prompt-risk-analysis/    # OSS prompt triage (PROMPT.md only, no scripts)
├── data-source-completeness/
├── dataasset-validation-advisor/
├── traceability-analysis/
├── alert-confirmation/
├── risk-identification/
├── external-listener-cmd-risk/
├── external-listener-connect-risk/
└── log-format-discovery/   # 新日志格式接入（discover.py + 大模型映射）
```

## 新数据源接入

```text
样本日志 → log-format-discovery（discover.py 预处理 + 大模型映射）
         → evidence-minimum-fields / normalizer / templates / assets
         → validate.py → test_connector.py
```

文档：[完整接入](../../docs_user/03-configure-data-sources.zh-CN.md) | [字段发现与归一化](../../docs_user/20-log-format-discovery.zh-CN.md) | [短 FAQ](../../docs_user/16-data-source-onboarding-faq.zh-CN.md)

## 快速示例

离线测试数据见 [examples/](../../examples/)。以下命令均从项目根目录执行：

最快的智能体体验方式：Linux/macOS 运行 `make quickstart`，原生 Windows PowerShell
运行 `.\quickstart.ps1`，再使用 Codex 或其他支持的智能体打开当前仓库，然后输入
“运行 SecWeaver 离线案例”。案例目录和产品价值说明见
[`examples/ai-showcase/`](../../examples/ai-showcase/README.zh-CN.md)。

```bash
# 完整性预检
python3 src/skills/data-source-completeness/scripts/check.py \
  -i examples/data-source-completeness/s1-full-traceable.json

# 告警确认
python3 src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json

# 风险识别
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json

# 溯源拼链
python3 src/skills/traceability-analysis/scripts/correlate.py \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json

# 格式发现 Step 1：须 discovery 状态资产
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i src/skills/log-format-discovery/samples/waf-jsonl.example --pretty

# 单 Skill（内置 dataasset + Vault）
python3 src/skills/evidence-fetch/scripts/fetch_evidence.py --from-bundle \
  --bundle bundle-host-risk-default \
  --params '{"hosts":["192.0.2.91"],"time_start":"...","time_end":"..."}' \
  --pretty

python3 src/skills/data-source-completeness/scripts/check.py --from-bundle \
  --params '{"attacker_ip":"203.0.113.10"}'

# 流水线
python3 src/skills/_shared/data-access/run_pipeline.py risk-chain \
  --bundle bundle-host-risk-default \
  --params '{"host":"web-01","time_start":"...","time_end":"..."}' \
  --pretty

python3 src/skills/_shared/data-access/run_pipeline.py trace-chain \
  --params '{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"...","host":"web-01"}' \
  --fetch --pretty
```
