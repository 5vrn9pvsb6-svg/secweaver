# 智能体配置指南

**语言：** [English](38-ai-agent-host-setup.md) | 简体中文（本文）

SecWeaver 不内置或锁定某一个大模型。Codex、Cursor、Claude Code、OpenClaw 和
WorkBuddy 作为智能体，读取仓库中唯一的规范 Skill 目录 `src/skills/`。

`make quickstart` 会为全部支持的智能体生成很薄的本地适配器；`make ai-setup` 可用于
刷新全部适配器或单独刷新一个智能体。适配器告诉智能体先读
`src/skills/README.md`，再按任务选择 `src/skills/<name>/SKILL.md`。适配器不复制
Skill 正文，因此不会出现不同智能体之间的规则漂移。

## 前置条件

1. 从 SecWeaver 仓库根目录执行命令。
2. 执行 `make quickstart`，安装依赖、验证离线 demo 并生成全部智能体适配器。
3. 智能体必须能读取当前仓库并在仓库根目录执行命令。
4. 离线样例不需要 ES/SLS 凭证；查询真实数据时再按 DataAsset 文档配置凭证引用。

## 命令和生成路径

下方逐屏文本是操作示意，不是实际截图，也不保证各版本菜单名称完全相同。
菜单有差异时按适配器路径和智能体当前帮助定位，以验证提示词确实加载 Skill 为准，
不要仅凭文件存在就判定智能体配置成功。

```bash
make ai-setup HOST=all
make ai-setup HOST=codex
make ai-setup HOST=cursor
make ai-setup HOST=claude
make ai-setup HOST=openclaw
make ai-setup HOST=workbuddy
```

第一条命令与 `make quickstart` 执行的全智能体配置相同。只有需要刷新或排查某个
适配器时，才需要执行单智能体命令。

| 智能体 | 生成的本地适配文件 |
|---|---|
| Codex | `.agents/skills/secweaver/SKILL.md` |
| Cursor | `.cursor/rules/secweaver-skills.mdc` |
| Claude Code | `.claude/skills/secweaver/SKILL.md` |
| OpenClaw | `skills/secweaver/SKILL.md` |
| WorkBuddy | `.workbuddy/skills/secweaver/SKILL.md` |

这些路径已加入 `.gitignore`，只对当前 checkout 生效。重复执行会返回
`unchanged`。如果目标路径已有用户自己的文件，命令会拒绝覆盖。

## Codex：逐屏操作

### 屏幕 1：终端

```text
┌─ SecWeaver repository
│ $ make ai-setup HOST=codex
│ created: .agents/skills/secweaver/SKILL.md
│ host: Codex
│ canonical skills: src/skills/
└─
```

### 屏幕 2：Codex

```text
Codex
├─ Open Folder / Project
├─ 选择 SecWeaver 仓库根目录
├─ 新建任务（已打开的会话需重新加载 Skill）
└─ 在 Skill 列表中确认 secweaver
```

### 屏幕 3：验证提示词

```text
请使用 secweaver Skill，分析
examples/prompt-risk-analysis/fetch-waf-bypass-mini.json，
并输出带 evidence_id、waf_coverage 和 data_gaps 的中文报告。
```

预期：Codex 先读 `src/skills/README.md`，再加载
`src/skills/prompt-risk-analysis/SKILL.md`；样例最高结论为 `P0 / confirmed_success`。

## Cursor：逐屏操作

### 屏幕 1：终端

```text
$ make ai-setup HOST=cursor
created: .cursor/rules/secweaver-skills.mdc
```

### 屏幕 2：Cursor

```text
Cursor
├─ File > Open Folder > SecWeaver 仓库根目录
├─ Settings > Rules
├─ Project Rules
└─ 确认 secweaver-skills（Agent Requested）
```

### 屏幕 3：验证提示词

```text
@secweaver-skills 请用 data-source-completeness Skill 分析
examples/data-source-completeness/s1-full-traceable.json。
```

预期：Cursor 显示项目 Rule 已附加，并按 `src/skills/data-source-completeness/SKILL.md`
的输出契约返回结果。

## Claude Code：逐屏操作

### 屏幕 1：终端

```text
$ make ai-setup HOST=claude
created: .claude/skills/secweaver/SKILL.md
$ claude
```

### 屏幕 2：Claude Code

```text
Claude Code
├─ 从 SecWeaver 仓库根目录启动
├─ 输入 /secweaver，或在普通请求中让 Claude 自动匹配
└─ 新会话中确认 Skill 已可用
```

### 屏幕 3：验证提示词

```text
/secweaver 请分析 examples/alert-confirmation/s4-webshell-attack-success.json，
先报告 fetch_summary，再判断是否攻击成功。
```

预期：Claude 读取规范 `alert-confirmation/SKILL.md`，可调用其确定性脚本，并输出
`confirmed_attack / success_confirmed`。

## OpenClaw：逐屏操作

### 屏幕 1：终端

```text
$ make ai-setup HOST=openclaw
created: skills/secweaver/SKILL.md
$ openclaw skills list
```

### 屏幕 2：OpenClaw

```text
OpenClaw workspace
├─ Workspace root = SecWeaver 仓库根目录
├─ Skills
└─ secweaver = available
```

### 屏幕 3：验证提示词

```text
请调用 secweaver，使用 traceability-analysis 分析
examples/traceability/s1-web-shell-to-ssh-lateral.json。
```

预期：OpenClaw 从 workspace `skills/` 发现路由器，再读取
`src/skills/traceability-analysis/SKILL.md`。

## WorkBuddy：逐屏操作

WorkBuddy 适配器用于能访问 SecWeaver 仓库的本地项目任务。它不是可独立上传到
WorkBuddy 市场的自包含 Skill 包；市场包会要求把引用的资源一起打包，这与本项目
“不复制 `src/skills`”的原则冲突。

### 屏幕 1：终端

```text
$ make ai-setup HOST=workbuddy
created: .workbuddy/skills/secweaver/SKILL.md
```

### 屏幕 2：WorkBuddy 本地项目

```text
WorkBuddy
├─ 新建本地任务，将 SecWeaver 仓库作为可访问目录
├─ 专家·技能·连接器 > 技能 > 添加技能
├─ 选择 `.workbuddy/skills/secweaver/`
└─ 确认任务的命令工作目录是 SecWeaver 仓库根目录
```

### 屏幕 3：验证提示词

```text
请使用 SecWeaver 技能校验当前 dataasset，并解释 error 和 warning。
```

预期：WorkBuddy 读取 `src/skills/dataasset-validation-advisor/SKILL.md`，从仓库根目录
运行校验脚本。如果智能体任务不能访问本地仓库，该适配方式不可用。

## 通用验收

```bash
.venv/bin/python src/secweaver.py list
.venv/bin/python src/secweaver.py validate --json --strict
.venv/bin/python src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json
```

智能体生成的报告还应满足：

- 在结论前报告 `fetch_summary`。
- 结论可追溯到 `evidence_id`，无证据时不得臆测。
- S4/WAF 漏过调查包含 `waf_coverage`。
- 密码、Token、Cookie、API Key 和私钥不进入提示词或报告。

## 排错

| 现象 | 处理 |
|---|---|
| `HOST=... is required` | 使用本文支持的 5 个智能体名之一 |
| `refusing to overwrite` | 目标文件属于用户；先手工合并或备份，不要强制覆盖 |
| 新 Skill 未出现 | 重开智能体会话，确认工作区根目录和生成路径 |
| 适配器可见但脚本失败 | 先执行 `make quickstart`，并从仓库根目录重试 |
| WorkBuddy 找不到 `src/skills` | 切换到能访问本地仓库的项目任务；不要将薄适配器当作独立市场包 |

## 官方智能体参考

- [OpenAI Codex customization](https://developers.openai.com/codex/codex-manual#customization-and-durable-instructions)
- [Cursor Project Rules](https://docs.cursor.com/context/rules)
- [Claude Code Skills](https://code.claude.com/docs/en/slash-commands)
- [OpenClaw Skills](https://docs.openclaw.ai/tools/creating-skills)
- [WorkBuddy 技能规范](https://open.workbuddy.cn/docs/skill)
