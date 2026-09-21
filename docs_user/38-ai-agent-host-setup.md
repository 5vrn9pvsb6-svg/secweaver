# Intelligent Agent Setup

**Languages:** English (this page) | [简体中文](38-ai-agent-host-setup.zh-CN.md)

SecWeaver does not embed or lock users to one model. Codex, Cursor, Claude Code,
OpenClaw, and WorkBuddy act as intelligent agents over the single canonical Skill tree at
`src/skills/`.

`make quickstart` generates thin local adapters for every supported intelligent agent. `make ai-setup`
can refresh all adapters or one selected adapter. Each adapter tells the agent to read
`src/skills/README.md`, select the matching `src/skills/<name>/SKILL.md`, and follow
that canonical workflow. No Skill implementation is copied into adapter configuration.

## Prerequisites

1. Run commands from the SecWeaver repository root.
2. Run `make quickstart` to install dependencies, verify offline demos, and generate all adapters.
3. Give the intelligent agent read and command access to this repository.
4. Offline examples need no ES or SLS credentials. Live queries require the
   documented DataAsset credential references.

## Commands and generated paths

The screen-by-screen blocks below are text schematics, not screenshots or a
promise of identical menus across intelligent-agent versions. If a menu differs, use the
documented adapter path and the agent's current help; verify actual Skill loading
with the prompt, not just the presence of a file.

```bash
make ai-setup HOST=all
make ai-setup HOST=codex
make ai-setup HOST=cursor
make ai-setup HOST=claude
make ai-setup HOST=openclaw
make ai-setup HOST=workbuddy
```

The first command is the same all-agent setup performed by `make quickstart`. Use a
single-agent command only when you need to refresh or troubleshoot that adapter.

| Intelligent agent | Local adapter |
|---|---|
| Codex | `.agents/skills/secweaver/SKILL.md` |
| Cursor | `.cursor/rules/secweaver-skills.mdc` |
| Claude Code | `.claude/skills/secweaver/SKILL.md` |
| OpenClaw | `skills/secweaver/SKILL.md` |
| WorkBuddy | `.workbuddy/skills/secweaver/SKILL.md` |

These paths are ignored by Git and apply only to the current checkout. Re-running
the command reports `unchanged`. The generator refuses to overwrite a file it did
not create.

## Codex: screen-by-screen

### Screen 1: terminal

```text
┌─ SecWeaver repository
│ $ make ai-setup HOST=codex
│ created: .agents/skills/secweaver/SKILL.md
│ agent: Codex
│ canonical skills: src/skills/
└─
```

### Screen 2: Codex

```text
Codex
├─ Open Folder / Project
├─ Select the SecWeaver repository root
├─ Start a new task or reload Skills
└─ Confirm secweaver appears in the Skill list
```

### Screen 3: verification prompt

```text
Use the secweaver Skill to analyze
examples/prompt-risk-analysis/fetch-waf-bypass-mini.json.
Return evidence_id references, waf_coverage, and data_gaps.
```

Expected: Codex reads the canonical prompt-risk-analysis Skill and reaches the
fixture's `P0 / confirmed_success` result.

## Cursor: screen-by-screen

### Screen 1: terminal

```text
$ make ai-setup HOST=cursor
created: .cursor/rules/secweaver-skills.mdc
```

### Screen 2: Cursor

```text
Cursor
├─ File > Open Folder > SecWeaver repository root
├─ Settings > Rules > Project Rules
└─ Confirm secweaver-skills is available as Agent Requested
```

### Screen 3: verification prompt

```text
@secweaver-skills Use data-source-completeness to analyze
examples/data-source-completeness/s1-full-traceable.json.
```

Expected: Cursor attaches the project rule and follows the canonical
`src/skills/data-source-completeness/SKILL.md` output contract.

## Claude Code: screen-by-screen

### Screen 1: terminal

```text
$ make ai-setup HOST=claude
created: .claude/skills/secweaver/SKILL.md
$ claude
```

### Screen 2: Claude Code

```text
Claude Code
├─ Start from the SecWeaver repository root
├─ Enter /secweaver, or let Claude match it from the request
└─ Confirm the Skill is available in a new session
```

### Screen 3: verification prompt

```text
/secweaver Analyze examples/alert-confirmation/s4-webshell-attack-success.json.
Report fetch_summary first, then determine whether the attack succeeded.
```

Expected: Claude reads the canonical alert-confirmation Skill and returns
`confirmed_attack / success_confirmed`.

## OpenClaw: screen-by-screen

### Screen 1: terminal

```text
$ make ai-setup HOST=openclaw
created: skills/secweaver/SKILL.md
$ openclaw skills list
```

### Screen 2: OpenClaw

```text
OpenClaw workspace
├─ Workspace root = SecWeaver repository root
├─ Skills
└─ secweaver = available
```

### Screen 3: verification prompt

```text
Invoke secweaver and use traceability-analysis on
examples/traceability/s1-web-shell-to-ssh-lateral.json.
```

Expected: OpenClaw discovers the workspace router and then reads the canonical
traceability Skill under `src/skills/`.

## WorkBuddy: screen-by-screen

The WorkBuddy adapter is for a local project task that can access the SecWeaver
repository. It is not a self-contained WorkBuddy Marketplace package. Marketplace
uploads require bundled resources, which conflicts with the no-copy canonical-Skill
policy.

### Screen 1: terminal

```text
$ make ai-setup HOST=workbuddy
created: .workbuddy/skills/secweaver/SKILL.md
```

### Screen 2: WorkBuddy local project

```text
WorkBuddy
├─ Create a local task with the SecWeaver repository available
├─ Experts · Skills · Connectors > Skills > Add Skill
├─ Select `.workbuddy/skills/secweaver/`
└─ Set the task command working directory to the repository root
```

### Screen 3: verification prompt

```text
Use SecWeaver to validate the current dataasset configuration and explain all
errors and warnings.
```

Expected: WorkBuddy reads the canonical dataasset-validation-advisor Skill and
runs its validator from the repository root. This adapter cannot work in a task
that has no access to the local repository.

## Common acceptance checks

```bash
.venv/bin/python src/secweaver.py list
.venv/bin/python src/secweaver.py validate --json --strict
.venv/bin/python src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json
```

The AI report should also:

- show `fetch_summary` before its verdict;
- cite `evidence_id` and avoid unsupported claims;
- include `waf_coverage` for S4/WAF-bypass investigations;
- keep passwords, tokens, cookies, API keys, and private keys out of prompts and reports.

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `HOST=... is required` | Use one of the five supported intelligent-agent keys |
| `refusing to overwrite` | Manually merge or back up the user-owned target file |
| Skill is missing | Start a new intelligent-agent session and verify workspace root and adapter path |
| Adapter loads but scripts fail | Run `make quickstart`, then retry from repository root |
| WorkBuddy cannot find `src/skills` | Use a local project task with repository access; do not upload the thin adapter as a standalone Marketplace package |

## Official intelligent-agent references

- [OpenAI Codex customization](https://developers.openai.com/codex/codex-manual#customization-and-durable-instructions)
- [Cursor Project Rules](https://docs.cursor.com/context/rules)
- [Claude Code Skills](https://code.claude.com/docs/en/slash-commands)
- [OpenClaw Skills](https://docs.openclaw.ai/tools/creating-skills)
- [WorkBuddy Skill specification](https://open.workbuddy.cn/en/docs/skill)
