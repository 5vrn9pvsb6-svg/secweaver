# 00. Security Operator 10-Minute Quickstart

**Languages:** English (this page) | [简体中文](00-security-operator-quickstart.zh-CN.md)

Complete one AI investigation with synthetic logs: entry, execution, lateral movement,
and evidence gaps. No ES, SLS, production credentials, or Agent installation is required.
Real-data onboarding is an optional next step. For your first experience, complete only steps 1–3 below; read philosophy, field configuration, and deployment guides later as needed.

## Before You Start

Use a Linux/macOS POSIX terminal with Python 3.10+, Make, and an AI agent that can read
the local repository and run commands. The AI agent needs permission to read the repository,
execute `.venv/bin/python`, and write to `outputs/ai-showcase/`, with the repository root
as its working directory. Native Windows PowerShell is not supported by
these Make snippets: the virtual environment uses `.venv/bin/python`, not `Scripts/python.exe`.
WSL/Linux is a possible Windows route, but project end-to-end acceptance is still pending.
For a verified first run, use Linux/macOS; Windows Agent collection support is a separate matter.
Initial dependency downloads and hosted-model calls need a network. “Offline” means evidence
does not come from external data sources, not that the model runs offline.
The ten-minute estimate starts with dependencies and the AI agent available; initial environment setup takes additional time.

## 1. Initialize

Download and extract the project, or clone its repository. In your terminal, enter the directory
containing `README.md`, `Makefile`, and `src/`, rather than `docs_user/`. Check the tools first:

```bash
python3 --version
make --version
```

Python must be 3.10 or newer, and Make must print its version. If a command is unavailable,
install the tool or ask your administrator for help before continuing:

```bash
make quickstart
```

This creates `.venv`, validates DataAsset, runs four offline demos, and generates thin
adapters for five AI agents. Adapters reference `src/skills/` without copying Skill content.
Adapter generation does not mean the AI investigation has run.
Before dependency installation, Make checks the selected `PYTHON` interpreter and the
existing `.venv`. If either is below Python 3.10, it exits with a remediation message.
When the terminal prints `SecWeaver quickstart completed.`, initialization is complete.
Open the same project directory in your AI agent and continue with step 2.

## 2. Run the Case in Your AI Agent

Open this repository in Codex, Cursor, Claude Code, OpenClaw, or WorkBuddy and ask:

```text
Run the SecWeaver offline showcase.
```

The default request runs all 27 executable assessment cases. The AI agent reads the
corresponding Skills, writes a report for every successful case, and produces
`outputs/ai-showcase/suite-summary.md` with counts and failures.
Append a case ID to run only one; the example below focuses on `webshell-to-ssh-lateral`.
If the AI agent cannot discover the entry point, see [AI agent setup](38-ai-agent-host-setup.md).

## 3. Read the Result

Expand `outputs/ai-showcase/` in your AI agent's file list and open:

- `outputs/ai-showcase/webshell-to-ssh-lateral.json`: the script-generated structured result.
- `outputs/ai-showcase/webshell-to-ssh-lateral.md`: the investigation report written by the AI agent following the Skill. If it is missing, use the follow-up prompt below.

This fixed sample expects `overall_verdict=confirmed_intrusion_chain` and `blocked=false` in the JSON.

### Expected Report Example (Excerpt)

This reading example is based on the [public synthetic input](../examples/traceability/s1-web-shell-to-ssh-lateral.json) and current analysis output. It shows the content you should be able to understand, not a complete report template. Your AI agent's wording and layout may differ; key judgments must be supported by evidence.

> **Conclusion:** This synthetic case supports a chain of WebShell control, host execution, and SSH lateral movement. Commands execute on `web-01` (`10.0.1.5`), followed by successful SSH logins from that host to `db-01` and `app-02`. How the original intrusion occurred and the WebShell was planted remains unproven.

| Investigation point | Facts the report should explain | Evidence IDs to check |
|---|---|---|
| WEB and host behavior | A request to `/api/upload.php` precedes `whoami` execution and creation of `shell.php` on web-01 | `web-001`, `exec-001`, `file-001` |
| Tool download and execution | web-01 downloads `/tmp/sshscan`, makes it executable, then runs it against an internal SSH address range | `exec-002`, `exec-003`, `exec-004` |
| SSH lateral movement to db-01 | SSH records a successful root login from `10.0.1.5`, with a corresponding firewall connection | `ssh-002`, `fw-001` |
| SSH lateral movement to app-02 | The same source logs in successfully as deploy, with a corresponding connection | `ssh-003`, `fw-002` |

> **Evidence limits:** HTTP 200 or a WAF hit alone does not prove a successful intrusion. The sample provides no post-login command evidence from the lateral targets, so it cannot establish what ran there or whether data was stolen. These conclusions concern synthetic evidence only, not your production environment.

### When Is the Experience Complete?

- [ ] You found the JSON and its two expected fields match.
- [ ] You opened the Markdown report, can identify host execution and both SSH lateral paths, and understand that the original intrusion route is still uncertain.
- [ ] You can find at least two cited evidence IDs in the input file; the report explains gaps and conclusion limits.

The original request already includes the readable report: no second “generate a
report” instruction is needed. If only JSON was delivered, the task is incomplete.
The runner generates a structured-result Markdown baseline; the agent must review
it against the input and complete the Skill report, including evidence statistics,
investigation paths, timeline, impact and gaps. Do not just copy the excerpt above.

Without an AI agent, inspect [sample reports](../examples/reports/README.md), or run:

```bash
make ai-showcase
```

This generates JSON, per-case readable Markdown, and a readable batch summary.
See the [case catalog](../examples/ai-showcase/README.md) for all current cases and explicit selection.

## Troubleshooting

| Symptom | Next step |
|---|---|
| Make cannot find the Makefile or quickstart target | Return to the project root containing `Makefile` |
| Quickstart exits because Python is below 3.10 | Remove the old `.venv`, install Python 3.10+, then run `PYTHON=python3.10 make quickstart` |
| The report displays hosts as IPs | Use the sample mapping: web-01=`10.0.1.5`, db-01=`10.0.2.10`, app-02=`10.0.2.20` |
| Dependency installation fails | Check Python version and package-download connectivity, then rerun `make quickstart` |
| Adapter refuses to overwrite | Back up or merge existing AI agent configuration; preserve user-owned rules |
| AI cannot find the input | Open the repository root and allow local reads and command execution |
| Script reports missing dependencies | Use Make commands or `.venv/bin/python`; system Python may lack the installed dependencies |
| AI only repeats JSON | The task is incomplete; the agent must follow the selected Skill and finish the report without requiring a second request |

## Optional: Connect Real Data

| Goal | Next guide |
|---|---|
| Use the recommended SaaS query service | [SLS Proxy onboarding](30-sls-proxy-onboarding.md) |
| Install an Agent uploading to SaaS | [Data Cloud customer quickstart](29-secweaver-data-system-quickstart.md) |
| Send Agent logs to your ES | [Complete self-managed ES guide](../src/tools/secweaver-agent/elasticsearch/README.md) |
| Query existing ES, SLS, or other logs | [Configure sources](03-configure-data-sources.md) |
| Explore DataAsset Studio | [UI walkthrough](11-onboarding-ui-walkthrough.md) |

Run `make ui` and visit `http://127.0.0.1:8765/` to view and edit `dataasset/` by default.
Studio occupies the terminal; stop it with Ctrl+C. For isolation, optionally copy to
`dataasset_my/` and set `DATAASSET_ROOT` as described in the onboarding guide. Do not
commit real credentials or customer configuration. Studio is not an AI chat page.
Additional commands are in the [CLI reference](13-SecWeaver-CLI.md); configuration manuals
are not prerequisites for the first experience.
