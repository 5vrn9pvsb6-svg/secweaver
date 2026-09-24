---
name: offline-showcase
description: >-
  Reads bundled offline evidence and invokes the matching analysis Skill,
  including traceability-analysis or risk-identification, to produce an
  evidence-backed report without ES, SLS, or credentials. Use for a quick product
  experience, showcase, test case, sample incident, or says 运行离线案例、快速体验、
  不接数据源看看效果.
---

# SecWeaver Offline Showcase

**Languages:** English (this document) | [Simplified Chinese](SKILL.zh-CN.md)

This Skill owns case selection and offline input preparation. The selected
analysis Skill owns evidence interpretation and the final investigation report.

## Default deliverable / 默认交付

`运行 SecWeaver 离线案例` means **run all catalog cases and deliver readable reports**.
The user does not need to add `形成可读的报告`, `生成报告`, or a second instruction.
默认交付：全部案例运行结果、每例可读分析报告、带报告链接的可读汇总。
Do not stop at PASS output or JSON. Report writing and evidence review are part of
the same authorized task, not an optional follow-up. For a named case, deliver its
readable report by default as well.

## Case selection

Read [`examples/ai-showcase/cases.json`](../../../examples/ai-showcase/cases.json).

- If the user names a case, select that `case_id`.
- If the user asks to list or compare cases, summarize the catalog without running one.
- If the user only asks to run the offline showcase (including `运行 SecWeaver 离线案例`),
  run every entry in `cases[]` in catalog order. Do not select a single default
  case or ask the user to choose. New catalog entries join the default run.
- The catalog covers all executable assessment inputs; derive the current count
  from `cases[]`, never from a hard-coded number. Prompt-only
  fetch fixtures and raw format-discovery samples are separate workflows, not
  executable assessment cases; do not claim those were analyzed by this run.
- If the user asks for host risk analysis without a case ID, select
  `reverse-shell-risk`; for an attack chain, select `webshell-to-ssh-lateral`.

## Analysis Skill routing

| Offline case | Analysis Skill to invoke |
|---|---|
| `webshell-to-ssh-lateral` and other traceability cases | [traceability-analysis](../traceability-analysis/SKILL.md) |
| `reverse-shell-risk` and other host risk cases | [risk-identification](../risk-identification/SKILL.md) |
| Alert cases | [alert-confirmation](../alert-confirmation/SKILL.md) |
| Data-source completeness cases | [data-source-completeness](../data-source-completeness/SKILL.md) |

Use each entry's `skill_doc` for routing; the table is a guide, not a fixed case list.

Invoke means reading and following that Skill's full workflow, running its
analysis script through the runner, and completing its report requirements.
The runner executes deterministic analysis, checks expected fields, and always
writes readable structured-result Markdown alongside JSON. These automatic
reports are a baseline, not the intelligent agent's narrative analysis or a
replacement for the delegated Skill's report contract.

## Run

1. For each selected entry, read its `input` JSON, including its evidence and completeness
   precheck. Confirm `offline: true`. Treat `_meta.expected_*` and catalog
   `expected` values as regression assertions only, never as incident evidence.
2. Read the delegated `skill_doc` completely and tell the user which analysis
   Skill is being invoked. Its workflow and reporting contract are authoritative.
3. From the repository root on Linux, macOS, or WSL2, run `.venv/bin/python
   src/scripts/run_ai_showcase.py <case_id>`. Windows users must run the Skill inside
   WSL2; native Windows is not a supported Community client runtime. Omit `<case_id>`
   (or use `--all`) to
   run all cases. The runner continues after individual failures and writes
   `outputs/ai-showcase/suite-summary.json` and `suite-summary.md`; each successful
   case writes `<case_id>.json` and `<case_id>.md`. A report write failure also
   counts as failure. A nonzero exit means at least one
   failure, not that the remaining cases were skipped.
4. Do not add `--fetch`, resolve credentials, contact a live endpoint, or send a
   notification. The runner requires `--no-ip-intel --no-notify` for traceability,
   enforces the offline boundary, and validates stable expected fields. The WebShell-to-SSH
   case confirms SSH lateral evidence but leaves the original compromise point
   unresolved; report that gap rather than calling the full entry chain proven.
5. For every successful entry in this run, read the JSON printed as `Result` alongside the offline input. The runner's
   `Report` path points to an automatically generated baseline. Complete
   the selected analysis Skill's evidence review and Markdown report, saving it
   beside the JSON as `<case_id>.md`, replacing the baseline with your reviewed
   analysis. Do not call an unreviewed baseline an AI-authored investigation.
   Rerunning a case overwrites its JSON and Markdown; always finish analysis after
   the final run, rather than leaving an older narrative attached to new results.
   An expectation mismatch is a regression
   signal; report it instead of rewriting the expected result.
6. For a batch, finish the generated `outputs/ai-showcase/suite-summary.md` with total/passed/failed
   counts, each case's verdict and limitations, and links to its JSON and AI-authored
   Markdown report. Include failures and their errors; old files for failed cases
   are not current results. Continue producing reports for the successful cases.
7. Before finishing, compare the current run's successful IDs with report paths.
   Verify every successful case has a nonempty, reviewed Markdown report and every
   summary link resolves. Link the readable summary first in the final response;
   include total/passed/failed counts. If report generation or review is incomplete,
   say so explicitly and do not claim the offline showcase is complete.

The inputs are synthetic test evidence. Running a case may write only under
`outputs/ai-showcase/`, which is ignored by Git.

## Complete the analysis

Follow the selected analysis Skill's report template rather than substituting a
generic showcase summary. For traceability, include the required evidence
statistics, attack path, cited timeline, confirmed/suspected lateral movement,
impact and gaps. For risk identification, include its evidence statistics,
risk items, severity, evidence references, rule/MITRE mapping and actions.

The task is complete when every successful case has its analysis Skill report,
failures are disclosed, and the batch summary (or single report) is linked with a
concise conclusion in chat. A runner success message, matched
expected verdict, or JSON file link alone is not a completed investigation.

State that this was an offline synthetic case and that no ES, SLS, credential,
or production data was used. Do not imply a live environment was investigated.
