# SecWeaver Offline Agent Showcase

Experience SecWeaver in Codex, Cursor, Claude Code, OpenClaw, or WorkBuddy without
connecting ES, SLS, or production data.

## Fastest path

From the repository root:

```bash
make quickstart
```

Then open an intelligent agent in this repository and ask:

```text
Run the SecWeaver offline showcase.
```

Without a case ID, run all 27 executable assessment cases in catalog order.
An explicit ID runs just that case; existing IDs remain supported. Readable reports
are included by default: no extra “generate a report” request is needed.

`offline-showcase` reads the selected offline input and invokes the corresponding
analysis Skill: `traceability-analysis` for attack chains, or `risk-identification`
for host risks. The agent follows that Skill's workflow and writes its full
Markdown report beside the JSON under `outputs/ai-showcase/`. Alert and data-gap
cases use their corresponding alert-confirmation and completeness Skills.
Expected verdict checks validate the script result; the AI analysis and report
remain a required part of the host experience.

## Cases

| Case ID | Scenario | Skill |
|---|---|---|
| `webshell-attack-confirmation` | Confirm a successful WebShell attack | `alert-confirmation` |
| `false-positive-parameter` | Recognize a false-positive request parameter | `alert-confirmation` |
| `webshell-to-ssh-lateral` | Reconstruct WebShell-to-SSH lateral movement | `traceability-analysis` |
| `reverse-shell-risk` | Detect a reverse shell from host evidence | `risk-identification` |
| `missing-host-exec-data` | Stop traceability when host evidence is missing | `data-source-completeness` |
| `s1-full-traceable` | Complete traceability sources | `data-source-completeness` |
| `s4-alert-triage-only` | Alert triage without host evidence | `data-source-completeness` |
| `s4-partial-missing-connect` | Missing connection evidence | `data-source-completeness` |
| `s4-scanner-generic-no-payload` | Generic scanner without payload | `alert-confirmation` |
| `s4-sqli-blocked-no-breach` | Blocked SQL injection attempt | `alert-confirmation` |
| `s1-scan-only-no-host-exec` | Scan without host execution | `traceability-analysis` |
| `s2-initial-access-no-lateral` | Initial access without confirmed lateral movement | `traceability-analysis` |
| `s5-curl-download-exec-p0` | Download and execute from a Web process | `risk-identification` |
| `s5-external-connect-p0` | Outbound connection from a Web listener | `risk-identification` |
| `s5-nginx-config-test-whitelisted` | Whitelisted nginx configuration test | `risk-identification` |
| `s5-persistence-authorized-keys-p0` | SSH authorized keys modification | `risk-identification` |
| `s5-ssh-bruteforce-p0` | Ten SSH authentication failures | `risk-identification` |
| `s5-ssh-nine-failures-below-threshold` | Nine SSH failures below threshold | `risk-identification` |
| `s5-whoami-recon-p0` | Discovery from a Web process shell | `risk-identification` |
| `s8-dns-dga-p1` | Suspicious DNS without connection evidence | `risk-identification` |
| `s6-full-traceable` | Complete account-compromise data sources | `data-source-completeness` |
| `s6-not-traceable-missing-auth` | Account investigation without authentication logs | `data-source-completeness` |
| `s7-full-traceable` | Complete data-exfiltration sources | `data-source-completeness` |
| `s7-partial-missing-traffic-volume` | Exfiltration investigation without traffic volume | `data-source-completeness` |
| `s4-batch-mixed-with-query-gap` | Mixed alert batch with an incomplete query | `alert-confirmation` |
| `s6-root-ssh-login-p1` | Suspicious root SSH login | `risk-identification` |
| `s7-data-staging-and-scp-p0` | Data staging and outbound SCP candidate | `risk-identification` |

Example:

```text
Run the SecWeaver offline case webshell-to-ssh-lateral and show the entry point,
execution, lateral path, evidence, and gaps.
```

The machine-readable catalog is [`cases.json`](cases.json). Inputs are synthetic
and stored under `examples/`; generated results go to
`outputs/ai-showcase/`, which Git ignores.
The WebShell-to-SSH case identifies observed WebShell control and lateral logins, not the
original compromise method. The runner requires live fetch, notification, and
online IP-intelligence lookups to remain disabled. Add `--no-ip-intel --no-notify`
when running the traceability script manually with the same offline guarantee.

## Without an agent

The deterministic analysis and expected-verdict checks can also run from the CLI.
This command produces JSON and readable structured-result Markdown automatically;
use the agent for the Skill-guided evidence review and narrative analysis:

```bash
make ai-showcase
make ai-showcase CASE=false-positive-parameter
```

No case requires a credential or live network query.

## Batch behavior and verification

After the documented quickstart, `make ai-showcase` or
`.venv/bin/python src/scripts/run_ai_showcase.py --all` on macOS/Linux, and
`.venv\Scripts\python.exe src\scripts\run_ai_showcase.py --all` in native Windows
PowerShell, run the whole catalog sequentially with a 60-second limit per case.
No network is needed after dependencies are installed.

Each passing case writes `<case_id>.json` and `<case_id>.md`; `suite-summary.json`
and `suite-summary.md` record every case, counts, failures and report links. Failures and timeouts do not stop later cases; any failure makes
the process exit nonzero. Old files may remain for failed cases: use the current
summary rather than assuming every file belongs to this run. A single explicit ID
retains its JSON output and also writes a Markdown report. `--list` lists without running.

Reports default to Chinese and include evidence statistics, verdicts, source records,
rules or readiness requirements, gaps and suggested actions. Recorded synthetic
query failures are labeled as replay metadata, not live queries. Automatic reports
are explicitly labeled as structured results awaiting agent review, not AI-authored
investigations. Report write failures count as failures and return a nonzero exit.
`--json` only changes console formatting; Markdown is still generated. The console
prints `Report:` paths and JSON summaries include `report` and `report_kind`.
Reruns replace both JSON and Markdown, including any earlier narrative. The agent
must review the latest evidence, replace the baseline with the analysis Skill's
report, finish the readable summary, and link it before ending the task.
The batch covers 27 assessment inputs (8 completeness, 5 alert, 3 traceability, 11 risk).
The 2 prompt-only fetch fixtures and 6 raw format samples are separate validation
workflows described in the [full catalog](../CASE-CATALOG.md).

Verify selection, failure continuation and all expected verdicts with:

```bash
.venv/bin/python -m unittest discover -s tests -p test_ai_showcase.py -v
```

When adding an assessment input, register it in `cases.json` with its Skill, offline
arguments and expected fields; the coverage test rejects unregistered inputs.
Existing single-case automation should now pass its case ID explicitly.
