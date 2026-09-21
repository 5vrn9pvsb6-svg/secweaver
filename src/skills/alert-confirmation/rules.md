# Alert Confirmation — Decision Reference

This page explains deterministic decision order. Run [confirm.py](scripts/confirm.py); see [attack-types.json](attack-types.json) for attack types, indicators and actions, and [fp-patterns.json](fp-patterns.json) for false-positive patterns.

## 1. Two-layer triage

Determine `alert_verdict` (false positive, scanning, suspicious or confirmed attack), then `attack_outcome` (success). An exploit payload does not prove success; missing payload does not justify a success conclusion either. Decoding, matching and correlated upgrades are defined in the [implementation design](../../../docs_dev/14-alert-confirmation-skill-design.md) and [layer1.py](scripts/alert_confirmation/layer1.py).

## 2. Per-alert outcome order

This order follows [layer2_outcome()](scripts/alert_confirmation/success.py):

1. `false_positive` → `not_applicable`.
2. Other inputs outside suspicious/scanning_or_probe/confirmed_attack → `success_unknown`.
3. `mode=triage_only` → `success_unknown`, even when candidate D2 evidence was supplied.
4. Full mode with attributed `success_refs` → `success_confirmed`.
5. No success proof, `confirmed_attack` and WAF action in `blocked_actions` → `blocked`.
6. No success proof and no D2 → `success_unknown`.
7. D2 exists without success proof → `attempt_failed`.

`attempt_failed` means no success indicator was found in the supplied evidence; it does not guarantee environmental safety. `campaign_success` is a separate activity-level result and does not establish success for every alert.

## 3. Evidence eligible to confirm success

The window comes from `time_windows.attack_success` in [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json), currently **5 minutes before and 30 minutes after**. Target attribution is required. When WEB logs exist, evidence must also match successful request contexts, their targets and timing. `find_d2_success()` defines the detailed scope and fallback behavior.

| D2 source | Attack-type compatibility |
|---|---|
| host_exec | SQLi accepts only database indicators; path traversal accepts file_read/sensitive_file_read; RCE/WebShell accepts shell/download/webshell_cmd/file_read/sensitive_file_read; SSRF accepts download/shell |
| host_connect | Outbound indicators support RCE/WebShell/SSRF only |
| host_file_op | File indicators support RCE/WebShell/path traversal only |
| host_persistence | Persistence indicators support RCE/WebShell; unknown and scanner fingerprints use generic compatibility |

unknown/scanner_fingerprint accepts a broader indicator set but still requires attribution and window checks. Indicator values come from `success_indicators`; compatibility is implemented by `_indicator_compatible()`.

**WEB status codes are not D2.** HTTP 200/500, unusual responses and WAF pass actions provide context or candidate signals, not standalone success proof. `gateway_success_hint` is a D1.5 hint that may change review recommendations without rewriting the per-alert outcome.

## 4. Actions, confidence and downstream work

Recommendations consider false positives, confirmed success, repeated confirmed attacks, blocking, scanning and suspicious signals in that order. `recommended_action_map`, gateway hints and IP blocking safeguards affect the final advice. Success defaults to `escalate_investigate`; repeated-attack blocking advice is subject to IP context safeguards and does not authorize automatic blocking or isolation.

Confidence is a rule score. The effective ceiling may be raised by confirmed-attack/D2-success floors in `layer1_upgrade` before bounding the final score; it is not always the original upstream confidence. Formulas and defaults are maintained in the [design confidence reference](../../../docs_dev/14-alert-confirmation-skill-design.md).

Use `traceability-analysis` for cross-host chains and `data-source-completeness` for missing coverage. This skill does not perform lateral BFS. Command risk uses the parent `risk-identification` detection, policy and whitelist workflow; a command severity is not itself proof of this alert's success.

## 5. Offline acceptance and counterexamples

| Case and prerequisites | Expected result |
|---|---|
| Full mode + SQLi + blocked, no success proof | confirmed_attack / blocked |
| Triage-only mode + the same SQLi alert | confirmed_attack / success_unknown |
| Business UUID false hit without an exploit | false_positive / not_applicable |
| SQLi + same-host/window curl, no database indicator | curl is supporting only, not success_confirmed; full/unblocked with D2 yields attempt_failed |
| RCE/WebShell + exec matching attribution, window and attack type | Full mode can produce success_confirmed |
| WEB 500 alone or DNS/egress context alone | No standalone success proof |

Run a public synthetic fixture from the repository root, without credentials:

```bash
python3 src/skills/alert-confirmation/scripts/confirm.py \
  -i examples/alert-confirmation/s4-webshell-attack-success.json
```
