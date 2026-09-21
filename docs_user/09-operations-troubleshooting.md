# 09. Operations Checks and Troubleshooting

**Languages:** English (this page) | [简体中文](09-operations-troubleshooting.zh-CN.md)

This guide explains what to check when maintaining `dataasset/` day to day, and how to troubleshoot common issues.

---

## What to Do First After Changing Configuration

Run validation first:

```bash
.venv/bin/python src/dataasset/validate.py
```

If the project has no virtual environment, try:

```bash
python3 src/dataasset/validate.py
```

For JSON output:

```bash
.venv/bin/python src/dataasset/validate.py --json
```

For root causes, fix steps, and related docs:

```bash
.venv/bin/python src/dataasset/validate.py --diagnose
```

You can also use the unified CLI:

```bash
python3 src/secweaver.py validate --diagnose
```

---

## How to Switch to a Private Asset Directory

If real assets are stored in `dataasset_my/`, do not overwrite the published `dataasset/` directory. Operators can temporarily select the asset root with `DATAASSET_ROOT`:

```bash
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --diagnose
```

The same variable applies when starting DataAsset Studio:

```bash
DATAASSET_ROOT=dataasset_my DATAASSET_UI_PORT=8765 python3 dataasset-ui/server.py
```

Use the same variable for connectivity checks and dry-runs so you do not accidentally test the default `dataasset/` tree:

```bash
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py asset test YOUR_ASSET_ID --dry-run
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py asset apply -f dataasset_my/onboarding/examples/data-sources.sample.json --dry-run
```

Team convention:

- `dataasset/`: default local configuration directory; only sanitized public examples may be committed.
- `dataasset_my/`: local or private real asset directory, not committed to the open-source repository.

---

## What Does validate Check?

Typically:

- JSON file format is valid.
- Filenames match IDs.
- Assets reference existing Connectors.
- Connector credential references are reasonably formatted.
- Assets reference existing Query Templates.
- Fields meet minimum evidence requirements.
- Host / Network / `coverage.hosts` are consistent.
- Host IPs fall within Network CIDRs.
- Scenario Patterns reference existing Bundles.
- Correlation Matrix Join fields are reachable.
- Correlation Matrix `fetch_plan` resolves to templates and parameters.
- `catalog` matches directory contents.

---

## Understanding error, warning, and blocking

| Type | Meaning | Recommended action |
|---|---|---|
| `blocking` | Blocks formal use | Must fix |
| `error` | Clear error; may cause fetch or correlation failure | Must fix |
| `warning` | Risk or non-recommended configuration | Fix after evaluation or document reason |

General target:

```text
blocking = 0
error = 0
warning = as few as possible, with a known reason for each
```

---

## How to Use Configuration Diagnostics

`--diagnose` enriches each issue into an operator-facing diagnostic card. It typically includes:

- `category`: issue type, such as `credential`, `connector_config`, `field_contract`, `correlation_matrix`, or `status_lifecycle`.
- `root_cause`: why the issue happened.
- `suggested_fix`: the most direct remediation.
- `fix_steps`: recommended steps in order.
- `docs`: related documentation paths.

If you use dataasset-ui, the validation page shows the same diagnostic cards. When onboarding preview or apply fails, the UI prioritizes advice for JSON syntax, field spelling, overwrite conflicts, missing templates, and unknown connector types.

---

## Turn Validation Findings into an Action Plan

Do not edit JSON blindly from an `ERROR` or `WARN` line. Preserve the complete output,
identify the affected object and runtime path, assign an owner, make the smallest change,
and run the relevant verification again.

```text
1. Run validate and retain the complete output
2. Group findings by blocking / error / warning and affected object
3. Confirm the root cause using --diagnose
4. Assign operator, senior operator, development, or security review
5. Apply the smallest configuration or code change
6. Re-run registry validation and the affected connector/query check
7. Promote to active only after the acceptance query passes
```

Use this priority model:

| Priority | Typical finding | Owner | Release effect |
|---|---|---|---|
| P0 | Schema failure, active object references a missing/draft dependency, active Connector lacks a credential reference | Operator first; development if validator or schema is wrong | Blocks activation/release |
| P1 | Missing alias, unreachable Join field, coverage host is not an IP, template/Connector mismatch | Senior operator or security engineer | Usually blocks trusted investigation |
| P2 | Incomplete draft metadata or documentation warning | Operator backlog | Does not always block |

Operators can normally correct object status during onboarding, IDs and references,
verified per-Asset aliases, `coverage.hosts`, and Vault references. Escalate these cases:

| Escalate when | Why |
|---|---|
| A new Connector runtime or built-in parser is required | It changes executable fetch or parsing behavior |
| A complex Correlation Matrix Join is introduced | It can change investigation conclusions |
| `validate.py` appears to report a false positive | Validation logic or Schema may need a code change |
| A production SQL, ES DSL, or SLS query needs structural changes | Security, performance, and indexed-field behavior need review |

After a fix, run only the checks that prove the affected behavior, plus final registry
validation. A typical source-onboarding loop is:

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py YOUR_ASSET_ID --by-asset --dry-run
.venv/bin/python src/dataasset/test_connector.py YOUR_ASSET_ID --by-asset \
  --params '{"time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z","src_ip":"203.0.113.10"}'
```

The live command must use an authorized known event and real time window. Empty results do
not prove the source works. Field-specific failures belong in
[Log Format Discovery](20-log-format-discovery.md#field-discovery-and-normalization-model);
the full status lifecycle belongs in
[How to Configure Data Sources](03-configure-data-sources.md#end-to-end-onboarding-workflow).

---

## Common Issue 1: Asset References a Connector That Does Not Exist

Symptom:

```text
asset xxx references a non-existent connector_id
```

Troubleshooting:

1. Check `connector_id` in `dataasset/assets/asset-xxx.json`.
2. Check whether a matching file exists under `dataasset/connectors/`.
3. If it is only a reference template, put it in `dataasset/examples/connectors/`, not in production `connectors/`.
4. If the connector is a production fetch path, move it back to `dataasset/connectors/` and ensure `connector_id` matches.

Note: Connectors not referenced by any asset are no longer reported as warnings. They may be spare connectors, jump hosts, connectors in onboarding, or operational inventory; validate only blocks “asset references non-existent connector.”

---

## Common Issue 2: Query Template Missing or Mismatch

Symptom:

```text
query_template_id does not exist
```

Or fetches return no data.

Troubleshooting:

1. Confirm `query_template_ids` on the Asset exist.
2. Confirm the Template supports the `connector_type`.
3. Confirm all required Template parameters can be supplied.
4. Confirm field names in the query match the log source.

---

## Common Issue 3: Fields Do Not Correlate

Symptom:

```text
Join did not match
data_gaps shows no_match
```

Possible causes:

1. Two data sources use different field names without `field_aliases`.
2. An Asset’s `schema.fields` is missing key fields.
3. Time window is too narrow.
4. Query results contain no relevant events.
5. Hostname and IP are not linked via asset inventory or the Host registry.

Remediation:

- Check `schema.fields` includes fields required for Joins.
- Check `field_aliases` covers source fields.
- Check Join fields in `correlation-matrix.json`.
- Widen the time range if appropriate.
- Add `asset_inventory` or Host configuration.

---

## Common Issue 4: Host and Network Mismatch

Symptom:

```text
host_ip is not in network.cidr
host.zone does not match network.zone
```

Troubleshooting:

1. Is the Host `host_ip` correct?
2. Is the Host `network_id` correct?
3. Is the Network `cidr` correct?
4. Should Host and Network `zone` match?

Fix principles:

- Wrong IP → fix Host.
- Wrong subnet → fix Network.
- Host spans multiple subnets → add `interfaces`.

---

## Common Issue 5: AI Output Says “Insufficient Evidence”

This is not necessarily an AI fault.

Possible causes:

1. Data source not onboarded.
2. Data source is `draft`, not enabled for production.
3. Query template returns no data.
4. Time window is wrong.
5. Field mapping is wrong.
6. Join rules did not match.
7. The environment truly had no related behavior.

Recommended troubleshooting order:

```text
Does the Bundle include the relevant Asset?
Is the Asset active?
Is the Connector usable?
Does the Query Template return raw data?
Are fields normalized?
Did Joins match?
Is the time window reasonable?
```

---

## Common Issue 6: LLM Conclusions Are Unstable

If the same question yields very different answers, constraints are usually insufficient.

Check:

1. Is there an explicit Scenario Pattern?
2. Does the Scenario Pattern specify a recommended chain?
3. Does the Correlation Matrix define Join rules?
4. Is output based on `join_edges`?
5. Are data gaps passed clearly to the model?

Principle:

```text
The more configured the investigation path, the more stable the model output.
```

---

## Recommended Routine Health Checks

Check regularly:

- validate passes.
- Active asset count matches expectations.
- Draft assets are not stuck unpublished for long.
- Discovery assets still need format discovery.
- Connectors are not orphaned or obsolete without reason.
- Bundles cover key scenarios.
- S1–S8 each have at least minimal data sources.
- Query templates still return data.

---

## Pre-Production Data Source Checklist

- [ ] Connector contains no plaintext secrets.
- [ ] Credentials are configured correctly.
- [ ] Connector dry-run passes.
- [ ] Asset fields are complete.
- [ ] Query Template is usable.
- [ ] Added to the correct Bundle.
- [ ] validate passes.
- [ ] Status changed from `draft` to `active`.
- [ ] At least one real or sample investigation completed successfully.

---

## Next Steps

Continue reading: [10. FAQ](10-faq.md)
