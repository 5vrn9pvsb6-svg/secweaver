---
name: dataasset-validation-advisor
description: >-
  Validate SecWeaver dataasset registry and explain actionable fixes. Use when
  the user asks to 校验数据源资产, validate dataasset, check data assets, analyze
  validate.py output, explain validation errors, or give suggestions for assets,
  connectors, bundles, credentials, hosts, schemas, or query templates.
---

# Data Asset Validation and Recommendations

Run “executable validation + human-readable advice” on `dataasset/`: run deterministic scripts, categorize errors/warnings, explain impact, and give minimal fix paths.

## When to use

- User says “validate data,” “check dataasset,” “how to read validate errors,” “suggest fixes”
- After editing `assets/`, `connectors/`, `bundles/`, `hosts/`, `query-templates/`, `schema/` — health check
- Before publishing assets / bundles — confirm ready for `active`
- Recheck a historical issue from `docs_dev/history/10-data-asset-design-evaluation.md` against current schemas and code

## Required commands

From repo root:

```bash
# Preferred: project venv so jsonschema works
.venv/bin/python src/dataasset/validate.py 2>&1

# When catalog changed
.venv/bin/python src/dataasset/validate.py --sync-catalog 2>&1
```

If `.venv` missing or lacks `jsonschema`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install jsonschema
```

Do not force-install on system Python; macOS/Homebrew Python may be PEP 668 protected.

## Analysis workflow

1. Run validate; keep full stdout/stderr.
2. Split by prefix: `ERROR:` blocks, `WARN:` advisory.
3. Group by object: asset / connector / bundle / host / schema / catalog / template.
4. Per category output:
   - **Symptom**: raw error summary
   - **Cause**: which contract violated
   - **Impact**: blocks active / fetch / Skill?
   - **Suggested fix**: conservative, minimal change
5. Clearly distinguish:
   - **Design issues**: script or schema needs change
   - **Operational data issues**: example draft, placeholders, not promoted, real connection params missing
   - **Acceptable warnings**: onboarding draft, example dir notes, catalog remarks; unreferenced connectors no longer warned
6. Do not flip draft to active just to green validate; set active only after connectivity test and field confirmation.

## Common errors and suggestions

| validate output | Cause | Suggestion |
|---|---|---|
| `environment: 'lab' is not one of ...` | asset schema allows only `production/staging/development` | POC/lab assets → `development`, or extend schema if team agrees |
| `correlation-matrix.json: asset_id=None` | Old validate scanned matrix as asset | validate now skips matrix in asset scan and runs matrix-specific checks; if reproduced, script regressed |
| `active bundle references non-active asset` | active bundle publish contract broken | Onboarding bundle → `draft`; or test and promote member assets first |
| `query_template_id ... not in templates.json` | asset references missing template | Add template or remove reference |
| `connector ... no matching query_template` | connector_type vs template mismatch | Add template for connector_type or adjust asset `query_template_ids` |
| `credentials_ref invalid/missing` | active connector missing vault ref | Set `vault://namespace/name`; local_file may be exempt |
| `asset-coverage-host-not-ip` | hostname/alias/text in `coverage.hosts` | Use actual log source IP; put aliases in `host.aliases` |
| `connector ... config.host_id references unknown host` | single-host connector points to missing host | Add host or fix connector.config.host_id |
| `text_parser valid under each of ...` | oneOf branches overlap | Add `not enum` to custom parser string branch to exclude built-in ids |

## Output format

Deliver an operations-ready short report. Do not paste validate raw only; each issue needs owner, blocking status, how to fix, dev involvement.

### Overview

```markdown
## Validation Result

- Errors: N
- Warnings: M
- Blocks release: yes/no
- Suggested owner: ops / senior ops / engineering / security
- Fix order: P0 → P1 → P2
```

### Issue detail table

```markdown
| Priority | Object | Issue | Cause | Impact | Fix | Owner | Dev needed? |
|---|---|---|---|---|---|---|---|
| P0 | asset / connector / bundle / matrix | raw error summary | contract violated | blocks active / fetch / Skill | minimal change | ops | no |
```

Priority definitions:

| Priority | Meaning | Release impact |
|---|---|---|
| P0 | `ERROR` or causes active/fetch/Skill failure | Must fix |
| P1 | `WARN` lowering investigation confidence or data gaps | Fix this round |
| P2 | Docs, examples, redundancy, acceptable warnings | Schedule |

### Per-issue explanation card

For each P0/P1 issue, at least one card:

```markdown
### [P0] <object>: <issue title>

- **Raw output**: `ERROR/WARN: ...`
- **What it means**: ops-friendly explanation.
- **Why**: cite contract — schema, coverage.hosts, connector, template, bundle, matrix.
- **Impact**: validate, test-connector, fetch, completeness, alert confirmation, traceability.
- **Minimal fix**: change only required JSON fields.
- **Example change**: JSON snippet or file path.
- **Owner**: ops / senior ops / engineering / security.
- **Re-verify**: `validate.py` / `test_connector.py` / corresponding Skill command.
```

### Copy-paste fix examples for ops

When fix is clear and low-risk, provide copyable JSON:

```json
"field_aliases": {
  "host_name": "host",
  "time": "timestamp"
}
```

Do not auto-edit files unless user explicitly says “fix it for me.”

### When uncertain

If context is missing, do not guess:

```markdown
Need confirmation:
1. Does production log raw data actually include `<field>`?
2. Should this connector be referenced by an asset, or kept as jump/backup?
3. Is this bundle going active, or staying draft during onboarding?
```

## Optional fix actions

Edit files only when user explicitly requests “fix.” State which files before editing. Common safe fixes:

- `asset-local-lab-auth.environment: lab → development`
- Onboarding `bundle.status: active → draft`
- Fix non-IP values in `coverage.hosts`; aliases in `host.aliases`
- `validate.py` skips `assets/correlation-matrix.json` in normal asset scan; runs matrix-specific checks
- When extending schema (e.g. `pii_fields`), sync design and assessment docs

## Reference files

- `src/dataasset/validate.py`
- `dataasset/schema/*.schema.json`
- `dataasset/README.md`
- `docs_dev/09-data-asset-design.md`
- `docs_dev/history/10-data-asset-design-evaluation.md` (historical context only)
- `src/skills/_shared/data-access/README.md`
