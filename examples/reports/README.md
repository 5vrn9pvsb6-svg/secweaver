# SecWeaver Sample Reports

Sample outputs for the open-source SecWeaver experience.

**Languages:** English (primary) | [简体中文](README.zh-CN.md)

These files are generated from offline inputs under `examples/` and demonstrate structured verdicts, evidence chains, join edges, and data gaps.

Reading note: this English index is concise; the Chinese index provides more detailed interpretation. Generated `demo-*.zh-CN.md` and `investigation-report.zh-CN.md` retain some English headings and field names from the current templates. Their suffix does not imply a complete manual translation. Change the report templates and regenerate rather than hand-editing generated output.

## Regenerate

```bash
make reports
```

Equivalent manual steps:

```bash
python3 src/secweaver.py demo all
python3 src/secweaver.py report markdown --demo all --bundle
```

## Generated files

| File | Demo | Description |
|---|---|---|
| `demo-completeness-output.json` | `completeness` | Data source completeness precheck |
| `demo-alert-output.json` | `alert` | WAF/WEB alert confirmation |
| `demo-traceability-output.json` | `traceability` | Attack chain traceability |
| `demo-risk-output.json` | `risk` | Host behavior risk identification |
| `demo-*-output.md` | — | Markdown reports per demo |
| `investigation-report.md` | — | Bundled investigation report |

## Typical investigation chain

```text
Data source completeness
        ↓
Alert confirmation (WebShell success)
        ↓
Traceability (entry, execution, lateral movement)
        ↓
Risk identification (high-risk listener behavior)
```

## How to read the outputs

1. Start with `overall_verdict` / `alert_verdict`.
2. Check `confidence`.
3. Review `evidence` / `evidence_refs`.
4. Inspect `join_edges` for cross-source correlation.
5. Read `data_gaps` for unsupported conclusions.
6. Follow `recommended_action` / `next_skill` for next steps.

For detailed Chinese walkthroughs of each sample field, see [README.zh-CN.md](README.zh-CN.md).

## Single-file conversion

```bash
python3 src/secweaver.py report markdown \
  -i examples/reports/demo-alert-output.json \
  -o /tmp/alert-report.md
```
