# Log Format Discovery — Sample Data

Raw log samples for `discover.py` preprocessing and field mapping (requires a dataasset with `status: discovery`).

## Samples

| File | Type | Notes |
|---|---|---|
| [waf-jsonl.sample](waf-jsonl.sample) | WAF JSONL | Inconsistent field names (`client_ip` / `remote_addr`) |
| [ssh-auth.log.sample](ssh-auth.log.sample) | SSH auth.log | Standard syslog format |
| [host-exec-jsonl.sample](host-exec-jsonl.sample) | audit-port-execmon | One exec and one active_connect event each |
| [host-exec-webshell-no-tty.sample](host-exec-webshell-no-tty.sample) | audit-port-execmon | WebShell/RCE without TTY |
| [vendor-cloud-audit.sample](vendor-cloud-audit.sample) | Vendor cloud audit | Noncanonical field names |
| [vendor-edr-identity.sample](vendor-edr-identity.sample) | Vendor EDR identity | Noncanonical identity fields |

## Run

Recommended via the `secweaver` CLI:

```bash
# Use offline samples (no live credentials required)
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample

# Other samples
python3 src/secweaver.py asset discover-format <discovery-asset-id> \
  -i examples/log-format-discovery/ssh-auth.log.sample
```

For the discovery queue, report export, or LLM prompt generation, use the underlying script:

```bash
# List discovery queue
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery

# Export full report
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample \
  --preview-normalize --pretty -o /tmp/discovery-report.json
```

Both WAF rows are within the same minute on 2026-06-21; they use string
`@timestamp` and epoch-seconds `__time__` respectively. `normalized_preview`
should expose canonical `src_ip`, `timestamp`, and `url` for both. Regression
checks this discovery-to-normalized-preview path against the public discovery
asset. Preview does **not** establish a live connection, applied mapping, or
downstream fetch. The other vendor samples still cover format detection and
preview only, not their completed field mappings.

## Related

- Skill: `src/skills/log-format-discovery/SKILL.md`
- Docs: [docs_user/20-log-format-discovery.md](../../docs_user/20-log-format-discovery.md)
