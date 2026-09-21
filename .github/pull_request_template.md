## Summary

<!-- What does this PR change and why? Link issues with "Fixes #123" when applicable. -->

## Type of change

- [ ] Bug fix
- [ ] Feature / enhancement
- [ ] Example DataAsset (connector, asset, host, network, bundle)
- [ ] Skill or demo sample
- [ ] Documentation
- [ ] Tests / CI only

## Checklist

- [ ] I ran `make ci`, or listed each unrun gate and its reason below (partial checks are not equivalent to CI)
- [ ] No real credentials, tokens, private keys, or files under `dataasset/credentials/secrets/`
- [ ] No production logs, customer data, or unsanitized internal IP inventories
- [ ] Example connectors use `REPLACE_ME`, `YOUR_*`, or `vault://namespace/name` only
- [ ] User-facing strings are **English-first** (or I added matching `zh` / `*.zh-CN.md` where required)
- [ ] Every behavior change includes its documentation update, synchronized English/Chinese siblings, and appropriate regression checks
- [ ] Non-obvious code behavior has current comments, as required by `AGENTS.md`
- [ ] Agent package changes increment canonical `VERSION` before building a new release; published versions are never reused

## DataAsset PRs only

- [ ] New examples live under `dataasset/examples/` unless explicitly part of the offline demo registry
- [ ] Synthetic IPs (e.g. `203.0.113.x`, `10.0.0.0/8` lab ranges) and fake hostnames only
- [ ] `.venv/bin/python src/secweaver.py validate` passes with 0 errors

## Screenshots / sample output (optional)

<!-- CLI output, validate summary, or UI screenshot for UX changes -->
