# Repository Scripts

Repository-level maintenance programs live here instead of the project root.

| Script | Purpose |
|---|---|
| `release_scan.py` | Scan for private content, secrets, placeholders, and Community version drift |
| `check_docs_links.py` | Validate local Markdown paths and same-file/cross-file anchors without network access |
| `ai_host_setup.py` | Generate non-destructive local host adapters that route to `src/skills` |
| `run_ai_showcase.py` | Run and verify one credential-free offline AI Showcase case |
<!-- private-delivery: these are policy examples, not executable commands -->
| `check_public_doc_commands.py` | Reject `src/es-operator/*` and `src/server/*` commands unless marked as private delivery |

Use the stable Make targets when possible:

```bash
make release-scan
make docs-check
make ai-setup HOST=all
make ai-setup HOST=codex
make ai-showcase
```

The release scan requires the latest `CHANGELOG.md` release, `pyproject.toml`,
CLI `--version` output, and source SBOM root component to use the same Community
version. The Agent keeps an independent version in `src/tools/secweaver-agent/VERSION`.

The Project `wis-log` and Logstore `gateway_plugin_log` are intentionally public
onboarding identifiers and are allowed in documentation, tests, and public asset
configuration. Resource names do not confer access; the Proxy still requires
authorized query credentials. Files containing these names remain subject to
secret, private-path, and other private-content checks. Verify this policy with
`python3 -m unittest discover -s tests -p test_release_scan.py` and `make release-scan`.

Direct invocation remains available:

```bash
python3 src/scripts/release_scan.py --json
python3 src/scripts/check_docs_links.py
python3 src/scripts/check_public_doc_commands.py
python3 src/scripts/ai_host_setup.py --host all
python3 src/scripts/ai_host_setup.py --host codex
python3 src/scripts/run_ai_showcase.py webshell-to-ssh-lateral
```

The documentation link check recognizes generated GitHub-style heading IDs,
duplicate-heading suffixes such as `-1`, and explicit `<a id="...">` anchors.
Use an explicit anchor when a public link must remain stable after a heading is renamed.
