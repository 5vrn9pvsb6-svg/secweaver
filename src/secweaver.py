#!/usr/bin/env python3
"""SecWeaver local CLI.

This CLI intentionally wraps existing repository scripts instead of reimplementing
skill logic. It provides a stable, user-friendly entry point for open-source users.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = Path(__file__).resolve().parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
DATA_ACCESS_ROOT = SRC_ROOT / "skills" / "_shared" / "data-access"
if str(DATA_ACCESS_ROOT) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_ROOT))

from dataasset.plugin_contract import (  # noqa: E402
    API_VERSION as PLUGIN_API_VERSION,
    DEFAULT_TIMEOUT_SECONDS,
    EVENT_KEYS as PLUGIN_EVENT_KEYS,
    PluginContractError,
    decode_response,
    manifest_errors,
    positive_timeout,
    resolve_entrypoint,
    resolve_python,
)
from dataasset_paths import DATAASSET_ROOT  # noqa: E402
from connector_catalog import connector_catalog  # noqa: E402
from connector_registry import CONNECTOR_TYPE_RE, PLUGIN_ROOT  # noqa: E402
from report_markdown import (  # noqa: E402
    DEMO_JSON_NAMES,
    render_investigation_bundle,
    render_markdown_file,
    write_demo_markdown_reports,
    write_markdown_file,
)

from secweaver_cli.asset_commands import (  # noqa: E402
    ASSET_INIT_CONFIG_KEYS,
    build_asset_init_plan,
    cmd_asset_apply,
    cmd_asset_diff,
    cmd_asset_init,
    cmd_asset_promote,
    cmd_asset_rollback,
    configured_output_dir,
    deep_merge,
    expand_asset_apply_config,
    render_asset_plan,
)

SCRIPT_PATHS = {
    "validate": REPO_ROOT / "src/dataasset/validate.py",
    "test_connector": REPO_ROOT / "src/dataasset/test_connector.py",
    "promote": REPO_ROOT / "src/dataasset/promote_after_connectivity.py",
    "format_discovery": REPO_ROOT / "src/skills/log-format-discovery/scripts/discover.py",
}

ONBOARDING_ROOT = DATAASSET_ROOT / "onboarding"
SKILL_MANIFEST_PATH = REPO_ROOT / "src" / "skills" / "manifest.json"

PLUGIN_FETCH_TEMPLATE = '''#!/usr/bin/env python3
"""Stdio-json connector plugin scaffold.

Input on stdin:
  {"connector": {...}, "credentials": {...}, "query": "...", "params": {...}}

Output on stdout:
  {"events": [...], "meta": {...}}
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from typing import Any


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def main() -> int:
    request = json.load(sys.stdin)
    connector = request.get("connector") if isinstance(request, dict) else {}
    params = request.get("params") if isinstance(request, dict) else {}
    credentials = request.get("credentials") if isinstance(request, dict) else {}
    query = str(request.get("query") or "")
    if not isinstance(connector, dict):
        connector = {}
    if not isinstance(params, dict):
        params = {}
    if not isinstance(credentials, dict):
        credentials = {}

    limit = max(1, min(_int_value(params.get("limit"), 10), 100))
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    # Replace this block with vendor SDK/HTTP calls. Keep secrets in credentials
    # or process environment; do not commit real tokens into dataasset config.
    events = [
        {
            "timestamp": (now - dt.timedelta(minutes=index)).isoformat().replace("+00:00", "Z"),
            "connector_id": connector.get("connector_id"),
            "message": "replace this sample event with vendor results",
            "query": query,
        }
        for index in range(limit)
    ]

    print(
        json.dumps(
            {
                "events": events,
                "meta": {
                    "mode": "plugin",
                    "rows_returned": len(events),
                },
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def repo_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def unique_values(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return result


@lru_cache(maxsize=1)
def skill_entries() -> tuple[dict[str, Any], ...]:
    if not SKILL_MANIFEST_PATH.is_file():
        raise SystemExit(f"skill manifest not found: {SKILL_MANIFEST_PATH}")
    try:
        manifest = json.loads(SKILL_MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid skill manifest JSON: {SKILL_MANIFEST_PATH}: {exc}") from exc

    entries: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for raw in manifest.get("skills", []):
        if raw.get("enabled", True) is False:
            continue
        key = str(raw.get("key", "")).strip()
        name = str(raw.get("name", key)).strip()
        script = str(raw.get("script", "")).strip()
        cli_visible = bool(raw.get("cli_visible", False))
        if not key or not name:
            raise SystemExit("each skill manifest entry requires key and name")
        if cli_visible and not script:
            raise SystemExit(f"CLI-visible skill {key} requires a script")
        if key in seen_keys:
            raise SystemExit(f"duplicate skill key in manifest: {key}")
        seen_keys.add(key)

        demo = raw.get("demo") or {}
        aliases = unique_values([key, name, *[str(alias) for alias in raw.get("aliases", [])]])
        entry = dict(raw)
        entry["key"] = key
        entry["name"] = name
        entry["aliases"] = aliases
        entry["cli_visible"] = cli_visible
        entry["script_path"] = repo_path(script) if script else None
        if raw.get("docs"):
            entry["docs_path"] = repo_path(str(raw["docs"]))
        if demo.get("input"):
            entry["demo_input_path"] = repo_path(str(demo["input"]))
        if demo.get("output"):
            entry["demo_output_path"] = repo_path(str(demo["output"]))
        entries.append(entry)

    if not entries:
        raise SystemExit(f"skill manifest contains no enabled skills: {SKILL_MANIFEST_PATH}")
    return tuple(entries)


@lru_cache(maxsize=1)
def skill_by_key() -> dict[str, dict[str, Any]]:
    return {entry["key"]: entry for entry in skill_entries()}


@lru_cache(maxsize=1)
def skill_aliases() -> dict[str, str]:
    aliases: dict[str, str] = {}
    for entry in skill_entries():
        for alias in entry["aliases"]:
            if alias in aliases and aliases[alias] != entry["key"]:
                raise SystemExit(f"duplicate skill alias in manifest: {alias}")
            aliases[alias] = entry["key"]
    return aliases


@lru_cache(maxsize=1)
def demo_inputs() -> dict[str, Path]:
    return {
        entry["key"]: entry["demo_input_path"]
        for entry in skill_entries()
        if entry.get("demo_input_path") is not None
    }


@lru_cache(maxsize=1)
def demo_reports() -> dict[str, Path]:
    return {
        entry["key"]: entry["demo_output_path"]
        for entry in skill_entries()
        if entry.get("demo_output_path") is not None
    }


def run_script(script: Path, args: list[str]) -> int:
    if not script.is_file():
        print(f"script not found: {script}", file=sys.stderr)
        return 1
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.call([sys.executable, str(script), *args], cwd=REPO_ROOT, env=env)


def trim_subprocess_output(stdout: str, stderr: str, limit: int = 1200) -> str:
    text = ((stderr or "") + ("\n" if stdout and stderr else "") + (stdout or "")).strip()
    if not text:
        return "no output"
    return text[:limit] + ("\n..." if len(text) > limit else "")


def run_script_capture(script: Path, args: list[str], timeout: int = 90) -> subprocess.CompletedProcess[str]:
    if not script.is_file():
        return subprocess.CompletedProcess([str(script), *args], 1, "", f"script not found: {script}\n")
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def add_common_io_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-i", "--input", help="Input JSON file. If omitted, the wrapped skill may read stdin or require bundle params.")
    parser.add_argument("-o", "--output", help="Output JSON file. If omitted, prints to stdout.")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Additional arguments passed to the underlying skill script after '--'.")


def passthrough_args(args: list[str]) -> list[str]:
    """Remove the wrapper separator even after options captured by REMAINDER.

    argparse stops parsing wrapper flags once the Skill name is consumed, so
    flags such as ``-i`` may precede ``--`` inside this list. Keep their order
    while removing only the first separator before invoking the child script.
    """
    if "--" in args:
        index = args.index("--")
        return [*args[:index], *args[index + 1 :]]
    return args


def extract_sample_lines(fetch_output: str) -> str:
    text = (fetch_output or "").strip()
    if not text:
        return ""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(data, list):
        return "\n".join(json.dumps(item, ensure_ascii=False) for item in data[:100])
    if isinstance(data, dict):
        for key in ("events", "items", "rows", "data", "records", "logs"):
            value = data.get(key)
            if isinstance(value, list):
                return "\n".join(json.dumps(item, ensure_ascii=False) for item in value[:100])
        return json.dumps(data, ensure_ascii=False)
    return str(data)


def load_asset_metadata(asset_id: str) -> dict:
    path = DATAASSET_ROOT / "assets" / f"{asset_id}.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def default_smoke_params(asset_id: str, params: str | None) -> str:
    if params and params != "{}":
        return params
    asset = load_asset_metadata(asset_id)
    asset_type = asset.get("asset_type")
    now = datetime.now(timezone.utc)
    defaults: dict[str, object] = {
        "limit": 20,
        "max_lines": 20,
        "time_start": (now - timedelta(minutes=30)).isoformat(),
        "time_end": now.isoformat(),
    }
    if asset_type == "ssh_auth":
        defaults["grep_pattern"] = "sshd"
    elif asset_type in {"linux_syslog", "windows_event_log"}:
        defaults["grep_pattern"] = ".*"
    elif asset_type in {"web_access_log", "waf_alert", "firewall_log", "dns_log", "network_traffic_audit"}:
        defaults["src_ip"] = "0.0.0.0"
        defaults["client_ip"] = "0.0.0.0"
    elif asset_type in {"asset_inventory", "db_audit"}:
        defaults["host"] = "localhost"
    return json.dumps(defaults, ensure_ascii=False)



def cmd_validate(args: argparse.Namespace) -> int:
    script_args: list[str] = []
    if args.strict:
        script_args.append("--strict")
    if args.json:
        script_args.append("--json")
    if args.diagnose:
        script_args.append("--diagnose")
    if args.sync_catalog:
        script_args.append("--sync-catalog")
    if args.only_active:
        script_args.append("--only-active")
    if args.runtime_ready:
        script_args.append("--runtime-ready")
    for bundle_id in args.bundle_ids or []:
        script_args.extend(["--bundle", bundle_id])
    return run_script(SCRIPT_PATHS["validate"], script_args)


def cmd_catalog(args: argparse.Namespace) -> int:
    if args.action == "sync":
        return run_script(SCRIPT_PATHS["validate"], ["--sync-catalog"])
    return run_script(SCRIPT_PATHS["validate"], [])


def cmd_dataasset_migrate(args: argparse.Namespace) -> int:
    """Preview or write connector-catalog format migration for one asset root."""
    from dataasset.config_migration import migrate_root

    result = migrate_root(Path(args.root), write=args.write)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"DataAsset migration ({result['mode']}): {result['root']}")
        for catalog in result["catalogs"]:
            print(f"  {catalog['path']}")
            for change in catalog["changes"]:
                print(f"    - {change}")
            for error in catalog["errors"]:
                print(f"    ERROR: {error}")
        if result["legacy_profile_retained"]:
            print("  legacy onboarding profile retained for rollback")
        if args.write:
            print(f"  wrote {len(result['written'])} catalog(s)")
    return 0 if result["ok"] else 1


def filtered_connector_catalog(source: str | None = None) -> list[dict[str, Any]]:
    records = connector_catalog()
    if source:
        records = [record for record in records if record.get("source") == source]
    return records


def print_connector_catalog_table(records: list[dict[str, Any]]) -> None:
    headers = ("connector_type", "source", "runtime", "query_key", "dependency")
    print("\t".join(headers))
    for record in records:
        print(
            "\t".join(
                [
                    str(record.get("connector_type") or ""),
                    str(record.get("source") or ""),
                    str(record.get("runtime") or ""),
                    str(record.get("query_key") or ""),
                    str(record.get("dependency_hint") or ""),
                ]
            )
        )


def validate_connector_identifier(value: str, *, label: str) -> str:
    normalized = str(value or "").strip()
    if not CONNECTOR_TYPE_RE.fullmatch(normalized):
        raise SystemExit(f"{label} must match {CONNECTOR_TYPE_RE.pattern}: {value!r}")
    return normalized


def render_plugin_readme(connector_type: str, query_key: str) -> str:
    return f"""# {connector_type} connector plugin

This scaffold registers `{connector_type}` without modifying SecWeaver core
Python code. Put vendor SDK dependencies in this plugin directory or in a
plugin-local virtual environment.

## Files

- `plugin.json`: connector manifest discovered by SecWeaver.
- `fetch.py`: stdio-json executor. Replace the sample event block with vendor
  SDK/HTTP calls.
- `requirements.txt`: optional plugin dependencies.

## Preview

```bash
python3 src/secweaver.py connector catalog --json
python3 src/secweaver.py connector plugin validate src/dataasset/plugins/connectors/{connector_type}
python3 src/dataasset/plugins/connectors/{connector_type}/fetch.py < sample-request.json
```

Use the connector in onboarding config:

```json
{{
  "name": "demo-{connector_type}",
  "connector_type": "{connector_type}",
  "asset_type": "waf_alert",
  "template": {{
    "{query_key}": "src_ip={{src_ip}} limit {{limit}}"
  }}
}}
```
"""


def scaffold_connector_plugin(args: argparse.Namespace) -> dict[str, Any]:
    """Create a plugin whose manifest also owns its onboarding behavior."""
    connector_type = validate_connector_identifier(args.connector_type, label="connector_type")
    query_key = validate_connector_identifier(args.query_key or f"{connector_type}_query", label="query_key")
    output_root = repo_path(args.output_dir) if args.output_dir else PLUGIN_ROOT
    plugin_dir = output_root / connector_type
    if plugin_dir.exists() and not args.force:
        raise SystemExit(f"refuse to overwrite existing plugin directory: {format_path(plugin_dir)} (use --force)")

    plugin_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": args.display_name or connector_type.replace("_", " ").title(),
        "api_version": PLUGIN_API_VERSION,
        "connector_type": connector_type,
        "query_key": query_key,
        "runtime": "plugin",
        "protocol": "stdio-json",
        "entrypoint": "fetch.py",
        "timeout_sec": args.timeout_sec,
        "description": args.description or "Local connector plugin scaffold.",
        "onboarding_template": "external_generic",
        "onboarding_profile": {
            "label": args.display_name or connector_type.replace("_", " ").title(),
            "fields": ["endpoint", "base_url", "sample_file", "sample_dir"],
            "required": [],
            "defaults": {"sample_file": "examples/log-format-discovery/waf-jsonl.sample"},
            "default_asset_type": "waf_alert",
            "template_params": ["src_ip", "time_start", "time_end", "limit"],
            "template_defaults": {"limit": 1000},
            "default_query": "src_ip={src_ip} limit {limit}",
            "hint": "Configure a local sample or implement vendor access in this plugin.",
        },
    }
    files = {
        plugin_dir / "plugin.json": json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        plugin_dir / "fetch.py": PLUGIN_FETCH_TEMPLATE,
        plugin_dir / "requirements.txt": "# Add plugin-only vendor SDKs here.\n",
        plugin_dir / "README.md": render_plugin_readme(connector_type, query_key),
    }
    for path, content in files.items():
        if path.exists() and not args.force:
            raise SystemExit(f"refuse to overwrite existing file: {format_path(path)} (use --force)")
        path.write_text(content, encoding="utf-8")
    fetch_path = plugin_dir / "fetch.py"
    fetch_path.chmod(fetch_path.stat().st_mode | 0o111)
    return {
        "ok": True,
        "connector_type": connector_type,
        "query_key": query_key,
        "plugin_dir": format_path(plugin_dir),
        "files": [format_path(path) for path in files],
        "next": [
            "python3 src/secweaver.py connector catalog --json",
            f"python3 src/secweaver.py asset init --connector-type {connector_type} --asset-type waf_alert --dry-run",
        ],
    }


def _plugin_issue(severity: str, path: Path, message: str) -> dict[str, str]:
    return {"severity": severity, "path": format_path(path), "message": message}


def plugin_validation_targets(target: str | None) -> list[Path]:
    if target:
        path = repo_path(target)
        if not path.exists():
            candidate = PLUGIN_ROOT / target
            if candidate.exists():
                path = candidate
        if path.is_file():
            path = path.parent
        return [path]
    if not PLUGIN_ROOT.is_dir():
        return []
    return sorted(path for path in PLUGIN_ROOT.iterdir() if path.is_dir())


def resolve_plugin_entrypoint(plugin_dir: Path, manifest: dict[str, Any]) -> tuple[Path | None, list[dict[str, str]]]:
    """Adapt shared path errors to CLI diagnostics without executing the plugin."""
    try:
        return resolve_entrypoint(plugin_dir, manifest), []
    except PluginContractError as exc:
        return None, [_plugin_issue("error", plugin_dir / "plugin.json", str(exc))]


def resolve_plugin_python(plugin_dir: Path, manifest: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    """Use the same trusted interpreter resolution as runtime execution."""
    try:
        return resolve_python(plugin_dir, manifest), []
    except PluginContractError as exc:
        return "", [_plugin_issue("error", plugin_dir / "plugin.json", str(exc))]


def validate_plugin_manifest(plugin_dir: Path, manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Present all canonical manifest errors instead of maintaining CLI-only rules."""
    return [_plugin_issue("error", plugin_dir / "plugin.json", message) for message in manifest_errors(manifest)]


def run_plugin_smoke(plugin_dir: Path, manifest: dict[str, Any], args: argparse.Namespace) -> list[dict[str, str]]:
    """Probe with no credentials; enforce the runtime response and timeout contract."""
    issues: list[dict[str, str]] = []
    entrypoint, entry_issues = resolve_plugin_entrypoint(plugin_dir, manifest)
    issues.extend(entry_issues)
    python_bin, python_issues = resolve_plugin_python(plugin_dir, manifest)
    issues.extend(python_issues)
    if issues or entrypoint is None:
        return issues
    try:
        params = json.loads(args.sample_params)
    except json.JSONDecodeError as exc:
        return [_plugin_issue("error", plugin_dir / "plugin.json", f"--sample-params must be JSON: {exc}")]
    if not isinstance(params, dict):
        return [_plugin_issue("error", plugin_dir / "plugin.json", "--sample-params must be a JSON object")]
    connector_type = str(manifest.get("connector_type") or "")
    payload = {
        "connector": {
            "connector_id": f"conn-{connector_type}-contract",
            "connector_type": connector_type,
            "config": {},
        },
        "credentials": {},
        "query": args.sample_query or f"{manifest.get('query_key')}=contract-smoke",
        "params": params,
    }
    try:
        timeout = positive_timeout(args.timeout_sec if args.timeout_sec is not None else manifest.get("timeout_sec", DEFAULT_TIMEOUT_SECONDS))
    except PluginContractError as exc:
        return [_plugin_issue("error", plugin_dir / "plugin.json", str(exc))]
    try:
        result = subprocess.run(
            [python_bin, str(entrypoint)],
            input=json.dumps(payload, ensure_ascii=False),
            cwd=plugin_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [_plugin_issue("error", entrypoint, f"smoke execution timed out after {timeout}s")]
    except OSError:
        return [_plugin_issue("error", entrypoint, "smoke execution could not start")]
    if result.returncode != 0:
        detail = trim_subprocess_output(result.stdout, result.stderr)
        return [_plugin_issue("error", entrypoint, f"smoke execution failed: {detail}")]
    try:
        decode_response(result.stdout or "")
    except PluginContractError as exc:
        return [_plugin_issue("error", entrypoint, str(exc))]
    return []


def validate_connector_plugins(args: argparse.Namespace) -> dict[str, Any]:
    """Validate raw manifests; --no-exec still checks containment and interpreter paths."""
    results: list[dict[str, Any]] = []
    for plugin_dir in plugin_validation_targets(args.target):
        issues: list[dict[str, str]] = []
        manifest_path = plugin_dir / "plugin.json"
        manifest: Any = None
        manifest_loaded = False
        if not plugin_dir.is_dir():
            issues.append(_plugin_issue("error", plugin_dir, "plugin directory does not exist"))
        elif not manifest_path.is_file():
            issues.append(_plugin_issue("error", manifest_path, "plugin.json does not exist"))
        else:
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest_loaded = True
            except json.JSONDecodeError as exc:
                issues.append(_plugin_issue("error", manifest_path, f"invalid plugin.json: {exc}"))
            except (OSError, UnicodeError):
                issues.append(_plugin_issue("error", manifest_path, "plugin.json could not be read as UTF-8"))
        # Empty objects and non-object JSON must reach the same contract checker
        # as runtime discovery; truthiness would incorrectly accept {} or null.
        if manifest_loaded:
            issues.extend(validate_plugin_manifest(plugin_dir, manifest))
            if not issues:
                if args.no_exec:
                    _, path_issues = resolve_plugin_entrypoint(plugin_dir, manifest)
                    _, python_issues = resolve_plugin_python(plugin_dir, manifest)
                    issues.extend(path_issues + python_issues)
                else:
                    issues.extend(run_plugin_smoke(plugin_dir, manifest, args))
        errors = [issue for issue in issues if issue["severity"] == "error"]
        results.append(
            {
                "plugin_dir": format_path(plugin_dir),
                "connector_type": manifest.get("connector_type", "") if isinstance(manifest, dict) else "",
                "ok": not errors,
                "issues": issues,
            }
        )
    errors = [issue for result in results for issue in result["issues"] if issue["severity"] == "error"]
    return {
        "ok": not errors,
        "summary": {
            "plugin_count": len(results),
            "error_count": len(errors),
            "warning_count": sum(1 for result in results for issue in result["issues"] if issue["severity"] == "warning"),
        },
        "plugins": results,
    }


def print_plugin_validation(payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    print(
        f"plugin-validate: {summary['plugin_count']} plugin(s), "
        f"{summary['error_count']} error(s), {summary['warning_count']} warning(s)"
    )
    for result in payload["plugins"]:
        status = "OK" if result["ok"] else "FAILED"
        print(f"- {status} {result['plugin_dir']} {result.get('connector_type') or ''}".rstrip())
        for issue in result["issues"]:
            print(f"  {issue['severity'].upper()}: {issue['path']}: {issue['message']}")


def cmd_connector(args: argparse.Namespace) -> int:
    if args.action == "catalog":
        records = filtered_connector_catalog(args.source)
        if args.json:
            print(json.dumps({"ok": True, "connectors": records}, ensure_ascii=False, indent=2))
        else:
            print_connector_catalog_table(records)
        return 0

    if args.action == "plugin" and args.plugin_action == "init":
        print(json.dumps(scaffold_connector_plugin(args), ensure_ascii=False, indent=2))
        return 0
    if args.action == "plugin" and args.plugin_action == "validate":
        payload = validate_connector_plugins(args)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print_plugin_validation(payload)
        return 0 if payload["ok"] else 1

    if args.action == "test":
        script_args = [args.target_id]
        if args.by_asset:
            script_args.append("--by-asset")
        if args.plan:
            script_args.append("--plan")
        if args.connector:
            script_args.extend(["--connector", args.connector])
        if args.params:
            script_args.extend(["--params", args.params])
        if args.dry_run:
            script_args.append("--dry-run")
        return run_script(SCRIPT_PATHS["test_connector"], script_args)

    raise SystemExit(f"unknown connector action: {args.action}")


def cmd_asset(args: argparse.Namespace) -> int:
    if args.action == "test":
        script_args = [args.asset_id, "--by-asset"]
        if args.plan:
            script_args.append("--plan")
        if args.connector:
            script_args.extend(["--connector", args.connector])
        if args.params:
            script_args.extend(["--params", default_smoke_params(args.asset_id, args.params)])
        if args.dry_run:
            script_args.append("--dry-run")
        return run_script(SCRIPT_PATHS["test_connector"], script_args)

    if args.action == "discover-format":
        discover_args = ["--asset-id", args.asset_id, "--pretty", "--preview-normalize", "--allow-any-status"]
        if args.parser_id:
            discover_args.extend(["--parser-id", args.parser_id])
        if args.emit_parser:
            discover_args.extend(["--emit-parser", args.emit_parser])
        if args.parser_description:
            discover_args.extend(["--parser-description", args.parser_description])
        if args.force_parser:
            discover_args.append("--force-parser")
        if args.input:
            discover_args.extend(["--input", args.input])
        elif args.text:
            discover_args.extend(["--text", args.text])
        else:
            with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
                sample_path = Path(handle.name)
            try:
                fetch = run_script_capture(
                    SCRIPT_PATHS["test_connector"],
                    [args.asset_id, "--by-asset", "--params", default_smoke_params(args.asset_id, args.params)],
                    timeout=90,
                )
                sample_path.write_text(extract_sample_lines(fetch.stdout or ""), encoding="utf-8")
                if fetch.returncode != 0:
                    if fetch.stdout:
                        print(fetch.stdout, end="")
                    if fetch.stderr:
                        print(fetch.stderr, end="", file=sys.stderr)
                    return fetch.returncode
                discover_args.extend(["--input", str(sample_path)])
                return run_script(SCRIPT_PATHS["format_discovery"], discover_args)
            finally:
                try:
                    sample_path.unlink(missing_ok=True)
                except OSError:
                    pass
        return run_script(SCRIPT_PATHS["format_discovery"], discover_args)

    raise SystemExit(f"unknown asset action: {args.action}")


def resolve_skill(name: str) -> str:
    key = skill_aliases().get(name)
    if not key:
        available = ", ".join(sorted(skill_aliases()))
        raise SystemExit(f"unknown skill: {name}\navailable skills: {available}")
    return key


def cmd_skill(args: argparse.Namespace) -> int:
    skill = resolve_skill(args.skill)
    entry = skill_by_key()[skill]
    if not entry.get("cli_visible") or not entry.get("script_path"):
        raise SystemExit(
            f"skill {entry['name']} is a non-CLI {entry.get('kind', 'workflow')}; "
            "read its SKILL.md and use the documented runner"
        )
    script_args: list[str] = []
    if args.input:
        script_args.extend(["-i", args.input])
    if args.output:
        script_args.extend(["-o", args.output])
    script_args.extend(passthrough_args(args.args))
    return run_script(entry["script_path"], script_args)


def extract_output_arg(output_arg: str | None, extra_args: list[str]) -> tuple[str | None, list[str]]:
    remaining: list[str] = []
    index = 0
    while index < len(extra_args):
        arg = extra_args[index]
        if arg in ("-o", "--output"):
            if index + 1 >= len(extra_args):
                raise SystemExit(f"{arg} requires a value")
            output_arg = extra_args[index + 1]
            index += 2
            continue
        if arg.startswith("--output="):
            output_arg = arg.split("=", 1)[1]
            index += 1
            continue
        remaining.append(arg)
        index += 1
    return output_arg, remaining


def format_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def run_single_demo(skill: str, output: Path | None, extra_args: list[str]) -> int:
    input_path = demo_inputs().get(skill)
    if not input_path or not input_path.is_file():
        print(f"demo input not found for {skill}: {input_path}", file=sys.stderr)
        return 1
    entry = skill_by_key()[skill]
    script_args = ["-i", str(input_path)]
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        script_args.extend(["-o", str(output)])
    if skill == "traceability" and "--notify" not in extra_args and "--no-notify" not in extra_args:
        script_args.append("--no-notify")
    script_args.extend(extra_args)
    return run_script(entry["script_path"], script_args)


def demo_output_path(skill: str, output_arg: str | None, *, all_demos: bool = False) -> Path | None:
    """Resolve demo output using the command's directory intent before suffix hints.

    ``demo all`` always writes multiple files, so dots in directory names must
    not turn the path into a filename. For a single demo, an existing directory
    takes precedence over the legacy suffix-based file/directory convention.
    """
    if not output_arg:
        return demo_reports()[skill]
    output_path = Path(output_arg)
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path
    if all_demos:
        if output_path.exists() and not output_path.is_dir():
            raise SystemExit("demo all expects -o/--output to be a directory, not a file")
        return output_path / demo_reports()[skill].name
    if output_path.is_dir():
        return output_path / demo_reports()[skill].name
    if output_path.suffix:
        return output_path
    return output_path / demo_reports()[skill].name


def cmd_demo(args: argparse.Namespace) -> int:
    output_arg, extra_args = extract_output_arg(args.output, passthrough_args(args.args))
    if args.demo == "all":
        if extra_args:
            print("warning: extra args are ignored for demo all", file=sys.stderr)
        print("Running all SecWeaver demos...")
        for skill in demo_reports():
            output_path = demo_output_path(skill, output_arg, all_demos=True)
            print(f"- {skill} -> {format_path(output_path)}")
            exit_code = run_single_demo(skill, output_path, [])
            if exit_code != 0:
                return exit_code
        print("Done. See examples/reports/README.md for the sample report.")
        return 0

    skill = resolve_skill(args.demo)
    output_path = None
    if output_arg:
        output_path = demo_output_path(skill, output_arg)
    return run_single_demo(skill, output_path, extra_args)


def resolve_report_path(path: str) -> Path:
    report_path = Path(path)
    if not report_path.is_absolute():
        report_path = REPO_ROOT / report_path
    return report_path


def cmd_report(args: argparse.Namespace) -> int:
    if args.action != "markdown":
        raise SystemExit(f"unknown report action: {args.action}")

    if args.investigation:
        input_dir = resolve_report_path(args.investigation)
        if not input_dir.is_dir():
            print(f"investigation directory not found: {input_dir}", file=sys.stderr)
            return 1
        content = render_investigation_bundle(input_dir)
        if args.output:
            output_path = resolve_report_path(args.output)
        else:
            output_path = input_dir / "investigation-report.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(format_path(output_path))
        return 0

    if args.demo:
        if args.demo == "all":
            input_dir = resolve_report_path(args.input_dir) if args.input_dir else REPO_ROOT / "examples/reports"
            outputs = write_demo_markdown_reports(input_dir)
            if not outputs:
                print(f"no demo JSON reports found in {input_dir}", file=sys.stderr)
                return 1
            for output_path in outputs:
                print(format_path(output_path))
            if args.bundle:
                bundle_path = resolve_report_path(args.output) if args.output else input_dir / "investigation-report.md"
                bundle_path.write_text(render_investigation_bundle(input_dir), encoding="utf-8")
                print(format_path(bundle_path))
            return 0
        demo_key = resolve_skill(args.demo)
        json_name = DEMO_JSON_NAMES.get(demo_key)
        if not json_name:
            print(f"unsupported demo for markdown report: {args.demo}", file=sys.stderr)
            return 1
        input_path = resolve_report_path(args.input_dir) / json_name if args.input_dir else demo_reports()[demo_key]
        if not input_path.is_file():
            print(f"demo JSON not found: {input_path}", file=sys.stderr)
            return 1
        output_path = resolve_report_path(args.output) if args.output else None
        written = write_markdown_file(input_path, output_path)
        print(format_path(written))
        return 0

    if not args.input:
        print("report markdown requires -i/--input, --demo, or --investigation", file=sys.stderr)
        return 1

    input_path = resolve_report_path(args.input)
    if not input_path.is_file():
        print(f"input file not found: {input_path}", file=sys.stderr)
        return 1

    content = render_markdown_file(input_path)
    if args.output:
        output_path = resolve_report_path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(format_path(output_path))
        return 0

    print(content, end="")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    print("Available demos:")
    print("  - all")
    print("    output: examples/reports/*.json")
    print("Available skills:")
    for entry in skill_entries():
        demo = demo_inputs().get(entry["key"])
        print(f"  - {entry['name']}")
        if demo:
            print(f"    demo: {demo.relative_to(REPO_ROOT).as_posix()}")
        if entry.get("docs_path"):
            print(f"    docs: {entry['docs_path'].relative_to(REPO_ROOT).as_posix()}")
    print("Asset operations:")
    print("  - asset apply -f dataasset/onboarding/examples/data-sources.sample.json")
    print("  - asset diff -f dataasset/onboarding/examples/data-sources.sample.json")
    print("  - asset init --connector-type <type> --asset-type <type>")
    print("  - asset promote --asset <asset_id> --params <json> [--dry-run]")
    print("  - asset rollback -f dataasset/onboarding/examples/data-sources.sample.json --dry-run")
    print("  - asset test <asset_id>")
    print("  - asset discover-format <asset_id> [-i sample]")
    print("    sample: examples/log-format-discovery/waf-jsonl.sample")
    print("Connector operations:")
    print("  - connector catalog [--json]")
    print("  - connector plugin init <connector_type> [--query-key <key>]")
    print("  - connector plugin validate [plugin_dir] [--json]")
    print("  - connector test <asset_or_connector_id> [--by-asset] [--dry-run]")
    print("DataAsset maintenance:")
    print("  - dataasset migrate --root <dataasset_root> [--write] [--json]")
    print("Report operations:")
    print("  - report markdown -i <result.json> [-o <report.md>]")
    print("  - report markdown --demo all [--bundle]")
    print("  - report markdown --investigation examples/reports")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secweaver",
        description="SecWeaver local CLI for dataasset validation and basic skill demos.",
    )
    parser.add_argument("--version", action="version", version="SecWeaver CLI 0.3.21")

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate dataasset registry.")
    validate.add_argument("--strict", action="store_true", help="Treat warnings as blocking issues if supported by validator.")
    validate.add_argument("--json", action="store_true", help="Print validator report as JSON.")
    validate.add_argument("--diagnose", action="store_true", help="Print operator-facing config diagnostics.")
    validate.add_argument("--sync-catalog", action="store_true", help="Update dataasset/catalog.json after validation.")
    validate.add_argument("--only-active", action="store_true", help="Only run active-object release gates.")
    validate.add_argument(
        "--runtime-ready",
        action="store_true",
        help="Check static Bundle execution readiness without decrypting credentials or contacting a backend.",
    )
    validate.add_argument("--bundle", action="append", dest="bundle_ids", help="Check one Bundle; repeatable and requires --runtime-ready.")
    validate.set_defaults(func=cmd_validate)

    catalog = subparsers.add_parser("catalog", help="Catalog helpers.")
    catalog_sub = catalog.add_subparsers(dest="action", required=True)
    catalog_sync = catalog_sub.add_parser("sync", help="Sync dataasset/catalog.json.")
    catalog_sync.set_defaults(func=cmd_catalog)

    dataasset_cmd = subparsers.add_parser("dataasset", help="DataAsset registry maintenance.")
    dataasset_sub = dataasset_cmd.add_subparsers(dest="action", required=True)
    dataasset_migrate = dataasset_sub.add_parser(
        "migrate",
        help="Migrate connector catalogs to the current format contract.",
    )
    dataasset_migrate.add_argument(
        "--root",
        default=str(DATAASSET_ROOT),
        help="DataAsset root. Defaults to DATAASSET_ROOT or ./dataasset.",
    )
    dataasset_migrate.add_argument(
        "--write",
        action="store_true",
        help="Write migrated catalogs atomically. Without this flag, only preview changes.",
    )
    dataasset_migrate.add_argument("--json", action="store_true", help="Print structured JSON output.")
    dataasset_migrate.set_defaults(func=cmd_dataasset_migrate)

    connector = subparsers.add_parser("connector", help="Connector capability and extension helpers.")
    connector_sub = connector.add_subparsers(dest="action", required=True)
    connector_catalog_cmd = connector_sub.add_parser("catalog", help="List connector capability catalog.")
    connector_catalog_cmd.add_argument("--json", action="store_true", help="Print catalog as JSON.")
    connector_catalog_cmd.add_argument(
        "--source",
        choices=["built_in", "external_config", "plugin"],
        help="Filter by connector source.",
    )
    connector_catalog_cmd.set_defaults(func=cmd_connector)
    connector_plugin = connector_sub.add_parser("plugin", help="Connector plugin helpers.")
    connector_plugin_sub = connector_plugin.add_subparsers(dest="plugin_action", required=True)
    connector_plugin_init = connector_plugin_sub.add_parser("init", help="Scaffold a local connector plugin.")
    connector_plugin_init.add_argument("connector_type", help="New plugin connector_type, e.g. vendor_logs.")
    connector_plugin_init.add_argument("--query-key", help="Template query key. Defaults to <connector_type>_query.")
    connector_plugin_init.add_argument("--display-name", help="Human-readable plugin name.")
    connector_plugin_init.add_argument("--description", help="Manifest description.")
    connector_plugin_init.add_argument("--timeout-sec", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="Plugin execution timeout.")
    connector_plugin_init.add_argument("--output-dir", help="Plugin root. Defaults to src/dataasset/plugins/connectors or SECWEAVER_PLUGIN_ROOT.")
    connector_plugin_init.add_argument("--force", action="store_true", help="Overwrite existing scaffold files.")
    connector_plugin_init.set_defaults(func=cmd_connector)
    connector_plugin_validate = connector_plugin_sub.add_parser("validate", help="Validate connector plugin manifest and stdio-json contract.")
    connector_plugin_validate.add_argument("target", nargs="?", help="Plugin directory or name. Defaults to all plugins under the configured plugin root.")
    connector_plugin_validate.add_argument("--json", action="store_true", help="Print structured JSON output.")
    connector_plugin_validate.add_argument("--no-exec", action="store_true", help="Only validate manifest and files; skip smoke execution.")
    connector_plugin_validate.add_argument("--sample-query", default="", help="Query string used for smoke execution.")
    connector_plugin_validate.add_argument("--sample-params", default='{"src_ip":"203.0.113.10","limit":2}', help="Params JSON used for smoke execution.")
    connector_plugin_validate.add_argument("--timeout-sec", type=int, help="Override smoke execution timeout.")
    connector_plugin_validate.set_defaults(func=cmd_connector)
    connector_test = connector_sub.add_parser("test", help="Run connector connectivity test.")
    connector_test.add_argument("target_id", help="connector_id, or asset_id when --by-asset is set.")
    connector_test.add_argument("--by-asset", action="store_true", help="Interpret target_id as asset_id.")
    connector_test.add_argument("--plan", action="store_true", help="Render fetch plan only when using --by-asset.")
    connector_test.add_argument("--connector", help="With --by-asset, test only this connector_id.")
    connector_test.add_argument("--params", default="{}", help="Fetch params JSON.")
    connector_test.add_argument("--dry-run", action="store_true", help="Render without resolving secrets or live fetch when supported.")
    connector_test.set_defaults(func=cmd_connector)

    asset = subparsers.add_parser("asset", help="Data asset local operations.")
    asset_sub = asset.add_subparsers(dest="action", required=True)
    asset_apply = asset_sub.add_parser("apply", help="Generate connector + asset + query templates from an ops-owned JSON config file.")
    asset_apply.add_argument("-f", "--file", required=True, help="JSON config file with a data_sources array.")
    asset_apply.add_argument("--output-dir", help="Output dataasset root. Defaults to config.output_dir, DATAASSET_ROOT, or ./dataasset.")
    asset_apply.add_argument("--dry-run", action="store_true", help="Print generated files without writing.")
    asset_apply.add_argument("--force", action="store_true", help="Overwrite existing generated files/templates.")
    asset_apply.set_defaults(func=cmd_asset_apply)
    asset_diff = asset_sub.add_parser("diff", help="Compare generated connector/asset/templates from a config against current files.")
    asset_diff.add_argument("-f", "--file", required=True, help="JSON config file with a data_sources array.")
    asset_diff.add_argument("--output-dir", help="Output dataasset root. Defaults to config.output_dir, DATAASSET_ROOT, or ./dataasset.")
    asset_diff.set_defaults(func=cmd_asset_diff)
    asset_rollback = asset_sub.add_parser("rollback", help="Remove connector/asset/templates generated by an onboarding config.")
    asset_rollback.add_argument("-f", "--file", required=True, help="JSON config file with a data_sources array.")
    asset_rollback.add_argument("--output-dir", help="Output dataasset root. Defaults to config.output_dir, DATAASSET_ROOT, or ./dataasset.")
    asset_rollback.add_argument("--dry-run", action="store_true", help="Preview rollback actions without deleting files.")
    asset_rollback.add_argument("--confirm-delete", action="store_true", help="Actually delete generated files/templates. Without this, rollback is dry-run.")
    asset_rollback.set_defaults(func=cmd_asset_rollback)
    asset_promote = asset_sub.add_parser("promote", help="Run connectivity test and promote draft assets to active on success.")
    promote_target = asset_promote.add_mutually_exclusive_group(required=True)
    promote_target.add_argument("--asset", help="Single asset_id to test and promote.")
    promote_target.add_argument("--bundle", help="bundle_id whose draft member assets should be tested and promoted.")
    asset_promote.add_argument("--params", default="{}", help="Fetch params JSON.")
    asset_promote.add_argument("--types", help="Comma-separated asset_types to promote. Defaults to script policy.")
    asset_promote.add_argument("--dry-run", action="store_true", help="Test only; do not write active status.")
    asset_promote.set_defaults(func=cmd_asset_promote)
    asset_init = asset_sub.add_parser("init", help="Create a connector + asset + optional query template from onboarding templates.")
    asset_init.add_argument("--connector-type", required=True, help="Connector type, including entries registered in dataasset/configure/external-connectors.json.")
    asset_init.add_argument("--asset-type", required=True, help="Logical asset type, e.g. waf_alert, ssh_auth, web_access_log.")
    asset_init.add_argument("--name", help="Human-readable data source name.")
    asset_init.add_argument("--asset-id", help="Override generated asset_id.")
    asset_init.add_argument("--connector-id", help="Override generated connector_id.")
    asset_init.add_argument("--template-id", help="Override generated template_id when the onboarding template creates one.")
    asset_init.add_argument("--credentials-ref", help="Vault reference, e.g. vault://sls/security-readonly.")
    asset_init.add_argument("--project", help="SLS project override.")
    asset_init.add_argument("--logstore", help="SLS logstore override.")
    asset_init.add_argument("--index", help="Elasticsearch index override.")
    asset_init.add_argument("--host", help="Host override for SSH / DB / local source metadata.")
    asset_init.add_argument("--host-id", help="Registered host_id placeholder override.")
    asset_init.add_argument("--database", help="Database name override.")
    asset_init.add_argument("--path", help="Filesystem path override for SQLite/local-style connectors.")
    asset_init.add_argument("--collection", help="Collection/table-like namespace override for document connectors.")
    asset_init.add_argument("--db", help="Logical DB index/name override, e.g. Redis db.")
    asset_init.add_argument("--driver", help="Database driver override, e.g. ODBC Driver 18 for SQL Server.")
    asset_init.add_argument("--connection-string", help="Full database connection string override.")
    asset_init.add_argument("--auth-source", help="Authentication database/source override for document connectors.")
    asset_init.add_argument("--ssl", help="SSL/TLS toggle override for connectors that support it.")
    asset_init.add_argument("--base-url", help="HTTP API base URL override.")
    asset_init.add_argument("--owner-team", help="Asset owner team.")
    asset_init.add_argument("--environment", help="Asset environment label.")
    asset_init.add_argument("--status", choices=["discovery", "draft", "active", "disabled"], help="Initial asset status.")
    asset_init.add_argument("--output-dir", help="Output dataasset root. Defaults to DATAASSET_ROOT or ./dataasset.")
    asset_init.add_argument("--endpoint", help="Endpoint override for API/cloud/external executor connectors.")
    asset_init.add_argument("--region", help="Region override for cloud connectors.")
    asset_init.add_argument("--log-group", help="AWS CloudWatch log group override.")
    asset_init.add_argument("--log-stream-prefix", help="AWS CloudWatch log stream prefix override.")
    asset_init.add_argument("--url", help="URL override for Elasticsearch-compatible connectors.")
    asset_init.add_argument("--port", help="Port override for DB/warehouse connectors.")
    asset_init.add_argument("--engine", help="Database engine override.")
    asset_init.add_argument("--base-path", help="Local file connector base path override.")
    asset_init.add_argument("--sample-file", help="Local sample file for local/external executor connectors.")
    asset_init.add_argument("--sample-dir", help="Local sample directory for local/external executor connectors.")
    asset_init.add_argument("--dry-run", action="store_true", help="Print files that would be generated without writing.")
    asset_init.add_argument("--force", action="store_true", help="Overwrite existing generated files/templates.")
    asset_init.set_defaults(func=cmd_asset_init)
    asset_test = asset_sub.add_parser("test", help="Run connector connectivity test for an asset via local fetch.")
    asset_test.add_argument("asset_id", help="dataasset asset_id")
    asset_test.add_argument("--plan", action="store_true", help="Render fetch plan only instead of live fetch.")
    asset_test.add_argument("--connector", help="Only test one connector from the asset fetch plan.")
    asset_test.add_argument("--params", default="{}", help="Fetch params JSON.")
    asset_test.add_argument("--dry-run", action="store_true", help="Render without resolving secrets or fetching live data if supported.")
    asset_test.set_defaults(func=cmd_asset)

    asset_discover = asset_sub.add_parser("discover-format", help="Run log format discovery for an asset.")
    asset_discover.add_argument("asset_id", help="dataasset asset_id")
    asset_discover.add_argument("-i", "--input", help="Sample file. If omitted, SecWeaver first fetches live samples via asset test.")
    asset_discover.add_argument("--text", help="Inline sample text.")
    asset_discover.add_argument("--params", default="{}", help="Fetch params JSON used when no sample input is provided.")
    asset_discover.add_argument("--parser-id", help="Custom text parser id to include in the discovery report.")
    asset_discover.add_argument("--emit-parser", help="Write a custom text parser draft JSON. Path can be a file or directory.")
    asset_discover.add_argument("--parser-description", help="Description for emitted custom parser draft.")
    asset_discover.add_argument("--force-parser", action="store_true", help="Overwrite parser file when using --emit-parser.")
    asset_discover.set_defaults(func=cmd_asset)

    skill = subparsers.add_parser("skill", help="Run a basic local skill wrapper.")
    skill.add_argument("skill", help="Skill name, e.g. alert-confirmation, traceability-analysis.")
    add_common_io_args(skill)
    skill.set_defaults(func=cmd_skill)

    demo = subparsers.add_parser("demo", help="Run an offline demo input through a skill.")
    demo.add_argument("demo", help="Demo name: all, completeness, alert, traceability, risk.")
    demo.add_argument("-o", "--output", help="Output JSON file or existing directory for a single demo; always a directory for demo all, even if its name contains dots. demo all defaults to examples/reports/.")
    demo.add_argument("args", nargs=argparse.REMAINDER, help="Additional arguments passed to the underlying skill script after '--'.")
    demo.set_defaults(func=cmd_demo)

    report = subparsers.add_parser("report", help="Generate human-readable Markdown reports from JSON outputs.")
    report_sub = report.add_subparsers(dest="action", required=True)
    report_md = report_sub.add_parser("markdown", help="Render a Markdown investigation report from structured JSON.")
    report_md.add_argument("-i", "--input", help="Input JSON file produced by a SecWeaver skill or demo.")
    report_md.add_argument("-o", "--output", help="Output Markdown file. Defaults to stdout or <input>.md.")
    report_md.add_argument("--demo", help="Convert built-in demo JSON: all, completeness, alert, traceability, risk.")
    report_md.add_argument("--input-dir", help="Directory containing demo-*-output.json when using --demo.")
    report_md.add_argument("--investigation", help="Generate a bundled investigation report from a demo reports directory.")
    report_md.add_argument("--bundle", action="store_true", help="With --demo all, also write investigation-report.md.")
    report_md.set_defaults(func=cmd_report)

    list_cmd = subparsers.add_parser("list", help="List available local skills and demos.")
    list_cmd.set_defaults(func=cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
