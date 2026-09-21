"""Asset onboarding lifecycle commands for the SecWeaver CLI."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
DATA_ACCESS_ROOT = SRC_ROOT / "skills" / "_shared" / "data-access"
if str(DATA_ACCESS_ROOT) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_ROOT))

from connector_registry import (  # noqa: E402
    connector_registry,
    onboarding_template_for_connector,
    query_key_for_connector,
)
from dataasset.registry_write import registry_write_lock, write_json_atomic  # noqa: E402
from dataasset_paths import DATAASSET_ROOT, format_path  # noqa: E402

ONBOARDING_ROOT = DATAASSET_ROOT / "onboarding"
SCRIPT_PATHS = {
    "promote": REPO_ROOT / "src/dataasset/promote_after_connectivity.py",
}

ASSET_INIT_CONFIG_KEYS = (
    "connector_type",
    "asset_type",
    "name",
    "asset_id",
    "connector_id",
    "template_id",
    "credentials_ref",
    "project",
    "project_id",
    "logstore",
    "index",
    "host",
    "host_id",
    "database",
    "path",
    "collection",
    "db",
    "driver",
    "connection_string",
    "auth_source",
    "ssl",
    "secure",
    "base_url",
    "owner_team",
    "environment",
    "status",
    "output_dir",
    "endpoint",
    "fallback_endpoint",
    "executor_endpoint",
    "external_endpoint",
    "region",
    "log_group",
    "log_group_id",
    "log_stream_id",
    "log_stream_prefix",
    "bucket",
    "prefix",
    "workspace_id",
    "tenant_id",
    "topic_id",
    "url",
    "port",
    "engine",
    "base_path",
    "sample_file",
    "sample_dir",
    "connector",
    "asset",
    "template",
    "overrides",
)
ASSET_STATUSES = {"discovery", "draft", "active", "disabled"}


def run_script(script: Path, args: list[str]) -> int:
    if not script.is_file():
        print(f"script not found: {script}", file=sys.stderr)
        return 1
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.call([sys.executable, str(script), *args], cwd=REPO_ROOT, env=env)


def slugify_id(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return text or "new-source"


def resolve_output_root(value: str | None) -> Path:
    if not value:
        return DATAASSET_ROOT
    root = Path(value)
    if not root.is_absolute():
        root = REPO_ROOT / root
    return root


def configured_output_dir(args_output: str | None, config_output: Any = None) -> str | None:
    if args_output:
        return args_output
    if os.environ.get("DATAASSET_ROOT"):
        return None
    return str(config_output) if config_output else None


def load_template_json(connector_type: str, name: str) -> dict:
    path = ONBOARDING_ROOT / connector_type / name
    if not path.is_file():
        raise SystemExit(f"onboarding template not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_json_file(path_arg: str) -> dict[str, Any]:
    path = Path(path_arg)
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.is_file():
        raise SystemExit(f"config file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"config file must contain a JSON object: {path}")
    return data


def replace_placeholders(value, replacements: dict[str, str]):
    if isinstance(value, str):
        out = value
        for old, new in replacements.items():
            out = out.replace(old, new)
        return out
    if isinstance(value, list):
        return [replace_placeholders(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: replace_placeholders(item, replacements) for key, item in value.items()}
    return value


def deep_merge(base, override):
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            merged[key] = deep_merge(merged.get(key), value)
        return merged
    if override is None:
        return base
    return override


def write_json_file(path: Path, payload: dict, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise SystemExit(f"refuse to overwrite existing file: {format_path(path)} (use --force)")
    write_json_atomic(path, payload)


def validate_generated_connector(connector: dict[str, Any]) -> None:
    """Reject generated connector files that the canonical schema cannot load.

    The check runs after user overrides, so both form and raw-JSON onboarding
    fail before writing a file that would make the registry invalid.
    """
    schema_path = DATAASSET_ROOT / "schema" / "data-connector.schema.json"
    if not schema_path.is_file():
        # Thin private overlays may own only inventory and onboarding files;
        # validate their generated connector against the packaged public contract.
        schema_path = REPO_ROOT / "dataasset" / "schema" / "data-connector.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(connector),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    field = ".".join(str(part) for part in error.absolute_path) or "<root>"
    raise SystemExit(f"generated connector violates data-connector.schema.json at {field}: {error.message}")


def load_or_create_templates(path: Path) -> dict:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "version": "1.0",
        "description": "SecWeaver query templates",
        "default_templates": {},
        "templates": {},
    }


def apply_connector_overrides(connector: dict, settings: argparse.Namespace) -> None:
    config = connector.setdefault("config", {})

    def has_config_value(name: str) -> bool:
        return hasattr(settings, name) and getattr(settings, name) not in (None, "")

    if config_value := getattr(settings, "credentials_ref", None):
        connector["credentials_ref"] = config_value
    if config_value := getattr(settings, "project", None):
        config["project"] = config_value
    if config_value := getattr(settings, "project_id", None):
        config["project_id"] = config_value
    if config_value := getattr(settings, "logstore", None):
        config["logstore"] = config_value
    if config_value := getattr(settings, "index", None):
        config["index"] = config_value
    if config_value := getattr(settings, "host", None):
        if connector.get("connector_type") in {"database_ro", "ssh_file", "ssh_command"}:
            config["host"] = config_value
        elif connector.get("connector_type") == "local_file":
            config["hostname"] = config_value
    if config_value := getattr(settings, "database", None):
        config["database"] = config_value
    if config_value := getattr(settings, "path", None):
        config["path"] = config_value
    if config_value := getattr(settings, "collection", None):
        config["collection"] = config_value
    if has_config_value("db"):
        value = getattr(settings, "db")
        config["db"] = int(value) if isinstance(value, str) and value.isdigit() else value
    if config_value := getattr(settings, "driver", None):
        config["driver"] = config_value
    if config_value := getattr(settings, "connection_string", None):
        config["connection_string"] = config_value
    if config_value := getattr(settings, "auth_source", None):
        config["auth_source"] = config_value
    if has_config_value("ssl"):
        value = getattr(settings, "ssl")
        config["ssl"] = value.lower() == "true" if isinstance(value, str) else value
    if has_config_value("secure"):
        value = getattr(settings, "secure")
        config["secure"] = value.lower() == "true" if isinstance(value, str) else value
    if config_value := getattr(settings, "base_url", None):
        config["base_url"] = config_value
    if config_value := getattr(settings, "endpoint", None):
        config["endpoint"] = config_value
    if config_value := getattr(settings, "fallback_endpoint", None):
        config["fallback_endpoint"] = config_value
    if config_value := getattr(settings, "executor_endpoint", None):
        config["executor_endpoint"] = config_value
    if config_value := getattr(settings, "external_endpoint", None):
        config["external_endpoint"] = config_value
    if config_value := getattr(settings, "region", None):
        config["region"] = config_value
    if config_value := getattr(settings, "log_group", None):
        config["log_group"] = config_value
    if config_value := getattr(settings, "log_group_id", None):
        config["log_group_id"] = config_value
    if config_value := getattr(settings, "log_stream_id", None):
        config["log_stream_id"] = config_value
    if config_value := getattr(settings, "log_stream_prefix", None):
        config["log_stream_prefix"] = config_value
    if config_value := getattr(settings, "bucket", None):
        config["bucket"] = config_value
    if config_value := getattr(settings, "prefix", None):
        config["prefix"] = config_value
    if config_value := getattr(settings, "workspace_id", None):
        config["workspace_id"] = config_value
    if config_value := getattr(settings, "tenant_id", None):
        config["tenant_id"] = config_value
    if config_value := getattr(settings, "topic_id", None):
        config["topic_id"] = config_value
    if config_value := getattr(settings, "url", None):
        config["url"] = config_value
    if config_value := getattr(settings, "port", None):
        config["port"] = int(config_value) if isinstance(config_value, str) and config_value.isdigit() else config_value
    if config_value := getattr(settings, "engine", None):
        config["engine"] = config_value
    if config_value := getattr(settings, "base_path", None):
        config["base_path"] = config_value
    if config_value := getattr(settings, "sample_file", None):
        config["sample_file"] = config_value
    if config_value := getattr(settings, "sample_dir", None):
        config["sample_dir"] = config_value


def normalize_source_config(raw: dict[str, Any], *, defaults: dict[str, Any] | None = None, index: int = 0) -> argparse.Namespace:
    if not isinstance(raw, dict):
        raise SystemExit(f"data_sources[{index}] must be an object")
    defaults = defaults or {}
    unknown = sorted(set(raw) - set(ASSET_INIT_CONFIG_KEYS))
    if unknown:
        raise SystemExit(f"data_sources[{index}] contains unknown field(s): {', '.join(unknown)}")
    merged = {key: defaults.get(key) for key in ASSET_INIT_CONFIG_KEYS}
    for key, value in raw.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    if not merged.get("connector_type"):
        raise SystemExit(f"data_sources[{index}] requires connector_type")
    if not merged.get("asset_type"):
        raise SystemExit(f"data_sources[{index}] requires asset_type")
    if merged.get("status") and merged["status"] not in ASSET_STATUSES:
        raise SystemExit(f"data_sources[{index}].status must be one of: {', '.join(sorted(ASSET_STATUSES))}")
    for section in ("connector", "asset", "template", "overrides"):
        if merged.get(section) is not None and not isinstance(merged[section], dict):
            raise SystemExit(f"data_sources[{index}].{section} must be an object when provided")
    overrides = merged.get("overrides") or {}
    for key, value in overrides.items():
        if key in {"connector", "asset", "template"}:
            continue
        if key in ASSET_INIT_CONFIG_KEYS:
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = deep_merge(merged[key], value)
            else:
                merged[key] = value
    return argparse.Namespace(**merged)


def expand_asset_apply_config(config: dict[str, Any]) -> list[argparse.Namespace]:
    defaults = config.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise SystemExit("defaults must be an object when provided")

    data_sources = config.get("data_sources")
    if not isinstance(data_sources, list) or not data_sources:
        raise SystemExit("config requires non-empty data_sources array")

    sources: list[argparse.Namespace] = []
    for index, raw in enumerate(data_sources):
        if not isinstance(raw, dict):
            raise SystemExit(f"data_sources[{index}] must be an object")
        sources.append(normalize_source_config(raw, defaults=defaults, index=index))
    return sources


def build_asset_init_plan(settings: argparse.Namespace, *, output_root: Path | None = None) -> dict[str, Any]:
    """Build one Connector/Asset/template plan from manifest-selected skeletons."""
    connector_type = settings.connector_type
    template_name = onboarding_template_for_connector(connector_type)
    if not template_name:
        available = ", ".join(sorted(connector_registry()))
        raise SystemExit(f"unknown connector_type or missing onboarding_template: {connector_type}\navailable: {available}")
    # Template selection is manifest-owned so CLI and UI cannot silently choose
    # different skeletons for the same connector type.
    template_dir = ONBOARDING_ROOT / template_name
    if not template_dir.is_dir():
        raise SystemExit(f"onboarding template directory not found: {template_dir}")

    source_slug = slugify_id(settings.name or f"{connector_type}-{settings.asset_type}")
    asset_id = settings.asset_id or f"asset-{source_slug}"
    connector_id = settings.connector_id or f"conn-{source_slug}"
    template_id = settings.template_id or f"{source_slug}-by-src-ip-time"
    output_root = output_root or resolve_output_root(settings.output_dir)

    replacements = {
        "YOUR_CONN_ID": connector_id,
        "YOUR_ASSET_ID": asset_id,
        "YOUR_TEMPLATE_ID": template_id,
        "YOUR_HOST": settings.host or "YOUR_HOST",
        "YOUR_HOST_ID": settings.host_id or "YOUR_HOST_ID",
        "YOUR_SLS_PROJECT": settings.project or "YOUR_SLS_PROJECT",
        "YOUR_LOGSTORE": settings.logstore or "YOUR_LOGSTORE",
        "YOUR_INDEX": settings.index or "YOUR_INDEX",
        "YOUR_DATABASE": settings.database or "YOUR_DATABASE",
    }

    template_connector_type = template_name
    connector = replace_placeholders(load_template_json(template_connector_type, "connector.json"), replacements)
    asset = replace_placeholders(load_template_json(template_connector_type, "asset.json"), replacements)
    template = replace_placeholders(load_template_json(template_connector_type, "template.snippet.json"), replacements)
    external_query_key = query_key_for_connector(connector_type)
    if external_query_key and "EXTERNAL_QUERY_KEY" in template:
        template[external_query_key] = template.pop("EXTERNAL_QUERY_KEY")

    connector["connector_id"] = connector_id
    connector["connector_type"] = connector_type
    asset["asset_id"] = asset_id
    asset["asset_type"] = settings.asset_type
    asset["connector_id"] = connector_id
    if settings.name:
        asset["name"] = settings.name
        connector["name"] = f"{settings.name} connector"
    if settings.owner_team:
        asset["owner_team"] = settings.owner_team
    if settings.environment:
        asset["environment"] = settings.environment
    if settings.status:
        asset["status"] = settings.status
        connector["status"] = settings.status if settings.status in {"draft", "active", "disabled"} else "draft"
    apply_connector_overrides(connector, settings)

    grouped_overrides = getattr(settings, "overrides", None) or {}
    connector_override = deep_merge(getattr(settings, "connector", None) or {}, grouped_overrides.get("connector") or {})
    asset_override = deep_merge(getattr(settings, "asset", None) or {}, grouped_overrides.get("asset") or {})
    template_override = deep_merge(getattr(settings, "template", None) or {}, grouped_overrides.get("template") or {})

    template_written = False
    if "asset_types" in template and "connector_types" in template:
        template["template_id"] = template_id
        template["asset_types"] = [settings.asset_type]
        template["connector_types"] = [connector_type]
        asset["query_template_ids"] = [template_id]
        template_written = True

    if template_written:
        original_template_id = template_id
        template = deep_merge(template, template_override)
        template_id = str(template.get("template_id") or original_template_id)
        template["template_id"] = template_id
        template.setdefault("asset_types", [settings.asset_type])
        template.setdefault("connector_types", [connector_type])
        if asset.get("query_template_ids") == [original_template_id]:
            asset["query_template_ids"] = [template_id]
        template_written = isinstance(template, dict) and "asset_types" in template and "connector_types" in template
    elif template_override:
        template = deep_merge(
            {
                "template_id": template_override.get("template_id") or template_id,
                "asset_types": [settings.asset_type],
                "connector_types": [connector_type],
            },
            template_override,
        )
        template_id = str(template.get("template_id") or template_id)
        template["template_id"] = template_id
        asset["query_template_ids"] = [template_id]
        template_written = "asset_types" in template and "connector_types" in template

    connector = deep_merge(connector, connector_override)
    asset = deep_merge(asset, asset_override)
    connector["connector_id"] = connector_id
    connector["connector_type"] = connector_type
    asset["asset_id"] = asset_id
    asset["asset_type"] = settings.asset_type
    asset["connector_id"] = connector_id
    if template_written:
        template["template_id"] = template_id

    validate_generated_connector(connector)

    return {
        "connector_id": connector_id,
        "asset_id": asset_id,
        "template_id": template_id,
        "connector": connector,
        "asset": asset,
        "template": template if template_written else None,
        "paths": {
            "connector": output_root / "connectors" / f"{connector_id}.json",
            "asset": output_root / "assets" / f"{asset_id}.json",
            "templates": output_root / "query-templates" / "templates.json",
        },
    }


def render_asset_plan(plan: dict[str, Any]) -> dict[str, Any]:
    paths = plan["paths"]
    return {
        "connector": {"path": format_path(paths["connector"]), "data": plan["connector"]},
        "asset": {"path": format_path(paths["asset"]), "data": plan["asset"]},
        "template": {"path": format_path(paths["templates"]), "data": plan["template"]},
    }


def write_asset_plan(plan: dict[str, Any], *, force: bool = False) -> None:
    paths = plan["paths"]
    template = plan["template"]
    if template:
        templates = load_or_create_templates(paths["templates"])
        catalog = templates.setdefault("templates", {})
        if plan["template_id"] in catalog and not force:
            raise SystemExit(f"refuse to overwrite existing template: {plan['template_id']} (use --force)")
    write_json_file(paths["connector"], plan["connector"], force=force)
    write_json_file(paths["asset"], plan["asset"], force=force)
    if template:
        catalog[plan["template_id"]] = template
        write_json_atomic(paths["templates"], templates)


def check_duplicate_plans(plans: list[dict[str, Any]]) -> None:
    seen_paths: dict[Path, str] = {}
    seen_templates: dict[tuple[Path, str], str] = {}
    for plan in plans:
        for kind in ("connector", "asset"):
            path = plan["paths"][kind]
            if path in seen_paths:
                raise SystemExit(f"duplicate generated {kind} path in config: {format_path(path)}")
            seen_paths[path] = plan["asset_id"]
        if plan["template"]:
            key = (plan["paths"]["templates"], plan["template_id"])
            if key in seen_templates:
                raise SystemExit(f"duplicate generated template_id in config: {plan['template_id']}")
            seen_templates[key] = plan["asset_id"]


def assert_asset_plans_can_write(plans: list[dict[str, Any]], *, force: bool = False) -> None:
    check_duplicate_plans(plans)
    if force:
        return
    for plan in plans:
        for kind in ("connector", "asset"):
            path = plan["paths"][kind]
            if path.exists():
                raise SystemExit(f"refuse to overwrite existing {kind}: {format_path(path)} (use --force)")
        if plan["template"]:
            templates_path = plan["paths"]["templates"]
            templates = load_or_create_templates(templates_path)
            if plan["template_id"] in (templates.get("templates") or {}):
                raise SystemExit(f"refuse to overwrite existing template: {plan['template_id']} (use --force)")


def cmd_asset_init(args: argparse.Namespace) -> int:
    plan = build_asset_init_plan(args)
    if args.dry_run:
        print(json.dumps(render_asset_plan(plan), ensure_ascii=False, indent=2))
        return 0

    with registry_write_lock(plan["paths"]["asset"].parent.parent):
        assert_asset_plans_can_write([plan], force=args.force)
        write_asset_plan(plan, force=args.force)
    summary = {
        "ok": True,
        "connector": format_path(plan["paths"]["connector"]),
        "asset": format_path(plan["paths"]["asset"]),
        "template_id": plan["template_id"] if plan["template"] else None,
        "next": [
            "python3 src/secweaver.py validate --json --only-active",
            f"python3 src/secweaver.py asset test {plan['asset_id']} --dry-run",
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_asset_apply(args: argparse.Namespace) -> int:
    config = load_json_file(args.file)
    output_root = resolve_output_root(configured_output_dir(args.output_dir, config.get("output_dir")))
    plans = [build_asset_init_plan(source, output_root=output_root) for source in expand_asset_apply_config(config)]

    if args.dry_run:
        payload = {
            "ok": True,
            "mode": "dry-run",
            "output_dir": format_path(output_root),
            "sources": [render_asset_plan(plan) for plan in plans],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    with registry_write_lock(output_root):
        assert_asset_plans_can_write(plans, force=args.force)
        for plan in plans:
            write_asset_plan(plan, force=args.force)

    summary = {
        "ok": True,
        "output_dir": format_path(output_root),
        "written": [
            {
                "connector": format_path(plan["paths"]["connector"]),
                "asset": format_path(plan["paths"]["asset"]),
                "template_id": plan["template_id"] if plan["template"] else None,
            }
            for plan in plans
        ],
        "next": [
            "python3 src/secweaver.py validate --json --only-active",
            "python3 src/secweaver.py catalog sync",
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def json_equal(left: Any, right: Any) -> bool:
    return json.dumps(left, ensure_ascii=False, sort_keys=True) == json.dumps(right, ensure_ascii=False, sort_keys=True)


def diff_json_path(path: Path, expected: dict[str, Any] | None) -> dict[str, Any]:
    if expected is None:
        return {"path": format_path(path), "status": "not_generated"}
    if not path.exists():
        return {"path": format_path(path), "status": "missing", "would_create": True}
    try:
        actual = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"path": format_path(path), "status": "invalid_json", "error": str(exc), "would_replace": True}
    if json_equal(actual, expected):
        return {"path": format_path(path), "status": "unchanged"}
    return {"path": format_path(path), "status": "changed", "would_replace": True}


def diff_template(plan: dict[str, Any]) -> dict[str, Any]:
    template = plan["template"]
    path = plan["paths"]["templates"]
    if not template:
        return {"path": format_path(path), "template_id": plan["template_id"], "status": "not_generated"}
    if not path.exists():
        return {"path": format_path(path), "template_id": plan["template_id"], "status": "missing", "would_create": True}
    try:
        templates = load_or_create_templates(path).get("templates") or {}
    except json.JSONDecodeError as exc:
        return {"path": format_path(path), "template_id": plan["template_id"], "status": "invalid_json", "error": str(exc), "would_replace": True}
    existing = templates.get(plan["template_id"])
    if existing is None:
        return {"path": format_path(path), "template_id": plan["template_id"], "status": "missing", "would_create": True}
    if json_equal(existing, template):
        return {"path": format_path(path), "template_id": plan["template_id"], "status": "unchanged"}
    return {"path": format_path(path), "template_id": plan["template_id"], "status": "changed", "would_replace": True}


def build_asset_plans_from_config(args: argparse.Namespace) -> tuple[Path, list[dict[str, Any]]]:
    config = load_json_file(args.file)
    output_root = resolve_output_root(configured_output_dir(args.output_dir, config.get("output_dir")))
    return output_root, [build_asset_init_plan(source, output_root=output_root) for source in expand_asset_apply_config(config)]


def cmd_asset_diff(args: argparse.Namespace) -> int:
    output_root, plans = build_asset_plans_from_config(args)
    sources = []
    for plan in plans:
        sources.append(
            {
                "asset_id": plan["asset_id"],
                "connector_id": plan["connector_id"],
                "template_id": plan["template_id"],
                "connector": diff_json_path(plan["paths"]["connector"], plan["connector"]),
                "asset": diff_json_path(plan["paths"]["asset"], plan["asset"]),
                "template": diff_template(plan),
            }
        )
    changed = [
        item
        for source in sources
        for item in (source["connector"], source["asset"], source["template"])
        if item["status"] in {"missing", "changed", "invalid_json"}
    ]
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "diff",
                "output_dir": format_path(output_root),
                "summary": {"source_count": len(sources), "change_count": len(changed)},
                "sources": sources,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def delete_if_allowed(path: Path, *, apply: bool) -> dict[str, Any]:
    if not path.exists():
        return {"path": format_path(path), "status": "missing"}
    if not apply:
        return {"path": format_path(path), "status": "would_delete"}
    path.unlink()
    return {"path": format_path(path), "status": "deleted"}


def rollback_template(plan: dict[str, Any], *, apply: bool) -> dict[str, Any]:
    path = plan["paths"]["templates"]
    template_id = plan["template_id"]
    if not plan["template"]:
        return {"path": format_path(path), "template_id": template_id, "status": "not_generated"}
    if not path.exists():
        return {"path": format_path(path), "template_id": template_id, "status": "missing"}
    templates = load_or_create_templates(path)
    catalog = templates.setdefault("templates", {})
    if template_id not in catalog:
        return {"path": format_path(path), "template_id": template_id, "status": "missing"}
    if not apply:
        return {"path": format_path(path), "template_id": template_id, "status": "would_remove"}
    del catalog[template_id]
    write_json_atomic(path, templates)
    return {"path": format_path(path), "template_id": template_id, "status": "removed"}


def cmd_asset_rollback(args: argparse.Namespace) -> int:
    output_root, plans = build_asset_plans_from_config(args)
    apply = bool(args.confirm_delete and not args.dry_run)
    sources = []
    # Hold the same root lock as Studio while checking and changing JSON files.
    with registry_write_lock(output_root):
        for plan in plans:
            sources.append(
                {
                    "asset_id": plan["asset_id"],
                    "connector_id": plan["connector_id"],
                    "template_id": plan["template_id"],
                    "connector": delete_if_allowed(plan["paths"]["connector"], apply=apply),
                    "asset": delete_if_allowed(plan["paths"]["asset"], apply=apply),
                    "template": rollback_template(plan, apply=apply),
                }
            )
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "rollback",
                "dry_run": not apply,
                "applied": apply,
                "output_dir": format_path(output_root),
                "confirm_required": not args.confirm_delete,
                "sources": sources,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def cmd_asset_promote(args: argparse.Namespace) -> int:
    script_args: list[str] = []
    if args.asset:
        script_args.extend(["--asset", args.asset])
    if args.bundle:
        script_args.extend(["--bundle", args.bundle])
    if args.params:
        script_args.extend(["--params", args.params])
    if args.types:
        script_args.extend(["--types", args.types])
    if args.dry_run:
        script_args.append("--dry-run")
    return run_script(SCRIPT_PATHS["promote"], script_args)
