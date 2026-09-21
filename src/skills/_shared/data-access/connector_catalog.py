"""Connector capability catalog shared by CLI and UI."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from connector_registry import (
    DATAASSET_ROOT,
    PLUGIN_ROOT,
    REGISTRY_FILE,
    builtin_catalog_file,
    builtin_connector_specs,
    connector_registry,
    plugin_connector_specs,
)
from dataasset_paths import format_path

ONBOARDING_ROOT = DATAASSET_ROOT / "onboarding"
DEFAULT_EXECUTION_ORDER = ["local_sample", "external_executor", "planned_metadata"]


def _rel(path: Path) -> str:
    return format_path(path)


def _strategy(spec: dict[str, Any], source: str) -> dict[str, Any]:
    """Read dependency strategy from the manifest, with source-level defaults.

    Built-in dependency metadata must live in connector-catalog.json. Generic
    defaults are retained only for operator-defined extensions and plugins whose
    dependency lifecycle belongs outside the built-in catalog.
    """
    if source == "plugin":
        defaults = {
            "dependency_hint": "Plugin-owned dependencies. Keep SDKs in the plugin virtualenv or requirements.txt.",
            "dependency_hint_zh": "插件自带依赖；SDK 放在插件虚拟环境或 requirements.txt 中。",
            "packages": [],
            "execution_order": ["plugin_stdio_json"],
            "missing_dependency": "Install dependencies declared by the plugin.",
        }
    else:
        defaults = {
            "dependency_hint": "Config-only connector. Use local samples or an external executor/plugin for vendor SDKs.",
            "dependency_hint_zh": "配置型 connector；厂商 SDK 放到本地样本、外部执行器或插件里。",
            "packages": [],
            "execution_order": DEFAULT_EXECUTION_ORDER,
            "missing_dependency": "Configure sample_file/sample_dir or connector.config.endpoint.",
        }
    return {key: spec.get(key, default) for key, default in defaults.items()}


def _source(connector_type: str, plugins: dict[str, dict[str, Any]]) -> str:
    if connector_type in plugins:
        return "plugin"
    if connector_type in builtin_connector_specs():
        return "built_in"
    return "external_config"


@lru_cache(maxsize=1)
def connector_catalog() -> list[dict[str, Any]]:
    """Return product-facing connector capabilities for CLI, UI, and docs."""
    registry = connector_registry()
    plugins = plugin_connector_specs()
    records: list[dict[str, Any]] = []
    for connector_type, spec in registry.items():
        source = _source(connector_type, plugins)
        strategy = _strategy(spec, source)
        template_name = str(spec.get("onboarding_template") or "").strip()
        onboarding_dir = ONBOARDING_ROOT / template_name if template_name else None
        has_template = bool(
            onboarding_dir
            and onboarding_dir.is_dir()
            and (onboarding_dir / "connector.json").is_file()
        )
        record: dict[str, Any] = {
            "connector_type": connector_type,
            "query_key": str(spec.get("query_key") or ""),
            "runtime": str(spec.get("runtime") or "local_or_external_executor"),
            "source": source,
            "source_file": "",
            "onboarding_template": has_template,
            "onboarding_dir": _rel(onboarding_dir) if onboarding_dir and onboarding_dir.exists() else "",
            "description": str(spec.get("description") or ""),
            "dependency_hint": str(strategy["dependency_hint"] or ""),
            "dependency_hint_zh": str(strategy["dependency_hint_zh"] or ""),
            "packages": list(strategy["packages"] or []),
            "execution_order": list(strategy["execution_order"] or DEFAULT_EXECUTION_ORDER),
            "missing_dependency": str(strategy["missing_dependency"] or ""),
        }
        if source == "built_in":
            record["source_file"] = _rel(builtin_catalog_file())
        elif source == "plugin":
            plugin = plugins.get(connector_type, {})
            record.update(
                {
                    "plugin_dir": plugin.get("plugin_dir", ""),
                    "manifest": plugin.get("manifest", ""),
                    "entrypoint": plugin.get("entrypoint", "fetch.py"),
                    "protocol": plugin.get("protocol", "stdio-json"),
                    "python": plugin.get("python", ""),
                    "source_file": str(plugin.get("manifest") or ""),
                }
            )
        else:
            record["source_file"] = _rel(REGISTRY_FILE) if REGISTRY_FILE.exists() else ""
        records.append(record)
    return records


def connector_catalog_by_type() -> dict[str, dict[str, Any]]:
    return {record["connector_type"]: record for record in connector_catalog()}


def plugin_scaffold_root() -> str:
    return _rel(PLUGIN_ROOT)


def clear_connector_catalog_cache() -> None:
    """Reload product-facing connector metadata on next read."""
    connector_catalog.cache_clear()
