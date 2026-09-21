"""Config-backed connector type registry."""

from __future__ import annotations

import json
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from dataasset_paths import DATAASSET_ROOT, REPO_ROOT, format_path

# The contract belongs to DataAsset, not to any particular Skill or executor.
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
from dataasset.plugin_contract import IDENTIFIER_RE, PluginContractError, normalize_manifest  # noqa: E402

CONNECTOR_CATALOG_FILE = DATAASSET_ROOT / "configure" / "connector-catalog.json"
REGISTRY_FILE = DATAASSET_ROOT / "configure" / "external-connectors.json"
PUBLIC_CONNECTOR_CATALOG_FILE = REPO_ROOT / "dataasset" / "configure" / "connector-catalog.json"
DEFAULT_PLUGIN_ROOT = REPO_ROOT / "src" / "dataasset" / "plugins" / "connectors"


def resolve_plugin_root() -> Path:
    configured = os.environ.get("SECWEAVER_PLUGIN_ROOT")
    if not configured:
        return DEFAULT_PLUGIN_ROOT
    path = Path(configured).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


PLUGIN_ROOT = resolve_plugin_root()
CONNECTOR_TYPE_RE = IDENTIFIER_RE
CONNECTOR_CATALOG_FORMAT_VERSION = "2.0"

def _valid_connector_type(value: Any) -> str:
    connector_type = str(value or "").strip()
    return connector_type if CONNECTOR_TYPE_RE.fullmatch(connector_type) else ""


def builtin_catalog_file() -> Path:
    """Select the configured catalog, or the packaged catalog for thin overlays."""
    if CONNECTOR_CATALOG_FILE.is_file() or CONNECTOR_CATALOG_FILE == PUBLIC_CONNECTOR_CATALOG_FILE:
        return CONNECTOR_CATALOG_FILE
    return PUBLIC_CONNECTOR_CATALOG_FILE


def _read_connector_catalog(path: Path) -> dict[str, Any]:
    """Read one registry catalog and reject unsupported structural formats.

    Runtime loading is deliberately strict here: silently accepting a legacy
    partial catalog can select the wrong query key or omit onboarding metadata.
    Operators must preview and run the documented migration first.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read connector catalog {format_path(path)}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"connector catalog {format_path(path)} must be a JSON object")
    format_version = str(data.get("format_version") or "")
    if format_version != CONNECTOR_CATALOG_FORMAT_VERSION:
        raise RuntimeError(
            f"connector catalog {format_path(path)} uses format_version={format_version or 'missing'}; "
            f"expected {CONNECTOR_CATALOG_FORMAT_VERSION}. Run `python3 src/secweaver.py "
            f"dataasset migrate --root {format_path(DATAASSET_ROOT)} --write`."
        )
    return data


def _load_builtin_connectors() -> dict[str, dict[str, Any]]:
    # A private registry may omit the platform capability catalog. In that case
    # reuse the packaged public catalog instead of maintaining a second Python
    # copy that can drift from the declared connector contract.
    catalog_file = builtin_catalog_file()
    if not catalog_file.is_file():
        return {}
    data = _read_connector_catalog(catalog_file)
    configured = data.get("connectors") if isinstance(data, dict) else {}
    if not isinstance(configured, dict):
        return {}

    connectors: dict[str, dict[str, Any]] = {}
    for connector_type, spec in configured.items():
        connector_type = _valid_connector_type(connector_type)
        if not connector_type or not isinstance(spec, dict):
            continue
        if spec.get("source") not in {None, "built_in"}:
            continue
        query_key = _valid_connector_type(spec.get("query_key"))
        if not query_key:
            continue
        runtime = str(spec.get("runtime") or "local_or_external_executor").strip()
        connectors[connector_type] = {
            **spec,
            "query_key": query_key,
            "runtime": runtime,
        }
    return connectors


@lru_cache(maxsize=1)
def builtin_connector_specs() -> dict[str, dict[str, Any]]:
    return _load_builtin_connectors()


def _relative_to_repo(path: Path) -> str:
    return format_path(path)


@lru_cache(maxsize=1)
def plugin_connector_specs() -> dict[str, dict[str, Any]]:
    """Register only raw manifests accepted by the CLI/runtime contract.

    Discovery never executes code. Invalid manifests are omitted from the cached
    catalog; the CLI validator reports their individual errors to the operator.
    """
    if not PLUGIN_ROOT.is_dir():
        return {}

    plugins: dict[str, dict[str, Any]] = {}
    for manifest_path in sorted(PLUGIN_ROOT.glob("*/plugin.json")):
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue

        try:
            data = normalize_manifest(data)
        except PluginContractError:
            continue

        connector_type = _valid_connector_type(data.get("connector_type"))
        query_key = _valid_connector_type(data.get("query_key"))
        if not connector_type or not query_key:
            continue

        plugin_dir = manifest_path.parent
        plugins[connector_type] = {
            **data,
            "connector_type": connector_type,
            "query_key": query_key,
            "runtime": "plugin",
            "plugin_dir": _relative_to_repo(plugin_dir),
            "manifest": _relative_to_repo(manifest_path),
        }
    return plugins


@lru_cache(maxsize=1)
def connector_registry() -> dict[str, dict[str, Any]]:
    registry = {key: dict(value) for key, value in builtin_connector_specs().items()}
    if REGISTRY_FILE.is_file():
        data = _read_connector_catalog(REGISTRY_FILE)
        configured = data.get("connectors") if isinstance(data, dict) else {}
        if isinstance(configured, dict):
            for connector_type, spec in configured.items():
                connector_type = _valid_connector_type(connector_type)
                if not connector_type or not isinstance(spec, dict):
                    continue
                query_key = _valid_connector_type(spec.get("query_key"))
                if not query_key:
                    continue
                runtime = str(spec.get("runtime") or "local_or_external_executor").strip()
                registry[connector_type] = {
                    **spec,
                    "query_key": query_key,
                    "runtime": runtime,
                }
    registry.update(plugin_connector_specs())
    return registry


def connector_types() -> list[str]:
    return list(connector_registry())


def query_key_by_connector() -> dict[str, str]:
    return {key: str(value["query_key"]) for key, value in connector_registry().items()}


def query_key_for_connector(connector_type: str) -> str | None:
    spec = connector_registry().get(connector_type)
    return str(spec["query_key"]) if spec and spec.get("query_key") else None


def runtime_capabilities() -> dict[str, str]:
    return {key: str(value.get("runtime") or "local_or_external_executor") for key, value in connector_registry().items()}


def onboarding_profiles() -> dict[str, dict[str, Any]]:
    """Return UI profiles from each connector's authoritative manifest.

    Built-ins, config-only extensions, and plugins own their profile beside their
    runtime metadata. Consumers therefore cannot observe a stale parallel profile
    catalog after connector capabilities change.
    """
    profiles: dict[str, dict[str, Any]] = {}
    for connector_type, spec in connector_registry().items():
        profile = spec.get("onboarding_profile")
        if isinstance(profile, dict):
            profiles[connector_type] = dict(profile)
    return profiles


def onboarding_template_for_connector(connector_type: str) -> str | None:
    """Return the declared onboarding skeleton directory for a connector type."""
    spec = connector_registry().get(connector_type) or {}
    value = str(spec.get("onboarding_template") or "").strip()
    return value or None


def is_external_runtime(connector_type: str) -> bool:
    return runtime_capabilities().get(connector_type) in {"local_or_external_executor", "live_or_external_executor"}


def is_plugin_runtime(connector_type: str) -> bool:
    return runtime_capabilities().get(connector_type) == "plugin"


def clear_connector_registry_cache() -> None:
    """Reload connector catalog, external config, and plugin manifests on next read."""
    builtin_connector_specs.cache_clear()
    plugin_connector_specs.cache_clear()
    connector_registry.cache_clear()
