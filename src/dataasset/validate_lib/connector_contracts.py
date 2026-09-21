"""Cross-file contracts for connector manifests and onboarding metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CATALOG_NAMES = ("connector-catalog.json", "external-connectors.json")
ONBOARDING_FILES = ("connector.json", "asset.json", "template.snippet.json")


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def _schema_config_requirements(root: Path) -> dict[str, set[str]]:
    """Extract unconditional config requirements from connector schema branches.

    Conditional and any-of requirements remain runtime/schema concerns. This
    cross-file check only prevents the onboarding UI from omitting fields that a
    connector can never satisfy without editing raw JSON.
    """
    schema_path = root / "schema" / "data-connector.schema.json"
    if not schema_path.is_file():
        return {}
    schema = _load_object(schema_path)
    required_by_type: dict[str, set[str]] = {}
    for branch in schema.get("allOf") or []:
        if not isinstance(branch, dict):
            continue
        connector_type = (
            (((branch.get("if") or {}).get("properties") or {}).get("connector_type") or {}).get("const")
        )
        config_schema = (((branch.get("then") or {}).get("properties") or {}).get("config") or {})
        if isinstance(connector_type, str) and isinstance(config_schema, dict):
            required_by_type[connector_type] = set(config_schema.get("required") or [])
    return required_by_type


def _schema_config_properties(root: Path) -> dict[str, set[str]]:
    """Return connector config fields accepted by each closed schema branch."""
    schema_path = root / "schema" / "data-connector.schema.json"
    if not schema_path.is_file():
        return {}
    schema = _load_object(schema_path)
    properties_by_type: dict[str, set[str]] = {}
    for branch in schema.get("allOf") or []:
        if not isinstance(branch, dict):
            continue
        connector_type = (
            (((branch.get("if") or {}).get("properties") or {}).get("connector_type") or {}).get("const")
        )
        config_schema = (((branch.get("then") or {}).get("properties") or {}).get("config") or {})
        properties = config_schema.get("properties") if isinstance(config_schema, dict) else {}
        if isinstance(connector_type, str) and isinstance(properties, dict):
            properties_by_type[connector_type] = set(properties)
    return properties_by_type


def connector_runtime_modes(root: Path) -> dict[str, str]:
    """Load manifest runtime modes for static validation and readiness checks."""
    modes: dict[str, str] = {}
    for name in CATALOG_NAMES:
        path = root / "configure" / name
        if not path.is_file():
            continue
        connectors = _load_object(path).get("connectors") or {}
        if not isinstance(connectors, dict):
            continue
        for connector_type, spec in connectors.items():
            if isinstance(spec, dict):
                modes[str(connector_type)] = str(spec.get("runtime") or "")
    return modes


def _onboarding_source_fields(root: Path) -> set[str]:
    """Return top-level fields accepted by the batch onboarding contract."""
    schema_path = root / "onboarding" / "data-sources.schema.json"
    if not schema_path.is_file():
        return set()
    schema = _load_object(schema_path)
    source = ((schema.get("$defs") or {}).get("source") or {})
    properties = source.get("properties") if isinstance(source, dict) else {}
    return set(properties) if isinstance(properties, dict) else set()


def connector_manifest_errors(root: Path) -> list[str]:
    """Return invariants that JSON Schema cannot express across catalog files.

    Connector runtime metadata and onboarding selection share one manifest entry.
    A type may have one owner only, and its UI fields/defaults must remain aligned
    with an existing onboarding skeleton.
    """
    catalogs: list[tuple[Path, dict[str, Any]]] = []
    for name in CATALOG_NAMES:
        path = root / "configure" / name
        if path.is_file():
            catalogs.append((path, _load_object(path)))

    errors: list[str] = []
    owners: dict[str, Path] = {}
    schema_requirements = _schema_config_requirements(root)
    schema_properties = _schema_config_properties(root)
    onboarding_source_fields = _onboarding_source_fields(root)
    for path, catalog in catalogs:
        connectors = catalog.get("connectors") or {}
        if not isinstance(connectors, dict):
            continue
        for connector_type, spec in connectors.items():
            if connector_type in owners:
                errors.append(
                    f"{path}: connector_type {connector_type!r} 已在 {owners[connector_type]} 定义；"
                    "每个类型只能有一个 manifest 来源"
                )
                continue
            owners[connector_type] = path
            if not isinstance(spec, dict):
                continue

            template_name = str(spec.get("onboarding_template") or "").strip()
            template_dir = root / "onboarding" / template_name
            missing = [filename for filename in ONBOARDING_FILES if not (template_dir / filename).is_file()]
            if missing:
                errors.append(
                    f"{path}: {connector_type}.onboarding_template={template_name!r} "
                    f"缺少三件套文件 {missing!r}"
                )

            profile = spec.get("onboarding_profile") or {}
            fields = set(profile.get("fields") or []) if isinstance(profile, dict) else set()
            required = set(profile.get("required") or []) if isinstance(profile, dict) else set()
            defaults = set((profile.get("defaults") or {}).keys()) if isinstance(profile, dict) else set()
            template_params = set(profile.get("template_params") or []) if isinstance(profile, dict) else set()
            template_defaults = set((profile.get("template_defaults") or {}).keys()) if isinstance(profile, dict) else set()
            if not required <= fields:
                errors.append(
                    f"{path}: {connector_type}.onboarding_profile.required "
                    f"包含未展示字段 {sorted(required - fields)!r}"
                )
            if not defaults <= fields:
                errors.append(
                    f"{path}: {connector_type}.onboarding_profile.defaults "
                    f"包含未展示字段 {sorted(defaults - fields)!r}"
                )
            if not template_defaults <= template_params:
                errors.append(
                    f"{path}: {connector_type}.onboarding_profile.template_defaults "
                    f"包含未声明参数 {sorted(template_defaults - template_params)!r}"
                )
            if onboarding_source_fields and not fields <= onboarding_source_fields:
                errors.append(
                    f"{path}: {connector_type}.onboarding_profile.fields "
                    f"包含 data-sources.schema.json 未支持字段 {sorted(fields - onboarding_source_fields)!r}"
                )
            schema_required = schema_requirements.get(connector_type, set())
            schema_fields = schema_properties.get(connector_type)
            if schema_fields is not None and not fields <= schema_fields:
                errors.append(
                    f"{path}: {connector_type}.onboarding_profile.fields "
                    f"包含 Connector Schema 不接受的配置 {sorted(fields - schema_fields)!r}"
                )
            if not schema_required <= fields:
                errors.append(
                    f"{path}: {connector_type}.onboarding_profile.fields "
                    f"缺少 Connector Schema 必填配置 {sorted(schema_required - fields)!r}"
                )
            if not schema_required <= required:
                errors.append(
                    f"{path}: {connector_type}.onboarding_profile.required "
                    f"缺少 Connector Schema 必填配置 {sorted(schema_required - required)!r}"
                )
    return errors
