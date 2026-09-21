"""DataAsset object CRUD services for the local UI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from dataasset import validate as registry_validator
from dataasset.registry_write import registry_write_lock
from dataasset.validate_lib.diagnostics import Report

from .common import (
    ASSETS_DIR,
    BUNDLES_DIR,
    CONNECTORS_DIR,
    CORRELATION_MATRIX_FILE,
    DATAASSET_DIR,
    EXCLUDED_ASSET_FILES,
    HOSTS_DIR,
    NETWORKS_DIR,
    SCENARIO_PATTERNS_FILE,
    delete_json,
    read_json,
    rel_to_root,
    safe_child,
    write_json,
)
from .credentials import delete_credential, load_credential_detail, save_credential

CRUD_OBJECTS = {
    "asset": {
        "directory": ASSETS_DIR,
        "id_key": "asset_id",
        "payload_key": "asset",
        "label": "资产",
        "excluded_files": EXCLUDED_ASSET_FILES,
    },
    "connector": {
        "directory": CONNECTORS_DIR,
        "id_key": "connector_id",
        "payload_key": "connector",
        "label": "Connector",
        "excluded_files": set(),
    },
    "host": {
        "directory": HOSTS_DIR,
        "id_key": "host_id",
        "payload_key": "host",
        "label": "主机",
        "excluded_files": set(),
    },
    "network": {
        "directory": NETWORKS_DIR,
        "id_key": "network_id",
        "payload_key": "network",
        "label": "网络",
        "excluded_files": set(),
    },
    "bundle": {
        "directory": BUNDLES_DIR,
        "id_key": "bundle_id",
        "payload_key": "bundle",
        "label": "Bundle",
        "excluded_files": set(),
    },
    "credential": {
        "label": "Credentials",
        "yaml_resource": True,
    },
    "correlation": {
        "file": CORRELATION_MATRIX_FILE,
        "id": "correlation-matrix",
        "label": "Correlation Matrix",
        "global_singleton": True,
    },
    "scenario": {
        "file": SCENARIO_PATTERNS_FILE,
        "id": "anchor-patterns",
        "label": "Scenario Pattern",
        "global_singleton": True,
    },
}

SCHEMAS = {
    "asset": "data-asset.schema.json",
    "connector": "data-connector.schema.json",
    "host": "data-host.schema.json",
    "network": "data-network.schema.json",
    "bundle": "data-bundle.schema.json",
    "correlation": "correlation-matrix.schema.json",
    "scenario": "anchor-patterns.schema.json",
}


def validate_object_before_save(kind: str, path: Path, payload: dict) -> None:
    """Use the registry's own schema and active-reference rules before commit.

    Draft objects may be prepared incrementally, but active objects must have
    usable references at the moment the Studio makes them visible to Skills.
    """
    schema_path = DATAASSET_DIR / "schema" / SCHEMAS[kind]
    schema = read_json(schema_path)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        field = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"{kind} schema [{field}]: {error.message}")
    if kind in {"correlation", "scenario"}:
        return

    report = Report()
    active = payload.get("status") == "active"
    if kind == "connector" and active:
        registry_validator.check_connector(report, path, payload, root=DATAASSET_DIR,
                                           credential_statuses=registry_validator.load_credential_statuses(DATAASSET_DIR))
        config = payload.get("config") or {}
        for key in ("sink_connector_id", "host_id"):
            referenced = config.get(key)
            if not referenced:
                continue
            directory = "connectors" if key == "sink_connector_id" else "hosts"
            id_key = "connector_id" if key == "sink_connector_id" else "host_id"
            if referenced not in registry_validator.load_all(DATAASSET_DIR / directory, id_key):
                report.error(f"{path}: {key} 引用不存在的 {directory} 对象 {referenced!r}")
    elif kind == "asset" and active:
        connectors = registry_validator.load_all(DATAASSET_DIR / "connectors", "connector_id")
        registry_validator.check_asset(
            report, path, payload, connectors,
            read_json(DATAASSET_DIR / "query-templates" / "templates.json"),
            registry_validator.load_hosts(DATAASSET_DIR),
            registry_validator.load_evidence_spec(DATAASSET_DIR),
        )
        for connector_id in registry_validator.resolve_connector_ids(payload):
            if connector_id in connectors and connectors[connector_id][1].get("status") != "active":
                report.error(f"{path}: active 资产引用了非 active Connector {connector_id!r}")
    elif kind == "bundle" and active:
        registry_validator.check_bundle(
            report, path, payload,
            registry_validator.load_all(DATAASSET_DIR / "assets", "asset_id",
                                        skip_filenames=registry_validator.SPECIAL_ASSET_FILES),
        )
    elif kind == "host" and active:
        registry_validator.check_host(report, path, payload, registry_validator.load_networks(DATAASSET_DIR))
    elif kind == "network" and active:
        registry_validator.check_network(report, path, payload)

    # Inbound active references matter even when an editor demotes this object.
    # Validate only affected dependents so unrelated draft inventory stays editable.
    if kind == "asset":
        assets = registry_validator.load_all(DATAASSET_DIR / "assets", "asset_id",
                                             skip_filenames=registry_validator.SPECIAL_ASSET_FILES)
        assets[payload["asset_id"]] = (path, payload)
        for bundle_path, bundle in registry_validator.load_all(DATAASSET_DIR / "bundles", "bundle_id").values():
            if bundle.get("status") == "active" and payload["asset_id"] in (bundle.get("asset_ids") or []):
                registry_validator.check_bundle(report, bundle_path, bundle, assets)
    elif kind == "connector":
        connectors = registry_validator.load_all(DATAASSET_DIR / "connectors", "connector_id")
        connectors[payload["connector_id"]] = (path, payload)
        for asset_path, asset in registry_validator.load_all(DATAASSET_DIR / "assets", "asset_id",
                                                             skip_filenames=registry_validator.SPECIAL_ASSET_FILES).values():
            if asset.get("status") != "active" or payload["connector_id"] not in registry_validator.resolve_connector_ids(asset):
                continue
            if not active:
                report.error(f"{asset_path}: active 资产引用了非 active Connector {payload['connector_id']!r}")
                continue
            registry_validator.check_asset(
                report, asset_path, asset, connectors,
                read_json(DATAASSET_DIR / "query-templates" / "templates.json"),
                registry_validator.load_hosts(DATAASSET_DIR),
                registry_validator.load_evidence_spec(DATAASSET_DIR),
            )
    issues = [issue.message for issue in report.issues if issue.severity == "error"]
    if issues:
        raise ValueError("active 对象校验失败: " + "; ".join(issues[:3]))


def load_detail(kind: str, object_id: str) -> tuple[dict, str]:
    object_map = {
        "asset": (ASSETS_DIR, object_id, "asset"),
        "connector": (CONNECTORS_DIR, object_id, "connector"),
        "host": (HOSTS_DIR, object_id, "host"),
        "network": (NETWORKS_DIR, object_id, "network"),
        "bundle": (BUNDLES_DIR, object_id, "bundle"),
    }
    if kind in object_map:
        directory, identifier, label = object_map[kind]
        path = safe_child(directory, identifier)
        if not path.exists():
            raise FileNotFoundError(f"{label} 不存在：{object_id}")
        return read_json(path), path.name
    if kind == "credential":
        return load_credential_detail(object_id)
    if kind == "correlation":
        return read_json(CORRELATION_MATRIX_FILE), rel_to_root(CORRELATION_MATRIX_FILE)
    if kind == "scenario":
        return read_json(SCENARIO_PATTERNS_FILE), rel_to_root(SCENARIO_PATTERNS_FILE)
    raise ValueError(f"未知对象类型：{kind}")


def object_config(kind: str) -> dict[str, Any]:
    config = CRUD_OBJECTS.get(kind)
    if not config:
        raise ValueError(f"未知对象类型：{kind}")
    return config


def save_object(kind: str, payload: dict, *, original_id: str = "") -> tuple[Path, str]:
    """Validate and atomically save a JSON object under the shared CLI lock."""
    config = object_config(kind)
    id_key = "credential_id" if config.get("yaml_resource") else config.get("id_key")
    if original_id and id_key:
        next_id = str(payload.get(id_key) or "").strip()
        if next_id != original_id:
            raise ValueError(f"{id_key} 不支持在编辑时修改；请新建对象后删除旧对象")
    if config.get("yaml_resource"):
        return save_credential(payload)
    if config.get("global_singleton"):
        path = config["file"]
        with registry_write_lock(DATAASSET_DIR):
            validate_object_before_save(kind, path, payload)
            write_json(path, payload)
        return path, config["id"]

    id_key = config["id_key"]
    object_id = str(payload.get(id_key) or "").strip()
    if not object_id:
        raise ValueError(f"{id_key} 不能为空")
    directory = config["directory"]
    path = safe_child(directory, object_id)
    if path.name in config.get("excluded_files", set()):
        raise ValueError(f"{config['label']} 文件不可写：{path.name}")
    with registry_write_lock(DATAASSET_DIR):
        validate_object_before_save(kind, path, payload)
        write_json(path, payload)
    return path, object_id


def delete_object(kind: str, object_id: str) -> Path:
    """Serialize JSON deletion with Studio and CLI saves for the same root."""
    config = object_config(kind)
    if config.get("yaml_resource"):
        return delete_credential(object_id)
    if config.get("global_singleton"):
        raise ValueError(f"{config['label']} 是全局配置，不支持删除")
    path = safe_child(config["directory"], object_id)
    if path.name in config.get("excluded_files", set()):
        raise ValueError(f"{config['label']} 文件不可删除：{path.name}")
    with registry_write_lock(DATAASSET_DIR):
        delete_json(path)
    return path
