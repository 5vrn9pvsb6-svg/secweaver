"""Registry metadata service for the DataAsset UI."""

from __future__ import annotations

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
    TEMPLATES_FILE,
    list_json_objects,
    read_json,
    rel_to_root,
    single_json_object,
)
from .credentials import list_credential_objects


def load_registry() -> dict:
    template_doc: dict = {}
    templates: dict = {}
    if TEMPLATES_FILE.exists():
        template_doc = read_json(TEMPLATES_FILE)
        templates = template_doc.get("templates", {})
    return {
        "dataasset_root": rel_to_root(DATAASSET_DIR),
        "assets": list_json_objects(ASSETS_DIR, "asset_id", EXCLUDED_ASSET_FILES),
        "connectors": list_json_objects(CONNECTORS_DIR, "connector_id"),
        "hosts": list_json_objects(HOSTS_DIR, "host_id"),
        "networks": list_json_objects(NETWORKS_DIR, "network_id"),
        "bundles": list_json_objects(BUNDLES_DIR, "bundle_id"),
        "credentials": list_credential_objects(),
        "correlations": single_json_object(CORRELATION_MATRIX_FILE, "correlation-matrix", "Correlation Matrix", "matrix"),
        "scenarios": single_json_object(SCENARIO_PATTERNS_FILE, "anchor-patterns", "Scenario Patterns", "patterns"),
        "default_templates": template_doc.get("default_templates", {}),
        "templates": [
            {
                "id": template_id,
                "asset_types": value.get("asset_types", []),
                "connector_types": value.get("connector_types", []),
                "params": value.get("params", []),
                "description": value.get("description", ""),
            }
            for template_id, value in sorted(templates.items())
        ],
    }
