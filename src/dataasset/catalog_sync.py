"""Scan dataasset/ and build catalog.json index."""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATAASSET_ROOT = REPO_ROOT / "dataasset"


def resolve_dataasset_root(value: Path | str | None = None) -> Path:
    configured = str(value) if value else os.environ.get("DATAASSET_ROOT")
    if not configured:
        return DEFAULT_DATAASSET_ROOT
    path = Path(configured).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


DATAASSET_ROOT = resolve_dataasset_root()
SPECIAL_ASSET_FILES = {"correlation-matrix.json"}


def scan_catalog(root: Path | None = None) -> dict[str, Any]:
    base = resolve_dataasset_root(root)
    catalog: dict[str, Any] = {
        "version": "1.0",
        "updated": date.today().isoformat(),
        "description": "SecWeaver 数据资产目录索引；由 catalog_sync.py 自动扫描生成",
        "connectors": sorted(
            f"connectors/{p.name}" for p in (base / "connectors").glob("*.json")
        ),
        "assets": sorted(
            f"assets/{p.name}"
            for p in (base / "assets").glob("*.json")
            if p.name not in SPECIAL_ASSET_FILES
        ),
        "correlation_matrix": "assets/correlation-matrix.json",
        "scenario_patterns": "scenarios/anchor-patterns.json",
        "evidence_minimum_fields": "configure/evidence-minimum-fields.json",
        "text_log_parsers": "configure/text-log-parsers.json",
        "hosts": sorted(f"hosts/{p.name}" for p in (base / "hosts").glob("*.json")),
        "networks": sorted(f"networks/{p.name}" for p in (base / "networks").glob("*.json")),
        "bundles": sorted(f"bundles/{p.name}" for p in (base / "bundles").glob("*.json")),
        "query_templates": "query-templates/templates.json",
        "credentials_note": (
            "本地 SOPS Vault：见 credentials/README.md；"
            "connectors 仅 credentials_ref，密钥在本地 secrets/（不进 Git）"
        ),
    }
    return catalog


def load_catalog(root: Path | None = None) -> dict[str, Any]:
    path = resolve_dataasset_root(root) / "catalog.json"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def catalog_drift(existing: dict[str, Any], scanned: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    for key in ("connectors", "assets", "hosts", "networks", "bundles"):
        old = set(existing.get(key) or [])
        new = set(scanned.get(key) or [])
        for path in sorted(new - old):
            issues.append(f"catalog 缺少: {path}")
        for path in sorted(old - new):
            issues.append(f"catalog 多余（文件已删）: {path}")
    return issues


def write_catalog(root: Path | None = None) -> Path:
    base = resolve_dataasset_root(root)
    catalog = scan_catalog(base)
    path = base / "catalog.json"
    path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
