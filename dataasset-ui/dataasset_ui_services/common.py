"""Shared context and filesystem helpers for the DataAsset UI server."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
UI_DIR = ROOT / "dataasset-ui"
SRC_DIR = ROOT / "src"
DATA_ACCESS_DIR = ROOT / "src" / "skills" / "_shared" / "data-access"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(DATA_ACCESS_DIR) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_DIR))

from dataasset_paths import DATAASSET_ROOT, format_path as format_repo_path  # noqa: E402
from dataasset.registry_write import write_json_atomic  # noqa: E402

DATAASSET_DIR = DATAASSET_ROOT
PLATFORM_DATAASSET_DIR = ROOT / "dataasset"
ASSETS_DIR = DATAASSET_DIR / "assets"
CONNECTORS_DIR = DATAASSET_DIR / "connectors"
HOSTS_DIR = DATAASSET_DIR / "hosts"
NETWORKS_DIR = DATAASSET_DIR / "networks"
BUNDLES_DIR = DATAASSET_DIR / "bundles"
CREDENTIALS_DIR = DATAASSET_DIR / "credentials"
CORRELATION_MATRIX_FILE = ASSETS_DIR / "correlation-matrix.json"
SCENARIO_PATTERNS_FILE = DATAASSET_DIR / "scenarios" / "anchor-patterns.json"
TEMPLATES_FILE = DATAASSET_DIR / "query-templates" / "templates.json"
VALIDATE_SCRIPT = ROOT / "src" / "dataasset" / "validate.py"
SECWEAVER_CLI = ROOT / "src" / "secweaver.py"
ONBOARDING_SCHEMA_FILE = DATAASSET_DIR / "onboarding" / "data-sources.schema.json"
ONBOARDING_SAMPLE_FILE = DATAASSET_DIR / "onboarding" / "examples" / "data-sources.sample.json"
CONNECTOR_SCHEMA_FILE = DATAASSET_DIR / "schema" / "data-connector.schema.json"
TEXT_LOG_PARSERS_FILE = DATAASSET_DIR / "configure" / "text-log-parsers.json"
REPORTS_DIR = ROOT / "examples" / "reports"
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
EXCLUDED_ASSET_FILES = {"correlation-matrix.json"}


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: dict) -> None:
    write_json_atomic(path, payload)


def rel_to_root(path: Path) -> str:
    return format_repo_path(path)


def rel_to_dataasset(path: Path) -> str:
    return path.relative_to(DATAASSET_DIR).as_posix()


def validation_python() -> str:
    if VENV_PYTHON.exists():
        return str(VENV_PYTHON)
    return sys.executable


def subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env["DATAASSET_ROOT"] = str(DATAASSET_DIR)
    return env


def parse_cli_json(stdout: str) -> Any | None:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def trim_error_output(stdout: str, stderr: str, limit: int = 1200) -> str:
    text = ((stderr or "") + ("\n" if stdout and stderr else "") + (stdout or "")).strip()
    if not text:
        return "命令执行失败，但没有返回错误详情。"
    return text[:limit] + ("\n..." if len(text) > limit else "")


def safe_child(base: Path, name: str, suffix: str = ".json") -> Path:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("非法文件名")
    if not name.endswith(suffix):
        name = f"{name}{suffix}"
    candidate = (base / name).resolve()
    if base.resolve() not in candidate.parents:
        raise ValueError("路径越界")
    return candidate


def delete_json(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"文件不存在：{path.name}")
    if not path.is_file():
        raise ValueError("只能删除文件")
    path.unlink()


def list_json_objects(directory: Path, id_key: str, exclude: set[str] | None = None) -> list[dict]:
    exclude = exclude or set()
    items: list[dict] = []
    if not directory.exists():
        return items
    for path in sorted(directory.glob("*.json")):
        if path.name in exclude:
            continue
        try:
            data = read_json(path)
        except Exception as exc:  # noqa: BLE001 - return partial registry plus error marker
            items.append({"file": path.name, "error": str(exc)})
            continue
        exposure = data.get("exposure") if isinstance(data.get("exposure"), dict) else {}
        items.append(
            {
                "file": path.name,
                "id": data.get(id_key),
                "name": data.get("name"),
                "type": data.get("asset_type") or data.get("connector_type") or data.get("host_type") or data.get("network_type") or "bundle",
                "status": data.get("status"),
                "environment": data.get("environment"),
                "domain": data.get("domain"),
                "connector_id": data.get("connector_id"),
                "owner_team": data.get("owner_team"),
                "host_os": data.get("host_os"),
                "host_ip": data.get("host_ip"),
                "network_id": data.get("network_id"),
                "cidr": data.get("cidr"),
                "gateway_ip": data.get("gateway_ip"),
                "internet_exposed": data.get("internet_exposed", exposure.get("internet_exposed")),
                "internet_ip": exposure.get("internet_ip"),
                "exposed_ports": exposure.get("exposed_ports"),
                "tags": data.get("tags"),
            }
        )
    return items


def single_json_object(path: Path, object_id: str, name: str, object_type: str) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = read_json(path)
    except Exception as exc:  # noqa: BLE001 - return error marker for UI
        return [{"file": path.name, "id": object_id, "name": name, "type": object_type, "error": str(exc)}]
    return [
        {
            "file": path.name,
            "id": object_id,
            "name": data.get("description") or name,
            "type": object_type,
            "status": data.get("version", "active"),
            "environment": "global",
        }
    ]
