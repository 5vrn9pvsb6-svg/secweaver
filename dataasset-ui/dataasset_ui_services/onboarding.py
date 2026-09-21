"""Data source onboarding services used by the local UI."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .common import (
    ASSETS_DIR,
    CONNECTOR_SCHEMA_FILE,
    DATAASSET_DIR,
    ONBOARDING_SAMPLE_FILE,
    ONBOARDING_SCHEMA_FILE,
    ROOT,
    SECWEAVER_CLI,
    TEXT_LOG_PARSERS_FILE,
    parse_cli_json,
    read_json,
    rel_to_dataasset,
    rel_to_root,
    subprocess_env,
    trim_error_output,
    validation_python,
)
from .credentials import list_credential_objects

from connector_catalog import clear_connector_catalog_cache  # noqa: E402
from connector_catalog import connector_catalog as registry_connector_catalog  # noqa: E402
from connector_registry import clear_connector_registry_cache  # noqa: E402
from connector_registry import connector_types as registry_connector_types  # noqa: E402
from connector_registry import query_key_by_connector as registry_query_key_by_connector  # noqa: E402
from connector_registry import onboarding_profiles as registry_onboarding_profiles  # noqa: E402
from connector_registry import runtime_capabilities as registry_runtime_capabilities  # noqa: E402


def onboarding_error_advice(text: str) -> list[dict[str, Any]]:
    lower = text.lower()
    card = {
        "priority": "P0",
        "severity": "error",
        "category": "onboarding-config",
        "message": text.splitlines()[0] if text.strip() else "数据源接入配置错误",
        "root_cause": "接入配置不满足 asset apply 的输入契约。",
        "impact": "无法生成 connector、asset 和 query template 三件套。",
        "suggested_fix": "检查 data_sources 中的字段名、必填项、覆盖参数和 connector_type 是否正确。",
        "fix_steps": [
            "先点击「生成配置」确认 configJson 是合法 JSON object。",
            "确认每个 data_sources[] 至少包含 connector_type、asset_type、name。",
            "对照右侧 Connector 能力目录补齐该类型的必填连接字段。",
            "修正后再次点击「预览三件套」。",
        ],
        "owner": "运营",
        "docs": ["dataasset/onboarding/README.zh-CN.md", "docs_user/11-onboarding-ui-walkthrough.zh-CN.md"],
    }
    if "unknown field" in lower or "unknown field(s)" in lower:
        card.update(
            {
                "category": "onboarding-unknown-field",
                "root_cause": "data_sources 中出现了 schema 未支持的字段名，通常是拼写错误或放错层级。",
                "suggested_fix": "把自定义 connector/asset/template 字段放到 connector、asset、template 或 overrides 对象里，不要放在 data_sources 顶层。",
                "fix_steps": [
                    "检查错误中列出的字段名。",
                    "若是 connector.config 字段，放入 `connector.config` 或使用页面已有表单项。",
                    "若是资产字段，放入 `asset` / `asset.schema` / `asset.coverage`。",
                    "若确实需要新增顶层字段，再由开发者扩展 ASSET_INIT_CONFIG_KEYS。",
                ],
            }
        )
    elif "requires connector_type" in lower or "requires asset_type" in lower:
        card.update(
            {
                "category": "onboarding-required-field",
                "root_cause": "data_sources[] 缺少最小必填字段。",
                "suggested_fix": "补齐 connector_type、asset_type 和 name；UI 下拉里已有常见 connector_type。",
                "fix_steps": [
                    "在表单里选择 Connector 类型和 Asset 类型。",
                    "填写数据源名称。",
                    "重新生成配置，确认 data_sources[0] 包含 connector_type 和 asset_type。",
                ],
            }
        )
    elif "refuse to overwrite" in lower:
        card.update(
            {
                "category": "onboarding-overwrite",
                "root_cause": "目标 connector/asset 文件已存在，asset apply 默认拒绝覆盖。",
                "suggested_fix": "确认要覆盖后勾选「覆盖已有文件」，或改用新的 asset_id / connector_id。",
                "fix_steps": [
                    "如果是在修改既有数据源，勾选覆盖。",
                    "如果是在新增数据源，修改 name/asset_id/connector_id 避免冲突。",
                    "覆盖前可先使用预览确认 diff。",
                ],
            }
        )
    elif "invalid json" in lower or "jsondecodeerror" in lower:
        card.update(
            {
                "category": "onboarding-json",
                "root_cause": "配置文本不是合法 JSON。",
                "suggested_fix": "修正逗号、引号、括号和注释；JSON 不支持注释。",
                "fix_steps": [
                    "用「生成配置」从表单重新生成一份合法 JSON。",
                    "手工编辑时避免尾随逗号和单引号。",
                    "再次预览确认。",
                ],
            }
        )
    elif "onboarding template not found" in lower:
        card.update(
            {
                "category": "onboarding-template",
                "root_cause": "Connector manifest 声明的 onboarding_template 不存在或缺少三件套。",
                "suggested_fix": "检查 Connector manifest 的 onboarding_template，并补齐对应目录中的 connector.json、asset.json 和 template.snippet.json。",
                "fix_steps": [
                    "在 connector-catalog.json、external-connectors.json 或插件 plugin.json 中确认 onboarding_template 的值。",
                    "确认 dataasset/onboarding/<onboarding_template>/ 存在且包含完整三件套。",
                    "没有模板时优先复制 external_generic 或 demo plugin 示例。",
                    "重新运行预览。",
                ],
                "owner": "开发 / 高阶运营",
                "docs": ["docs_dev/03-community-add-asset-connector.zh-CN.md", "docs_dev/04-connector-plugins.zh-CN.md"],
            }
        )
    return [card]


def schema_connector_types() -> list[str]:
    if not CONNECTOR_SCHEMA_FILE.exists():
        return []
    try:
        schema = read_json(CONNECTOR_SCHEMA_FILE)
    except Exception:  # noqa: BLE001 - best-effort metadata
        return []
    connector_type = (schema.get("properties") or {}).get("connector_type") if isinstance(schema, dict) else {}
    values = connector_type.get("enum") if isinstance(connector_type, dict) else []
    schema_values = [str(value) for value in values if str(value).strip()] if isinstance(values, list) else []
    return list(dict.fromkeys([*schema_values, *registry_connector_types()]))


def onboarding_connector_types() -> list[str]:
    onboarding_dir = DATAASSET_DIR / "onboarding"
    if not onboarding_dir.exists():
        return []
    return sorted(path.name for path in onboarding_dir.iterdir() if path.is_dir() and (path / "connector.json").exists())


def onboarding_asset_types() -> list[str]:
    values: set[str] = set()
    for directory in (ASSETS_DIR, DATAASSET_DIR / "onboarding"):
        if not directory.exists():
            continue
        paths = directory.rglob("asset.json") if directory.name == "onboarding" else directory.glob("*.json")
        for path in paths:
            try:
                data = read_json(path)
            except Exception:  # noqa: BLE001 - best-effort metadata
                continue
            value = str(data.get("asset_type") or "").strip()
            if value:
                values.add(value)
    values.update({"waf_alert", "web_access_log", "ssh_auth", "db_audit", "asset_inventory"})
    return sorted(values)


def onboarding_text_parsers() -> list[str]:
    values: set[str] = set()
    if TEXT_LOG_PARSERS_FILE.exists():
        try:
            data = read_json(TEXT_LOG_PARSERS_FILE)
            parsers = data.get("parsers") if isinstance(data, dict) else {}
            if isinstance(parsers, dict):
                values.update(str(key) for key in parsers if str(key).strip())
        except Exception:  # noqa: BLE001 - best-effort metadata
            pass
    for directory in (ASSETS_DIR, DATAASSET_DIR / "onboarding"):
        if not directory.exists():
            continue
        paths = directory.rglob("asset.json") if directory.name == "onboarding" else directory.glob("*.json")
        for path in paths:
            try:
                data = read_json(path)
            except Exception:  # noqa: BLE001 - best-effort metadata
                continue
            value = str(data.get("text_parser") or "").strip()
            if value:
                values.add(value)
    values.update({"syslog_auth", "nginx_combined", "json_lines", "json_lines2", "raw_only"})
    return sorted(values)


def connector_runtime_capabilities() -> dict[str, str]:
    return registry_runtime_capabilities()


def connector_query_keys() -> dict[str, str]:
    return registry_query_key_by_connector()


def connector_capability_catalog() -> list[dict[str, Any]]:
    return registry_connector_catalog()


def connector_onboarding_profiles() -> dict[str, Any]:
    """Expose profiles from the same manifests used by fetch dispatch."""
    return registry_onboarding_profiles()


def onboarding_example_configs() -> list[dict[str, Any]]:
    examples_dir = DATAASSET_DIR / "onboarding" / "examples"
    if not examples_dir.exists():
        return []
    examples: list[dict[str, Any]] = []
    for path in sorted(examples_dir.glob("*.json")):
        try:
            data = read_json(path)
        except Exception:  # noqa: BLE001 - best-effort metadata
            continue
        sources = data.get("data_sources") if isinstance(data, dict) else []
        if not isinstance(sources, list):
            sources = []
        connector_types = [
            str(source.get("connector_type"))
            for source in sources
            if isinstance(source, dict) and source.get("connector_type")
        ]
        examples.append(
            {
                "file": rel_to_dataasset(path),
                "name": path.stem.replace("-", " "),
                "connector_types": connector_types,
                "source_count": len(sources),
                "data": data,
            }
        )
    return examples


def load_onboarding_meta() -> dict[str, Any]:
    schema = read_json(ONBOARDING_SCHEMA_FILE) if ONBOARDING_SCHEMA_FILE.exists() else {}
    sample = read_json(ONBOARDING_SAMPLE_FILE) if ONBOARDING_SAMPLE_FILE.exists() else {"version": "1.0", "data_sources": []}
    generated_types = list(dict.fromkeys([*onboarding_connector_types(), *registry_connector_types()]))
    connector_types = schema_connector_types() or generated_types
    return {
        "dataasset_root": rel_to_root(DATAASSET_DIR),
        "schema": schema,
        "sample": sample,
        "connector_types": connector_types,
        "onboarding_connector_types": generated_types,
        "connector_runtime_capabilities": connector_runtime_capabilities(),
        "connector_query_keys": connector_query_keys(),
        "connector_catalog": connector_capability_catalog(),
        "connector_profiles": connector_onboarding_profiles(),
        "onboarding_examples": onboarding_example_configs(),
        "asset_types": onboarding_asset_types(),
        "text_parsers": onboarding_text_parsers(),
        "credentials": [item for item in list_credential_objects() if item.get("status") != "disabled"],
        "agent_install": {
            "bootstrap_url": os.environ.get(
                "SECWEAVER_AGENT_BOOTSTRAP_URL",
                "https://YOUR_DATA_CLOUD_HOST/secweaver-agent/install.sh",
            ),
            "version": os.environ.get("SECWEAVER_AGENT_VERSION", "0.3.0"),
            "enterprise_id": os.environ.get("SECWEAVER_ENTERPRISE_ID", ""),
            "license_server_url": os.environ.get(
                "SECWEAVER_LICENSE_SERVER_URL",
                "https://sls-proxy.id-net.cn",
            ),
            "enrollment_id": os.environ.get("SECWEAVER_LOGTAIL_ENROLLMENT_ID", ""),
            "aliyun_uid": os.environ.get("SECWEAVER_LOGTAIL_ALIUID", ""),
        },
    }


def refresh_connector_metadata() -> None:
    clear_connector_registry_cache()
    clear_connector_catalog_cache()


def run_onboarding_apply(config: dict[str, Any], *, dry_run: bool, force: bool = False) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("config 必须是 JSON object")
    python_bin = validation_python()
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
        temp_path = Path(handle.name)
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    try:
        cmd = [python_bin, str(SECWEAVER_CLI), "asset", "apply", "-f", str(temp_path)]
        if dry_run:
            cmd.append("--dry-run")
        if force:
            cmd.append("--force")
        result = subprocess.run(cmd, cwd=ROOT, env=subprocess_env(), text=True, capture_output=True, timeout=90, check=False)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass

    parsed = parse_cli_json(result.stdout)
    error = "" if result.returncode == 0 else trim_error_output(result.stdout, result.stderr)
    advice = [] if result.returncode == 0 else onboarding_error_advice(error)
    return {
        "ok": result.returncode == 0,
        "mode": "dry-run" if dry_run else "apply",
        "returncode": result.returncode,
        "python": python_bin,
        "command": " ".join(cmd),
        "data": parsed,
        "output": (result.stdout or "") + (result.stderr or ""),
        "error": error,
        "advice": advice,
        "diagnostics": {
            "category_count": len({item.get("category") for item in advice}),
            "categories": [
                {
                    "category": item.get("category"),
                    "error_count": 1,
                    "warning_count": 0,
                    "blocking_count": 1,
                }
                for item in advice
            ],
        },
    }
