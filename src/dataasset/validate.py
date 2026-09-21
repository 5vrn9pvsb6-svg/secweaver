#!/usr/bin/env python3
"""Validate dataasset/ registry: references, templates, credentials, bundles."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATAASSET_ROOT = REPO_ROOT / "dataasset"
SCRIPTS_ROOT = Path(__file__).resolve().parent
DATA_ACCESS = REPO_ROOT / "src/skills/_shared/data-access"


def resolve_dataasset_root(value: Path | str | None = None) -> Path:
    configured = str(value) if value else os.environ.get("DATAASSET_ROOT")
    if not configured:
        return DEFAULT_DATAASSET_ROOT
    path = Path(configured).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


DATAASSET_ROOT = resolve_dataasset_root()

if str(DATA_ACCESS) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS))
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from catalog_sync import catalog_drift, load_catalog, scan_catalog, write_catalog  # noqa: E402
from aggregate import resolve_connector_ids  # noqa: E402
from field_inventory import effective_fields  # noqa: E402
from sls_proxy_config import proxy_project  # noqa: E402
from connector_registry import query_key_by_connector  # noqa: E402
from template_select import (  # noqa: E402
    connector_supports_template,
    default_template_id_for_asset,
    select_template_for_asset,
)
from validate_lib.diagnostics import (  # noqa: E402
    DEFAULT_FIX,
    DEFAULT_IMPACT,
    DEFAULT_OWNER,
    Issue,
    Report,
    diagnose_issue,
    summarize_diagnostics,
)
from credential_contracts import (  # noqa: E402
    VAULT_REF_PATTERN,
    credential_secret_path,
    load_credential_status_file,
    normalize_credentials_ref,
    validate_credentials_ref,
)
from transport_contracts import resolve_ca_file, validate_secure_endpoint  # noqa: E402
from validate_lib.connector_contracts import connector_manifest_errors, connector_runtime_modes  # noqa: E402
from validate_lib.inventory_contracts import (  # noqa: E402
    check_host_contract,
    check_network_contract,
    parse_ip as _parse_ip,
)
from validate_lib.runtime_readiness import assess_runtime_readiness  # noqa: E402

VAULT_REF = VAULT_REF_PATTERN
SCENARIO_IDS = {f"S{i}" for i in range(1, 9)}
SPECIAL_ASSET_FILES = {"correlation-matrix.json"}
PROGRAM_SUFFIXES = {
    ".bash",
    ".class",
    ".cjs",
    ".dll",
    ".dylib",
    ".exe",
    ".fish",
    ".go",
    ".jar",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".php",
    ".pl",
    ".py",
    ".pyc",
    ".pyo",
    ".rb",
    ".rs",
    ".sh",
    ".so",
    ".ts",
    ".tsx",
    ".zsh",
}


def sls_proxy_endpoint_is_secure(endpoint: str) -> bool:
    try:
        validate_secure_endpoint(endpoint, label="sls_proxy endpoint")
        return True
    except ValueError:
        return False


PROGRAM_FILENAMES = {"Dockerfile", "Makefile"}


def normalize_vault_ref(ref: str) -> str:
    """Compatibility alias for callers that still import the validator helper."""
    return normalize_credentials_ref(ref)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def check_config_only_layout(report: Report, root: Path) -> None:
    """Reject runtime code copied into an operator-owned asset registry."""
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        is_program = path.suffix.lower() in PROGRAM_SUFFIXES or path.name in PROGRAM_FILENAMES
        is_executable = bool(path.stat().st_mode & 0o111)
        if not is_program and not is_executable:
            continue
        report.error(
            f"{path}: 资产目录只能保存配置、Schema、文档和样本数据；程序必须放在 src/dataasset/ 或独立插件目录",
            code="dataasset-program-file",
            object_type="registry",
            path=path,
            suggested_fix="将程序迁移到 src/dataasset/；第三方插件代码通过 SECWEAVER_PLUGIN_ROOT 指向资产目录外的位置。",
        )


def load_credential_statuses(root: Path | None = None) -> dict[str, str]:
    path = (root or DATAASSET_ROOT) / "credentials" / "credential-status.json"
    return load_credential_status_file(path)


def load_all(
    directory: Path,
    id_key: str,
    *,
    skip_filenames: set[str] | None = None,
) -> dict[str, tuple[Path, dict[str, Any]]]:
    items: dict[str, tuple[Path, dict[str, Any]]] = {}
    if not directory.is_dir():
        return items
    skipped = skip_filenames or set()
    for path in sorted(directory.glob("*.json")):
        if path.name in skipped:
            continue
        data = load_json(path)
        item_id = data.get(id_key, path.stem)
        items[item_id] = (path, data)
    return items


def annotate_object_issues(
    report: Report,
    start: int,
    *,
    object_type: str,
    object_id: str,
    path: Path,
) -> None:
    """Attach checker output to its registry object for downstream readiness.

    Older check helpers report human-readable messages without structured object
    metadata. The validation loop owns the object being checked, so it can add
    that metadata without parsing paths back out of localized messages.
    """
    for issue in report.issues[start:]:
        if issue.object_type == "unknown":
            issue.object_type = object_type
        if not issue.object_id:
            issue.object_id = object_id
        if not issue.path:
            issue.path = str(path)


def load_hosts(root: Path | None = None) -> dict[str, tuple[Path, dict[str, Any]]]:
    hosts_dir = (root or DATAASSET_ROOT) / "hosts"
    return load_all(hosts_dir, "host_id")


def load_networks(root: Path | None = None) -> dict[str, tuple[Path, dict[str, Any]]]:
    networks_dir = (root or DATAASSET_ROOT) / "networks"
    return load_all(networks_dir, "network_id")


def check_network(report: Report, path: Path, data: dict[str, Any]) -> None:
    check_id_matches_filename(report, path, data, "network_id")
    check_json_schema(report, path, data, registry_root_for(path) / "schema" / "data-network.schema.json")
    check_network_contract(report, path, data)


def check_host(
    report: Report,
    path: Path,
    data: dict[str, Any],
    networks: dict[str, tuple[Path, dict[str, Any]]] | None = None,
) -> None:
    check_id_matches_filename(report, path, data, "host_id")
    check_json_schema(report, path, data, registry_root_for(path) / "schema" / "data-host.schema.json")
    check_host_contract(report, path, data, networks)


def _canonical_field_names(asset: dict[str, Any]) -> set[str]:
    try:
        return set(effective_fields(asset))
    except Exception:  # noqa: BLE001 - validate should still report other issues
        schema = asset.get("schema") or {}
        names = {str(f) for f in schema.get("fields") or []}
        aliases = asset.get("field_aliases") or {}
        if isinstance(aliases, dict):
            names.update(str(v) for v in aliases.values())
        schema_aliases = schema.get("field_aliases") or {}
        if isinstance(schema_aliases, dict):
            names.update(str(v) for v in schema_aliases.values())
        return names


def load_evidence_spec(root: Path) -> dict[str, Any]:
    path = root / "configure" / "evidence-minimum-fields.json"
    if not path.is_file():
        return {}
    return load_json(path)


def evidence_required_fields(spec: dict[str, Any], asset_type: str | None) -> set[str]:
    if not asset_type:
        return set()
    meta = (spec.get("by_asset_type") or {}).get(asset_type) or {}
    return {str(f) for f in meta.get("required") or []}


def evidence_strong_fields(spec: dict[str, Any], asset_type: str | None) -> set[str]:
    if not asset_type:
        return set()
    meta = (spec.get("by_asset_type") or {}).get(asset_type) or {}
    return {str(f) for f in meta.get("strongly_recommended") or []}


def check_active_evidence_fields(
    report: Report,
    path: Path,
    asset: dict[str, Any],
    evidence_spec: dict[str, Any],
) -> None:
    if asset.get("status") != "active" or not evidence_spec:
        return
    asset_type = asset.get("asset_type")
    available = _canonical_field_names(asset)
    required = evidence_required_fields(evidence_spec, asset_type)
    if not required:
        report.warn(f"{path}: active 资产类型 {asset_type!r} 未在 evidence-minimum-fields.json 登记最小字段")
        return
    missing = sorted(required - available)
    if missing:
        report.error(
            f"{path}: active 资产缺少 evidence 必需字段 {missing!r}；"
            "请补 schema.fields 或 field_aliases，确保 Skill 能读取 canonical 字段"
        )
    strong_missing = sorted(evidence_strong_fields(evidence_spec, asset_type) - available)
    if strong_missing:
        report.warn(f"{path}: active 资产缺少强建议字段 {strong_missing!r}，可能降低研判可信度")


def check_active_asset_gate(report: Report, path: Path, asset: dict[str, Any]) -> None:
    if asset.get("status") != "active":
        return
    schema = asset.get("schema") or {}
    fields = schema.get("fields") or []
    time_field = schema.get("time_field")
    retention_days = schema.get("retention_days")
    if not fields:
        report.error(f"{path}: active 资产 schema.fields 不能为空")
    if time_field and fields and time_field not in fields and time_field not in _canonical_field_names(asset):
        report.error(f"{path}: active 资产 time_field={time_field!r} 不在 fields/aliases 可用字段中")
    if not isinstance(retention_days, int) or retention_days <= 0:
        report.error(f"{path}: active 资产 schema.retention_days 必须为正整数")
    if not asset.get("owner_team"):
        report.error(f"{path}: active 资产必须填写 owner_team，便于上线责任归属")
    if not asset.get("description"):
        report.warn(f"{path}: active 资产建议填写 description，便于运营理解用途")


def check_asset_coverage_hosts(report: Report, path: Path, asset: dict[str, Any]) -> None:
    coverage_hosts = (asset.get("coverage") or {}).get("hosts") or []
    for idx, value in enumerate(coverage_hosts):
        if _parse_ip(value) is None:
            report.warn(
                f"{path}: coverage.hosts[{idx}]={value!r} 不是 IP；coverage.hosts 只允许填写日志来源 IP，不填写 hostname/aliases",
                code="asset-coverage-host-not-ip",
                object_type="asset",
                object_id=str(asset.get("asset_id") or ""),
                path=path,
                field=f"coverage.hosts[{idx}]",
                suggested_fix="将该值替换为实际日志来源 IP；主机别名、历史名、FQDN 或日志 host_name 值请写入 host.aliases。",
            )


def check_connector_host_refs(
    report: Report,
    path: Path,
    data: dict[str, Any],
    hosts: dict[str, tuple[Path, dict[str, Any]]],
    connectors: dict[str, tuple[Path, dict]],
) -> None:
    for connector_id in set(resolve_connector_ids(data)):
        if connector_id not in connectors:
            continue
        _, connector = connectors[connector_id]
        cfg_host_id = (connector.get("config") or {}).get("host_id")
        if cfg_host_id and cfg_host_id not in hosts:
            report.error(f"{path}: connector {connector_id} config.host_id 引用未知主机 {cfg_host_id!r}")


def check_id_matches_filename(report: Report, path: Path, data: dict[str, Any], id_key: str) -> None:
    expected = path.stem
    actual = data.get(id_key)
    if actual != expected:
        report.error(f"{path}: {id_key}={actual!r} 与文件名 {expected} 不一致")


def registry_root_for(path: Path) -> Path:
    """Return the registry root for an object stored one directory below it.

    Validation may target an explicit temporary or private root. Deriving sibling
    Schema and credential paths from the object prevents that validation from
    mutating the process-wide DATAASSET_ROOT used by unrelated runtime modules.
    """
    return path.parent.parent


def check_json_schema(
    report: Report,
    path: Path,
    data: dict[str, Any],
    schema_path: Path,
) -> None:
    if not schema_path.is_file():
        report.warn(f"缺少 schema 文件 {schema_path.as_posix()}")
        return
    try:
        import jsonschema
    except ImportError:
        if not getattr(report, "_jsonschema_missing_warned", False):
            report.warn(
                "未安装 jsonschema，跳过 JSON Schema 校验（pip install jsonschema）",
                code="jsonschema-missing",
                object_type="validator",
                owner="开发者",
                impact="本次校验会跳过 JSON Schema 结构检查，但仍会执行内置引用、状态和字段规则。",
                suggested_fix="运行 `python3 -m pip install -r requirements-data-access.txt` 或 `make setup` 后重新执行 validate。",
            )
            setattr(report, "_jsonschema_missing_warned", True)
        return
    schema = load_json(schema_path)
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    for err in errors[:3]:
        loc = ".".join(str(p) for p in err.path) or "(root)"
        report.error(f"{path}: schema [{loc}]: {err.message}")


def check_catalog(report: Report, root: Path) -> None:
    catalog_path = root / "catalog.json"
    if not catalog_path.is_file():
        report.warn(f"缺少 {catalog_path.relative_to(root).as_posix()}，运行 validate.py --sync-catalog")
        return
    existing = load_catalog(root)
    scanned = scan_catalog(root)
    for issue in catalog_drift(existing, scanned):
        report.warn(f"catalog.json: {issue}")


def asset_types_with_fields(
    assets: dict[str, tuple[Path, dict[str, Any]]],
) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for _, asset in assets.values():
        asset_type = asset.get("asset_type")
        if not asset_type:
            continue
        mapping.setdefault(str(asset_type), set()).update(_canonical_field_names(asset))
    return mapping


def check_correlation_matrix(
    report: Report,
    root: Path,
    assets: dict[str, tuple[Path, dict[str, Any]]] | None = None,
) -> None:
    path = root / "assets" / "correlation-matrix.json"
    if not path.is_file():
        report.error(f"缺少 {path}")
        return

    try:
        matrix = load_json(path)
    except json.JSONDecodeError as exc:
        report.error(f"{path}: JSON 解析失败: {exc}")
        return

    check_json_schema(report, path, matrix, root / "schema" / "correlation-matrix.schema.json")

    if not matrix.get("version"):
        report.error(f"{path}: 缺少 version")
    if matrix.get("fetch_plan_defaults"):
        report.warn(f"{path}: fetch_plan_defaults 已移除；需要取数的 Join 请在 fetch_plan.left/right 显式声明 template_id + param_map")

    evidence_spec_path = root / "configure" / "evidence-minimum-fields.json"
    canonical_fields: set[str] = set()
    if evidence_spec_path.is_file():
        spec = load_json(evidence_spec_path)
        for meta in (spec.get("by_asset_type") or {}).values():
            canonical_fields.update(str(f) for f in meta.get("required") or [])
            canonical_fields.update(str(f) for f in meta.get("strongly_recommended") or [])
            canonical_fields.update(str(f) for f in meta.get("recommended") or [])
        canonical_fields.update(str(v) for v in (spec.get("field_aliases") or {}).values())
        canonical_fields.update(str(f) for f in spec.get("common_required") or [])
    else:
        report.warn(f"{path}: 未找到 evidence-minimum-fields.json，跳过 canonical key 参考校验")

    asset_type_fields = asset_types_with_fields(assets or {})

    time_windows = matrix.get("time_windows")
    if not isinstance(time_windows, dict) or not time_windows:
        report.error(f"{path}: time_windows 必须为非空 object")
        time_windows = {}

    joins: list[tuple[str, dict[str, Any]]] = []
    for section in ("cross_source_joins", "internal_joins"):
        raw = matrix.get(section, [])
        if raw is None:
            continue
        if not isinstance(raw, list):
            report.error(f"{path}: {section} 必须为 array")
            continue
        for item in raw:
            if not isinstance(item, dict):
                report.error(f"{path}: {section} 中存在非 object 项")
                continue
            joins.append((section, item))

    if not joins:
        report.warn(f"{path}: 未声明 cross_source_joins / internal_joins")

    join_priorities: dict[int, list[str]] = {}
    for section, join in joins:
        join_id = join.get("id") or "<unknown>"
        from_type = join.get("from_asset_type")
        to_type = join.get("to_asset_type")
        priority = join.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool) or not (1 <= priority <= 100):
            report.error(f"{path}: {section}.{join_id}.priority 必须为 1-100 的整数；数值越高越优先展示/执行")
        else:
            join_priorities.setdefault(priority, []).append(str(join_id))
        confidence = join.get("confidence")
        if not isinstance(confidence, dict):
            report.error(f"{path}: {section}.{join_id}.confidence 必须为 object，包含 base/max/reason")
        else:
            base = confidence.get("base")
            max_value = confidence.get("max")
            increment = confidence.get("optional_key_increment", 0.05)
            reason = str(confidence.get("reason") or "").strip()
            for field_name, value in (("base", base), ("max", max_value), ("optional_key_increment", increment)):
                if not isinstance(value, (int, float)) or isinstance(value, bool) or not (0 <= float(value) <= 1):
                    report.error(f"{path}: {section}.{join_id}.confidence.{field_name} 必须为 0-1 数字")
            if isinstance(base, (int, float)) and isinstance(max_value, (int, float)) and not isinstance(base, bool) and not isinstance(max_value, bool):
                if float(base) > float(max_value):
                    report.error(f"{path}: {section}.{join_id}.confidence.base 不得大于 confidence.max")
            if not reason:
                report.error(f"{path}: {section}.{join_id}.confidence.reason 必须说明可信度来源，便于安全运营审计")
        if not from_type or not to_type:
            report.error(f"{path}: {section}.{join_id} 缺少 from_asset_type/to_asset_type")
        else:
            if asset_type_fields and from_type not in asset_type_fields:
                report.warn(f"{path}: {section}.{join_id} from_asset_type={from_type!r} 当前没有注册资产，Join 暂不可用")
            if asset_type_fields and to_type not in asset_type_fields:
                report.warn(f"{path}: {section}.{join_id} to_asset_type={to_type!r} 当前没有注册资产，Join 暂不可用")

        join_keys = join.get("join_keys")
        if not isinstance(join_keys, list) or not join_keys:
            if join.get("path"):
                join_keys = []
            else:
                report.error(f"{path}: {section}.{join_id} join_keys 必须为非空 array")
                continue

        for idx, key_spec in enumerate(join_keys):
            if not isinstance(key_spec, dict):
                report.error(f"{path}: {section}.{join_id}.join_keys[{idx}] 必须为 object")
                continue
            left_key = key_spec.get("left")
            right_key = key_spec.get("right")
            if not left_key or not right_key:
                report.error(f"{path}: {section}.{join_id}.join_keys[{idx}] 缺少 left/right")
                continue
            for side, key, asset_type in (("left", left_key, from_type), ("right", right_key, to_type)):
                variants = [str(v) for v in key_spec.get(f"{side}_variants") or []]
                candidates = {str(key), *variants}
                if canonical_fields and key not in canonical_fields and not variants:
                    report.warn(
                        f"{path}: {section}.{join_id}.join_keys[{idx}] 使用 evidence 规范未登记字段；"
                        f"若为源字段请补 {side}_variants 或 field_aliases {key!r}"
                    )
                available = asset_type_fields.get(str(asset_type), set()) if asset_type else set()
                if available and candidates.isdisjoint(available):
                    msg = (
                        f"{path}: {section}.{join_id}.join_keys[{idx}].{side}={key!r} "
                        f"在 asset_type={asset_type!r} 的已注册字段/别名中不可达；"
                        "请补 schema.fields、field_aliases 或 join variants"
                    )
                    if key_spec.get("optional"):
                        report.warn(msg)
                    else:
                        report.error(msg)
            match = key_spec.get("match")
            if match and match not in {"exact", "path_prefix", "cidr_contains", "session_5tuple", "hostname_to_ip_via_cmdb", "dns_answer_ip"}:
                report.warn(f"{path}: {section}.{join_id}.join_keys[{idx}] 未知 match 类型 {match!r}")

        for extra_key_name in ("secondary_keys",):
            extra_keys = join.get(extra_key_name) or []
            if not isinstance(extra_keys, list):
                report.error(f"{path}: {section}.{join_id}.{extra_key_name} 必须为 array")
                continue
            for idx, key_spec in enumerate(extra_keys):
                if not isinstance(key_spec, dict):
                    report.error(f"{path}: {section}.{join_id}.{extra_key_name}[{idx}] 必须为 object")
                    continue
                for side, key, asset_type in (("left", key_spec.get("left"), from_type), ("right", key_spec.get("right"), to_type)):
                    if canonical_fields and key and key not in canonical_fields:
                        report.warn(
                            f"{path}: {section}.{join_id}.{extra_key_name}[{idx}] 使用 evidence 规范未登记字段；"
                            f"若为源字段请确认 alias/variants 可解析 {key!r}"
                        )
                    variants = [str(v) for v in key_spec.get(f"{side}_variants") or []]
                    candidates = {str(key), *variants} if key else set(variants)
                    available = asset_type_fields.get(str(asset_type), set()) if asset_type else set()
                    if key and available and candidates.isdisjoint(available):
                        report.warn(
                            f"{path}: {section}.{join_id}.{extra_key_name}[{idx}].{side}={key!r} "
                            f"在 asset_type={asset_type!r} 的已注册字段/别名中不可达"
                        )
                match = key_spec.get("match")
                if match and match not in {"exact", "path_prefix", "cidr_contains", "session_5tuple", "hostname_to_ip_via_cmdb", "dns_answer_ip"}:
                    report.warn(f"{path}: {section}.{join_id}.{extra_key_name}[{idx}] 未知 match 类型 {match!r}")

        tw = join.get("time_window")
        if tw and tw not in time_windows:
            report.error(f"{path}: {section}.{join_id} 引用未知 time_window {tw!r}")

        fetch_plan = join.get("fetch_plan") or {}
        if fetch_plan and not isinstance(fetch_plan, dict):
            report.error(f"{path}: {section}.{join_id}.fetch_plan 必须为 object")
        elif isinstance(fetch_plan, dict):
            for side in ("left", "right"):
                side_spec = fetch_plan.get(side)
                if side_spec is None:
                    continue
                if not isinstance(side_spec, dict):
                    report.error(f"{path}: {section}.{join_id}.fetch_plan.{side} 必须为 object")
                    continue
                if not side_spec.get("template_id"):
                    report.error(
                        f"{path}: {section}.{join_id}.fetch_plan.{side} 必须显式声明 template_id；"
                        "fetch_plan_defaults 已移除"
                    )
                param_map = side_spec.get("param_map") or {}
                if param_map and not isinstance(param_map, dict):
                    report.error(f"{path}: {section}.{join_id}.fetch_plan.{side}.param_map 必须为 object")

    for priority, ids in sorted(join_priorities.items(), reverse=True):
        if len(ids) > 3:
            report.warn(
                f"{path}: priority={priority} 被 {len(ids)} 个 Join 共用（{', '.join(ids[:5])}）；"
                "建议拆分优先级，便于 UI 和运行时解释排序"
            )

    check_anchor_patterns(report, root, time_windows, joins, assets or {}, load_all(root / "bundles", "bundle_id"))


def _scenario_id_from_pattern_id(pattern_id: str) -> str | None:
    match = re.match(r"^(S[1-8])(?:_|$)", str(pattern_id))
    return match.group(1) if match else None


def _join_asset_types(
    join_id: str,
    join_by_id: dict[str, dict[str, Any]],
    *,
    seen: set[str] | None = None,
) -> set[str]:
    seen = seen or set()
    if join_id in seen:
        return set()
    seen.add(join_id)
    join = join_by_id.get(join_id)
    if not join:
        return set()
    types: set[str] = set()
    path = join.get("path") or []
    if isinstance(path, list) and path:
        for step in path:
            types.update(_join_asset_types(str(step), join_by_id, seen=seen))
        return types
    for key in ("from_asset_type", "to_asset_type"):
        value = join.get(key)
        if value:
            types.add(str(value))
    return types


def _bundle_asset_types(
    bundle: dict[str, Any],
    assets: dict[str, tuple[Path, dict[str, Any]]],
    *,
    hosts: dict[str, tuple[Path, dict[str, Any]]] | None = None,
) -> set[str]:
    types: set[str] = set()
    for asset_id in bundle.get("asset_ids") or []:
        item = assets.get(str(asset_id))
        if not item:
            continue
        _, asset = item
        asset_type = asset.get("asset_type")
        if asset_type:
            types.add(str(asset_type))
        for covered in asset.get("covers_asset_types") or []:
            covered_type = str(covered)
            if covered_type == str(asset_type):
                continue
            types.add(covered_type)
    registry_covers = bundle.get("registry_covers_asset_types") or []
    if registry_covers and hosts:
        if any(h.get("status") != "disabled" for _, h in hosts.values()):
            types.update(str(t) for t in registry_covers)
    return types


def check_anchor_patterns(
    report: Report,
    root: Path,
    time_windows: dict[str, Any],
    joins: list[tuple[str, dict[str, Any]]],
    assets: dict[str, tuple[Path, dict[str, Any]]],
    bundles: dict[str, tuple[Path, dict[str, Any]]],
) -> None:
    path = root / "scenarios" / "anchor-patterns.json"
    legacy_path = root / "assets" / "correlation-matrix.json"
    if not path.is_file():
        report.warn(f"{path}: 未找到场景编排配置，跳过 anchor pattern 校验")
        return

    try:
        data = load_json(path)
    except json.JSONDecodeError as exc:
        report.error(f"{path}: JSON 解析失败: {exc}")
        return

    check_json_schema(report, path, data, root / "schema" / "anchor-patterns.schema.json")

    patterns = data.get("patterns") or {}
    join_by_id = {str(join.get("id")): join for _, join in joins if join.get("id")}
    join_ids = set(join_by_id)
    hosts = load_hosts(root)
    known_asset_types = {str(asset.get("asset_type")) for _, asset in assets.values() if asset.get("asset_type")}
    evidence_spec = load_evidence_spec(root)
    canonical_fields: set[str] = set()
    for meta in (evidence_spec.get("by_asset_type") or {}).values():
        canonical_fields.update(str(f) for key in ("required", "strongly_recommended", "recommended") for f in meta.get(key) or [])
    canonical_fields.update(str(v) for v in (evidence_spec.get("field_aliases") or {}).values())
    canonical_fields.update(str(f) for f in evidence_spec.get("common_required") or [])
    if not isinstance(patterns, dict):
        report.error(f"{path}: patterns 必须为 object")
        return

    for pid, pattern in patterns.items():
        field_prefix = f"patterns.{pid}"
        if not isinstance(pattern, dict):
            report.error(f"{path}: {field_prefix} 必须为 object")
            continue

        scenario_id = _scenario_id_from_pattern_id(str(pid))
        if not scenario_id:
            report.warn(f"{path}: {field_prefix} 无法从 pattern_id 推导 S1-S8 场景编号")

        anchor = pattern.get("anchor") or {}
        if anchor:
            if not isinstance(anchor, dict):
                report.error(f"{path}: {field_prefix}.anchor 必须为 object")
            else:
                anchor_field = anchor.get("field")
                if canonical_fields and anchor_field and str(anchor_field) not in canonical_fields:
                    variants = {str(v) for v in anchor.get("field_variants") or []}
                    if variants.isdisjoint(canonical_fields):
                        report.warn(
                            f"{path}: {field_prefix}.anchor.field={anchor_field!r} 未在 evidence canonical 字段中登记；"
                            "请确认 anchor 字段能从 evidence 或 params 推导"
                        )
                anchor_from = anchor.get("from")
                if anchor_from and not (str(anchor_from).startswith("params.") or str(anchor_from) in known_asset_types):
                    report.warn(
                        f"{path}: {field_prefix}.anchor.from={anchor_from!r} 不符合 params.* 或 asset_type 约定"
                    )

        inv_window = pattern.get("investigation_window")
        if inv_window and inv_window not in time_windows:
            report.error(f"{path}: {field_prefix} 引用未知 investigation_window {inv_window!r}")

        chain = pattern.get("recommended_chain") or []
        required_asset_types: set[str] = set()
        if not isinstance(chain, list):
            report.error(f"{path}: {field_prefix}.recommended_chain 必须为 array")
        else:
            for join_id in chain:
                join_id_text = str(join_id)
                if join_id_text not in join_ids:
                    report.error(f"{path}: {field_prefix}.recommended_chain 引用未知 Join {join_id!r}")
                    continue
                required_asset_types.update(_join_asset_types(join_id_text, join_by_id))
                join_scenarios = {str(s) for s in join_by_id[join_id_text].get("scenarios") or []}
                if scenario_id and join_scenarios and scenario_id not in join_scenarios:
                    report.warn(
                        f"{path}: {field_prefix}.recommended_chain 包含 Join {join_id_text!r}，"
                        f"但该 Join.scenarios 未声明 {scenario_id!r}"
                    )

        for layer_key in ("layer1_assets", "layer2_assets"):
            layer_assets = pattern.get(layer_key) or []
            if not layer_assets:
                continue
            if not isinstance(layer_assets, list):
                report.error(f"{path}: {field_prefix}.{layer_key} 必须为 array")
                continue
            for asset_type in layer_assets:
                if known_asset_types and str(asset_type) not in known_asset_types:
                    report.warn(f"{path}: {field_prefix}.{layer_key} 包含当前未注册 asset_type {asset_type!r}")
            required_asset_types.update(str(asset_type) for asset_type in layer_assets)

        fallback_asset_types = ((pattern.get("anchor") or {}).get("fallback_asset_types") or []) if isinstance(pattern.get("anchor") or {}, dict) else []
        if fallback_asset_types:
            if not isinstance(fallback_asset_types, list):
                report.error(f"{path}: {field_prefix}.anchor.fallback_asset_types 必须为 array")
            else:
                for asset_type in fallback_asset_types:
                    if known_asset_types and str(asset_type) not in known_asset_types:
                        report.warn(
                            f"{path}: {field_prefix}.anchor.fallback_asset_types 包含当前未注册 asset_type {asset_type!r}"
                        )
                required_asset_types.update(str(asset_type) for asset_type in fallback_asset_types)

        bundle_id = pattern.get("bundle_id")
        if not bundle_id:
            report.warn(f"{path}: {field_prefix} 未声明 bundle_id，无法做 scenario→bundle 覆盖校验")
            continue
        bundle_item = bundles.get(str(bundle_id))
        if not bundle_item:
            report.error(f"{path}: {field_prefix}.bundle_id 引用未知资产包 {bundle_id!r}")
            continue

        bundle_path, bundle = bundle_item
        bundle_scenarios = {str(s) for s in bundle.get("investigation_scenarios") or []}
        if scenario_id and scenario_id not in bundle_scenarios:
            report.error(
                f"{path}: {field_prefix}.bundle_id={bundle_id!r} 对应资产包 {bundle_path} "
                f"未声明 investigation_scenarios 包含 {scenario_id!r}"
            )

        optional_asset_types = pattern.get("optional_asset_types") or []
        if not isinstance(optional_asset_types, list):
            report.error(f"{path}: {field_prefix}.optional_asset_types 必须为 array")
            optional_asset_types = []
        optional_types = {str(asset_type) for asset_type in optional_asset_types}
        for asset_type in optional_types:
            if known_asset_types and asset_type not in known_asset_types:
                report.warn(
                    f"{path}: {field_prefix}.optional_asset_types 包含当前未注册 asset_type {asset_type!r}"
                )

        covered_asset_types = _bundle_asset_types(bundle, assets, hosts=hosts)
        missing_types = sorted(required_asset_types - covered_asset_types - optional_types)
        if missing_types:
            report.error(
                f"{path}: {field_prefix}.bundle_id={bundle_id!r} 未覆盖推荐链/分层资产需要的 asset_type {missing_types!r}；"
                "请补 bundle.asset_ids 或调整 recommended_chain/layer*_assets"
            )
        registry_covers = bundle.get("registry_covers_asset_types") or []
        if registry_covers and not hosts:
            report.warn(
                f"{bundle_path}: registry_covers_asset_types={registry_covers!r} 但 dataasset/hosts/ 为空"
            )

    matrix = load_json(legacy_path) if legacy_path.is_file() else {}
    if matrix.get("anchor_patterns"):
        report.warn(f"{legacy_path}: anchor_patterns 已迁移到 scenarios/anchor-patterns.json，请勿继续放在 correlation-matrix 中")


def public_credential_template_exists(ref: str, root: Path | None = None) -> bool:
    """Return whether the canonical public registry documents a Vault reference.

    A similarly named example in a custom registry must not hide a missing local
    ciphertext, because only this repository's sanitized templates are known to be
    intentionally secret-free.
    """
    registry_root = root or DATAASSET_ROOT
    if registry_root.resolve() != DEFAULT_DATAASSET_ROOT.resolve():
        return False
    rel = normalize_vault_ref(ref).replace("vault://", "")
    return (registry_root / "credentials" / "examples" / f"{rel}.yaml").is_file()


def check_connector(
    report: Report,
    path: Path,
    data: dict[str, Any],
    *,
    root: Path | None = None,
    credential_statuses: dict[str, str] | None = None,
) -> None:
    """Validate one connector against the registry being checked.

    The optional root is explicit so credential checks never depend on or rewrite
    the module-level DATAASSET_ROOT when callers validate another registry.
    """
    registry_root = root or registry_root_for(path)
    check_id_matches_filename(report, path, data, "connector_id")
    status = data.get("status", "draft")
    ctype = data.get("connector_type")
    raw_ref = str(data.get("credentials_ref") or "")
    ref = ""
    if raw_ref:
        try:
            ref = validate_credentials_ref(raw_ref)
        except ValueError as exc:
            report.error(
                f"{path}: {exc}",
                code="connector-credential-ref-invalid",
                object_type="connector",
                object_id=str(data.get("connector_id") or ""),
                path=path,
                field="credentials_ref",
                suggested_fix="使用 vault://namespace/name，禁止空段、.、.. 和反斜杠路径。",
            )
    if status == "active" and ctype != "local_file":
        if not ref:
            if not raw_ref:
                report.error(f"{path}: active 连接器缺少 credentials_ref")
        else:
            enc = credential_secret_path(registry_root / "credentials", ref)
            # The public registry intentionally ships placeholders instead of encrypted
            # secrets. Suppress that expected condition only for its canonical root and
            # a matching template; custom roots still surface missing operational Vaults.
            if not enc.is_file() and not public_credential_template_exists(ref, registry_root):
                report.warn(
                    f"{path}: 未找到 SOPS 密文 "
                    f"{enc.relative_to(registry_root.resolve()).as_posix()}"
                )
            elif (credential_statuses or {}).get(ref) == "disabled":
                report.error(f"{path}: active 连接器引用了已下线凭证 {ref}")

    config = data.get("config") or {}
    ca_file = config.get("ca_file")
    if ca_file is not None:
        try:
            resolve_ca_file(ca_file, registry_root, label=f"{ctype} connector")
        except ValueError as exc:
            report.error(
                f"{path}: {exc}",
                code="connector-ca-file-invalid",
                object_type="connector",
                object_id=str(data.get("connector_id") or ""),
                path=path,
                field="config.ca_file",
                suggested_fix="绝对路径可指向系统 CA；相对路径必须位于 DATAASSET_ROOT 内，且符号链接不能越界。",
            )
    if status == "active" and config.get("project") == "YOUR_SLS_PROJECT":
        report.error(
            f"{path}: 使用 YOUR_SLS_PROJECT 的公开占位 Connector 必须保持 draft；"
            "替换实际 Project/Logstore 并完成连通验收后才能启用"
        )
    if ctype == "sls_proxy":
        # Project is a resource selector, not an upstream URL or a tenant claim.
        # Share validation with live fetch so a saved Connector cannot drift.
        try:
            proxy_project(config)
        except ValueError as exc:
            report.error(f"{path}: {exc}")
        forbidden = [key for key in ("region", "enterprise_id") if config.get(key)]
        if forbidden:
            report.error(
                f"{path}: sls_proxy config 不应包含服务端字段 {forbidden!r}；请从 Connector 删除"
            )
        endpoint = str(config.get("endpoint") or "")
        if status == "active" and not sls_proxy_endpoint_is_secure(endpoint):
            report.error(
                f"{path}: active sls_proxy 必须使用 HTTPS；HTTP 只允许 localhost/127.0.0.1/::1 本地联调"
            )
    elif ctype == "agent_stream":
        if not config.get("sink_connector_id"):
            report.warn(f"{path}: agent_stream 建议填写 sink_connector_id（查询走 SLS sink）")
    elif ctype == "es":
        if status == "active":
            if config.get("tls_verify") is not True:
                report.error(
                    f"{path}: active es 必须设置 tls_verify=true；私有 CA 请使用 ca_file",
                    code="connector-es-tls-required",
                    object_type="connector",
                    object_id=str(data.get("connector_id") or ""),
                    path=path,
                    field="config.tls_verify",
                    suggested_fix="设置 config.tls_verify=true；私有 CA 使用 dataasset 根目录相对 ca_file，禁止关闭证书校验。",
                )
            endpoint = str(config.get("url") or config.get("endpoint") or "")
            try:
                validate_secure_endpoint(endpoint, label="active es endpoint")
            except ValueError as exc:
                report.error(
                    f"{path}: {exc}",
                    code="connector-transport-insecure",
                    object_type="connector",
                    object_id=str(data.get("connector_id") or ""),
                    path=path,
                    field="config.url",
                    suggested_fix="使用最终 HTTPS 地址；本地联调仅允许明确的回环地址，且不允许 URL 内嵌账号密码。",
                )
    elif ctype in {"http_api", "splunk"} and status == "active":
        endpoint = str(config.get("base_url") or "")
        try:
            validate_secure_endpoint(endpoint, label=f"active {ctype} base_url")
        except ValueError as exc:
            report.error(
                f"{path}: {exc}",
                code="connector-transport-insecure",
                object_type="connector",
                object_id=str(data.get("connector_id") or ""),
                path=path,
                field="config.base_url",
                suggested_fix="使用最终 HTTPS 地址；本地联调仅允许明确的回环地址，且不允许 URL 内嵌账号密码。",
            )
        verify_key = "verify_tls" if ctype == "splunk" else "tls_verify"
        if config.get(verify_key, True) is not True:
            report.error(
                f"{path}: active {ctype} 必须设置 {verify_key}=true；私有 CA 请使用 ca_file",
                code="connector-tls-required",
                object_type="connector",
                object_id=str(data.get("connector_id") or ""),
                path=path,
                field=f"config.{verify_key}",
                suggested_fix=f"设置 config.{verify_key}=true；私有 CA 使用 dataasset 根目录相对 ca_file。",
            )
    elif ctype == "local_file":
        if status == "active" and not (config.get("hostname") or config.get("host")):
            report.warn(f"{path}: local_file 建议填写 hostname 以便 host 过滤与 event 标注")

    # External-executor transport is orthogonal to each connector's native
    # settings, so validate it after type-specific checks (including agent_stream).
    if status == "active":
        runtime = connector_runtime_modes(registry_root).get(str(ctype), "")
        if runtime in {"local_or_external_executor", "live_or_external_executor"}:
            endpoint = str(config.get("executor_endpoint") or config.get("external_endpoint") or "")
            if not endpoint and runtime == "local_or_external_executor":
                endpoint = str(config.get("endpoint") or config.get("base_url") or "")
            if endpoint:
                try:
                    validate_secure_endpoint(endpoint, label=f"active {ctype} external executor")
                except ValueError as exc:
                    report.error(
                        f"{path}: {exc}",
                        code="connector-transport-insecure",
                        object_type="connector",
                        object_id=str(data.get("connector_id") or ""),
                        path=path,
                        field="config.executor_endpoint",
                        suggested_fix="远程执行器使用最终 HTTPS 地址；HTTP 仅允许明确的本机回环地址。",
                    )
    # Structural fields and connector-specific required combinations have one
    # source of truth in data-connector.schema.json. Runtime readiness consumes
    # these same structured validation errors instead of duplicating this table.
    check_json_schema(report, path, data, registry_root / "schema" / "data-connector.schema.json")


def check_asset(
    report: Report,
    path: Path,
    data: dict[str, Any],
    connectors: dict[str, tuple[Path, dict]],
    templates: dict[str, Any],
    hosts: dict[str, tuple[Path, dict[str, Any]]],
    evidence_spec: dict[str, Any],
) -> None:
    check_id_matches_filename(report, path, data, "asset_id")
    status = data.get("status", "draft")
    all_connector_ids = resolve_connector_ids(data)
    if not all_connector_ids:
        report.error(f"{path}: 缺少 connector_id / connector_ids")
        return

    primary = data.get("connector_id")
    if primary and primary not in (data.get("connector_ids") or []) and len(all_connector_ids) > 1:
        report.warn(f"{path}: connector_id 未出现在 connector_ids 中（已自动合并拉取）")

    connectors_ok = True
    for connector_id in all_connector_ids:
        if connector_id not in connectors:
            report.error(f"{path}: connector_id {connector_id!r} 不存在")
            connectors_ok = False
    if not connectors_ok:
        return

    if status == "discovery":
        catalog = templates.get("templates", {})
        for tid in data.get("query_template_ids") or []:
            if tid not in catalog:
                report.error(f"{path}: query_template_id {tid!r} 不在 templates.json")
        schema = data.get("schema") or {}
        for key in ("fields", "time_field", "retention_days"):
            if key not in schema:
                report.error(f"{path}: schema 缺少 {key}")
        _check_deprecated_correlation_keys(report, path, data)
        check_connector_host_refs(report, path, data, hosts, connectors)
        check_asset_coverage_hosts(report, path, data)
        check_active_asset_gate(report, path, data)
        check_active_evidence_fields(report, path, data, evidence_spec)
        check_json_schema(report, path, data, registry_root_for(path) / "schema" / "data-asset.schema.json")
        return

    catalog = templates.get("templates", {})
    template_ids = data.get("query_template_ids") or []
    has_default_for_all_connectors = True
    for connector_id in all_connector_ids:
        _, connector = connectors[connector_id]
        default_tid = default_template_id_for_asset(data, connector, templates)
        if not default_tid:
            has_default_for_all_connectors = False
            continue
        default_tpl = catalog.get(default_tid)
        ctype = connector.get("connector_type", "")
        if (
            not default_tpl
            or data.get("asset_type") not in default_tpl.get("asset_types", [])
            or not connector_supports_template(default_tpl, ctype)
        ):
            has_default_for_all_connectors = False

    if not template_ids and data.get("status") == "active" and not has_default_for_all_connectors:
        report.error(
            f"{path}: active 资产必须声明 query_template_ids，或在 templates.default_templates 中为每个 connector_type 配置默认模板"
        )

    for tid in template_ids:
        if tid not in catalog:
            report.error(f"{path}: query_template_id {tid!r} 不在 templates.json")
            continue
        tpl = catalog[tid]
        if data.get("asset_type") not in tpl.get("asset_types", []):
            msg = f"{path}: 模板 {tid} 的 asset_types 不包含 {data.get('asset_type')}"
            if data.get("status") == "active":
                report.error(msg)
            else:
                report.warn(msg)

    for connector_id in all_connector_ids:
        _, connector = connectors[connector_id]
        ctype = connector.get("connector_type", "")
        usable = [
            tid
            for tid in template_ids
            if tid in catalog
            and data.get("asset_type") in catalog[tid].get("asset_types", [])
            and connector_supports_template(catalog[tid], ctype)
        ]
        default_tid = default_template_id_for_asset(data, connector, templates)
        default_tpl = catalog.get(default_tid) if default_tid else None
        default_usable = bool(
            default_tpl
            and data.get("asset_type") in default_tpl.get("asset_types", [])
            and connector_supports_template(default_tpl, ctype)
        )
        if template_ids and not usable and not default_usable:
            report.error(f"{path}: connector {connector_id} ({ctype}) 无匹配的 query_template 或 default_template")

    schema = data.get("schema") or {}
    for key in ("fields", "time_field", "retention_days"):
        if key not in schema:
            report.error(f"{path}: schema 缺少 {key}")

    _check_deprecated_correlation_keys(report, path, data)
    check_connector_host_refs(report, path, data, hosts, connectors)
    check_asset_coverage_hosts(report, path, data)
    check_active_asset_gate(report, path, data)
    check_active_evidence_fields(report, path, data, evidence_spec)
    check_json_schema(report, path, data, registry_root_for(path) / "schema" / "data-asset.schema.json")


def _check_deprecated_correlation_keys(report: Report, path: Path, data: dict[str, Any]) -> None:
    schema = data.get("schema") or {}
    legacy = schema.get("correlation_keys")
    if legacy is None:
        return
    try:
        from correlation_keys import derive_correlation_keys

        derived = derive_correlation_keys(data)
        if list(legacy) != derived:
            report.warn(
                f"{path}: schema.correlation_keys 已废弃且与 matrix+fields 推导不一致；"
                f"请删除手写项（推导为 {derived!r}）"
            )
        else:
            report.warn(f"{path}: schema.correlation_keys 已废弃，请删除（可由 matrix+fields 自动推导）")
    except Exception as exc:  # noqa: BLE001
        report.warn(f"{path}: schema.correlation_keys 已废弃，请删除（推导校验失败: {exc}）")


def check_bundle(
    report: Report,
    path: Path,
    data: dict[str, Any],
    assets: dict[str, tuple[Path, dict]],
) -> None:
    check_id_matches_filename(report, path, data, "bundle_id")
    bundle_status = data.get("status", "draft")
    for asset_id in data.get("asset_ids") or []:
        if asset_id not in assets:
            report.error(f"{path}: asset_id {asset_id!r} 不存在")
            continue
        _, asset = assets[asset_id]
        if bundle_status == "active" and asset.get("status") != "active":
            report.error(f"{path}: active 资产包引用了非 active 资产 {asset_id} ({asset.get('status')})")
        if asset.get("status") == "discovery":
            report.warn(f"{path}: 资产包引用了 discovery 队列资产 {asset_id}（格式发现未完成）")

    for sid in data.get("investigation_scenarios") or []:
        if sid not in SCENARIO_IDS:
            report.warn(f"{path}: 未知 investigation_scenario {sid!r}")

    check_json_schema(report, path, data, registry_root_for(path) / "schema" / "data-bundle.schema.json")


def check_orphan_connectors(
    report: Report,
    connectors: dict[str, tuple[Path, dict]],
    assets: dict[str, tuple[Path, dict]],
) -> None:
    _ = assets
    for _cid, (path, data) in connectors.items():
        if data.get("connector_type") == "agent_stream":
            sink = (data.get("config") or {}).get("sink_connector_id")
            if sink and sink not in connectors:
                report.error(f"{path}: sink_connector_id {sink!r} 不存在")


def check_default_templates(report: Report, path: Path, templates: dict[str, Any]) -> None:
    catalog = templates.get("templates") or {}
    defaults = templates.get("default_templates") or {}
    query_keys = query_key_by_connector()
    if not isinstance(defaults, dict):
        report.error(f"{path}: default_templates 必须为 object")
        return

    for connector_type, by_asset_type in defaults.items():
        if connector_type not in query_keys:
            report.warn(f"{path}: default_templates.{connector_type} 使用了未知 connector_type")
        if not isinstance(by_asset_type, dict):
            report.error(f"{path}: default_templates.{connector_type} 必须为 object")
            continue
        for asset_type, template_id in by_asset_type.items():
            template = catalog.get(template_id)
            if not template:
                report.error(f"{path}: default_templates.{connector_type}.{asset_type} 指向不存在的模板 {template_id!r}")
                continue
            if asset_type not in template.get("asset_types", []):
                report.error(
                    f"{path}: 默认模板 {template_id} 的 asset_types 不包含 {asset_type}"
                )
            if not connector_supports_template(template, connector_type):
                report.error(
                    f"{path}: 默认模板 {template_id} 的 connector_types 不包含 {connector_type}"
                )
            query_key = query_keys.get(connector_type)
            if query_key and not template.get(query_key):
                report.error(
                    f"{path}: 默认模板 {template_id} 缺少 connector_type={connector_type} 需要的 {query_key}"
                )


def check_template_fetch_samples(
    report: Report,
    assets: dict[str, tuple[Path, dict]],
    connectors: dict[str, tuple[Path, dict]],
    templates: dict[str, Any],
) -> None:
    """Sample params to verify template selection path."""
    sample_params = {
        "attacker_ip": "203.0.113.10",
        "src_ip": "203.0.113.10",
        "time_start": "2026-06-21T08:00:00+08:00",
        "time_end": "2026-06-21T20:00:00+08:00",
        "host": "web-01",
        "alert_id": "WAF-001",
    }
    for asset_id, (path, asset) in assets.items():
        if asset.get("status") != "active":
            continue
        connector_id = asset.get("connector_id")
        if connector_id not in connectors:
            continue
        _, connector = connectors[connector_id]
        tid, reason = select_template_for_asset(asset, connector, sample_params, templates)
        if not tid:
            report.warn(f"{path}: 样例 params 下无法选择模板（{reason}）")
        elif reason:
            report.warn(f"{path}: 使用 default_template {tid}")


def validate(
    dataasset_root: Path | None = None,
    *,
    only_active: bool = False,
    runtime_ready: bool = False,
    bundle_ids: list[str] | None = None,
) -> Report:
    """Validate one registry and optionally derive static bundle readiness.

    Runtime readiness deliberately remains separate from live connectivity: it
    inspects the local object graph and encrypted-file presence without reading
    secrets or contacting a backend.
    """
    root = resolve_dataasset_root(dataasset_root)
    report = Report()
    check_config_only_layout(report, root)

    connectors_dir = root / "connectors"
    assets_dir = root / "assets"
    bundles_dir = root / "bundles"
    templates_path = root / "query-templates/templates.json"

    if not templates_path.is_file():
        report.error(f"缺少 {templates_path}")
        return report

    templates = load_json(templates_path)
    check_json_schema(report, templates_path, templates, root / "schema" / "query-templates.schema.json")
    check_default_templates(report, templates_path, templates)

    for config_name, schema_name in (
        ("connector-catalog.json", "connector-catalog.schema.json"),
        ("external-connectors.json", "external-connectors.schema.json"),
    ):
        config_path = root / "configure" / config_name
        if config_path.is_file():
            check_json_schema(report, config_path, load_json(config_path), root / "schema" / schema_name)
    for message in connector_manifest_errors(root):
        report.error(message)

    credential_status_path = root / "credentials" / "credential-status.json"
    credential_statuses: dict[str, str] = {}
    if credential_status_path.is_file():
        credential_status_payload = load_json(credential_status_path)
        check_json_schema(
            report,
            credential_status_path,
            credential_status_payload,
            root / "schema" / "credential-status.schema.json",
        )
        try:
            credential_statuses = load_credential_statuses(root)
        except ValueError as exc:
            report.error(
                str(exc),
                code="credential-status-invalid",
                object_type="credential_registry",
                path=credential_status_path,
                suggested_fix="只使用规范化 vault://namespace/name 键，状态仅允许 active 或 disabled。",
            )
    evidence_spec = load_evidence_spec(root)
    connectors = load_all(connectors_dir, "connector_id")
    assets = load_all(assets_dir, "asset_id", skip_filenames=SPECIAL_ASSET_FILES)
    bundles = load_all(bundles_dir, "bundle_id")
    hosts = load_hosts(root)
    networks = load_networks(root)

    for path, data in networks.values():
        start = len(report.issues)
        check_network(report, path, data)
        annotate_object_issues(
            report,
            start,
            object_type="network",
            object_id=str(data.get("network_id") or path.stem),
            path=path,
        )

    for path, data in connectors.values():
        if only_active and data.get("status", "draft") != "active":
            continue
        start = len(report.issues)
        check_connector(
            report,
            path,
            data,
            root=root,
            credential_statuses=credential_statuses,
        )
        annotate_object_issues(
            report,
            start,
            object_type="connector",
            object_id=str(data.get("connector_id") or path.stem),
            path=path,
        )

    for path, data in hosts.values():
        start = len(report.issues)
        check_host(report, path, data, networks)
        annotate_object_issues(
            report,
            start,
            object_type="host",
            object_id=str(data.get("host_id") or path.stem),
            path=path,
        )

    for path, data in assets.values():
        if only_active and data.get("status", "draft") != "active":
            continue
        start = len(report.issues)
        check_asset(report, path, data, connectors, templates, hosts, evidence_spec)
        annotate_object_issues(
            report,
            start,
            object_type="asset",
            object_id=str(data.get("asset_id") or path.stem),
            path=path,
        )

    for path, data in bundles.values():
        if only_active and data.get("status", "draft") != "active":
            continue
        start = len(report.issues)
        check_bundle(report, path, data, assets)
        annotate_object_issues(
            report,
            start,
            object_type="bundle",
            object_id=str(data.get("bundle_id") or path.stem),
            path=path,
        )

    if not only_active:
        check_orphan_connectors(report, connectors, assets)
    check_template_fetch_samples(report, assets, connectors, templates)
    check_catalog(report, root)
    check_correlation_matrix(report, root, assets)

    if runtime_ready:
        readiness = assess_runtime_readiness(
            root,
            bundles,
            assets,
            connectors,
            credential_statuses,
            bundle_ids=bundle_ids,
            validation_issues=list(report.issues),
        )
        report.runtime_readiness = readiness
        if readiness["summary"]["checked_bundle_count"] == 0:
            report.error(
                "没有可检查的 active Bundle；请使用 --bundle 指定目标，或先激活 Bundle",
                code="runtime-bundle-none",
                object_type="bundle",
                suggested_fix="使用 --bundle <bundle_id> 指定目标，或确认 bundles/*.json 的 status 为 active。",
            )
        for row in readiness["bundles"]:
            for blocker in row["blockers"]:
                report.error(
                    blocker["message"],
                    code=blocker["code"],
                    object_type=blocker["object_type"],
                    object_id=blocker["object_id"],
                    path=blocker["path"],
                    priority="P0",
                    owner="运营 / 开发",
                    suggested_fix=(
                        f"修复 Bundle {row['bundle_id']} 的静态执行链后重新运行 --runtime-ready；"
                        "通过后再执行 dataasset-connectivity-check。"
                    ),
                )

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate dataasset/ registry")
    parser.add_argument("--dataasset", type=Path, default=DATAASSET_ROOT)
    parser.add_argument(
        "--sync-catalog",
        action="store_true",
        help="扫描 assets/connectors/bundles 并重写 catalog.json",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="仅输出错误/警告行")
    parser.add_argument("--strict", action="store_true", help="严格门禁：warning 也作为阻塞项返回非 0")
    parser.add_argument("--json", action="store_true", dest="json_output", help="输出结构化 JSON，供 UI/CI 消费")
    parser.add_argument("--diagnose", action="store_true", help="输出每个问题的配置错误诊断和修复步骤")
    parser.add_argument("--only-active", action="store_true", help="仅检查 active 对象的上线门禁")
    parser.add_argument(
        "--runtime-ready",
        action="store_true",
        help="静态检查 Bundle 到凭证密文的执行链；不联网、不解密凭证",
    )
    parser.add_argument("--bundle", action="append", dest="bundle_ids", help="仅检查指定 Bundle；可重复")
    args = parser.parse_args()

    if args.bundle_ids and not args.runtime_ready:
        parser.error("--bundle 仅能与 --runtime-ready 一起使用")

    if args.sync_catalog:
        out = write_catalog(args.dataasset)
        print(f"synced catalog → {out}", file=sys.stderr)

    report = validate(
        args.dataasset,
        only_active=args.only_active,
        runtime_ready=args.runtime_ready,
        bundle_ids=args.bundle_ids,
    )
    payload = report.as_json(strict=args.strict)

    if args.json_output:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for issue in report.issues:
            prefix = "ERROR" if issue.severity == "error" else "WARN"
            print(f"{prefix}: {issue.message}", file=sys.stderr)

        if args.diagnose and report.issues:
            print("\n配置错误诊断:", file=sys.stderr)
            for issue in report.issues:
                data = issue.to_dict()
                print(f"- [{data['priority']}] {data['category']}: {data['message']}", file=sys.stderr)
                print(f"  原因: {data['root_cause']}", file=sys.stderr)
                print(f"  影响: {data['impact']}", file=sys.stderr)
                print(f"  建议: {data['suggested_fix']}", file=sys.stderr)
                for step in data.get("fix_steps") or []:
                    print(f"  - {step}", file=sys.stderr)
                if data.get("example"):
                    print(f"  示例: {data['example']}", file=sys.stderr)
                if data.get("docs"):
                    print(f"  文档: {', '.join(data['docs'])}", file=sys.stderr)

        if not args.quiet:
            mode = "strict" if args.strict else "normal"
            scope = "runtime-ready" if args.runtime_ready else ("active-only" if args.only_active else "all")
            print(
                f"\nvalidate[{mode}/{scope}]: "
                f"{len(report.errors)} error(s), {len(report.warnings)} warning(s), "
                f"{payload['summary']['blocking_count']} blocking issue(s)",
                file=sys.stderr,
            )

    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
