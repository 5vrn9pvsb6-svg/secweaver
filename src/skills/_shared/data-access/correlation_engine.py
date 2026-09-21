"""Correlation-matrix driven join engine: match, time windows, fetch planning."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from dataasset_paths import DATAASSET_ROOT
from field_resolver import (
    alias_source_keys,
    canonical_variants,
    load_correlation_matrix,
    resolve_field_value,
)
from normalizer import normalize_ip

ANCHOR_PATTERNS_PATH = DATAASSET_ROOT / "scenarios" / "anchor-patterns.json"

IP_IN_TEXT = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def load_matrix() -> dict[str, Any]:
    return load_correlation_matrix()


@lru_cache(maxsize=1)
def load_anchor_patterns_doc() -> dict[str, Any]:
    if ANCHOR_PATTERNS_PATH.is_file():
        with ANCHOR_PATTERNS_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


@lru_cache(maxsize=1)
def load_anchor_patterns() -> dict[str, Any]:
    doc = load_anchor_patterns_doc()
    if doc.get("patterns"):
        return doc.get("patterns") or {}
    return (load_matrix().get("anchor_patterns") or {})


_DEFAULT_SCENARIO_PRIORITY: list[tuple[str, str]] = [
    ("S1", "S1_external_ip_trace"),
    ("S2", "S2_web_breach"),
    ("S3", "S3_lateral_movement"),
    ("S5", "S5_host_risk"),
    ("S6", "S6_account_compromise"),
    ("S7", "S7_data_exfiltration"),
    ("S4", "S4_alert_confirmation"),
]


def load_scenario_priority() -> list[tuple[str, str]]:
    """Single source: dataasset/scenarios/anchor-patterns.json scenario_priority."""
    raw = load_anchor_patterns_doc().get("scenario_priority") or []
    result: list[tuple[str, str]] = []
    for item in raw:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            result.append((str(item[0]), str(item[1])))
        elif isinstance(item, dict):
            sid = item.get("scenario") or item.get("id")
            pid = item.get("pattern_id") or item.get("pattern")
            if sid and pid:
                result.append((str(sid), str(pid)))
    return result or list(_DEFAULT_SCENARIO_PRIORITY)


def get_anchor_pattern(anchor_pattern_id: str) -> dict[str, Any] | None:
    return load_anchor_patterns().get(anchor_pattern_id)


@lru_cache(maxsize=1)
def _join_index() -> dict[str, dict[str, Any]]:
    matrix = load_matrix()
    index: dict[str, dict[str, Any]] = {}
    for block in ("internal_joins", "cross_source_joins"):
        for join in matrix.get(block) or []:
            index[join["id"]] = join
    return index


def get_join(join_id: str, matrix: dict[str, Any] | None = None) -> dict[str, Any] | None:
    matrix = matrix or load_matrix()
    for block in ("internal_joins", "cross_source_joins"):
        for join in matrix.get(block) or []:
            if join.get("id") == join_id:
                return join
    return _join_index().get(join_id)


def get_join_trace_stage(join_id: str, matrix: dict[str, Any] | None = None) -> str | None:
    """Attack-chain stage for a join (join.trace_stage or matrix trace_stage_map)."""
    matrix = matrix or load_matrix()
    join = get_join(join_id, matrix) or {}
    stage = join.get("trace_stage")
    if stage:
        return str(stage)
    mapped = (matrix.get("trace_stage_map") or {}).get(join_id)
    return str(mapped) if mapped else None


def join_ids_for_trace_stage(stage: str, matrix: dict[str, Any] | None = None) -> frozenset[str]:
    matrix = matrix or load_matrix()
    ids: set[str] = set()
    for join_id, mapped in (matrix.get("trace_stage_map") or {}).items():
        if mapped == stage:
            ids.add(str(join_id))
    for block in ("internal_joins", "cross_source_joins"):
        for join in matrix.get(block) or []:
            if join.get("trace_stage") == stage and join.get("id"):
                ids.add(str(join["id"]))
    return frozenset(ids)


def expand_path(join_id: str, matrix: dict[str, Any] | None = None) -> list[str]:
    """Expand composite join (path) into ordered atomic join ids."""
    join = get_join(join_id, matrix)
    if not join:
        return []
    path = join.get("path")
    if not path:
        return [join_id]
    steps: list[str] = []
    for step in path:
        steps.extend(expand_path(str(step), matrix))
    return steps


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def event_timestamp(event: dict[str, Any], matrix: dict[str, Any] | None = None) -> datetime | None:
    matrix = matrix or load_matrix()
    for key in canonical_variants("timestamp", matrix=matrix):
        if event.get(key) not in (None, ""):
            return parse_ts(str(event[key]))
    return None


def time_window_spec(window_id: str, matrix: dict[str, Any] | None = None) -> dict[str, Any]:
    matrix = matrix or load_matrix()
    return dict((matrix.get("time_windows") or {}).get(window_id) or {})


def time_window_bounds(
    anchor_ts: datetime,
    window_id: str,
    matrix: dict[str, Any] | None = None,
) -> tuple[datetime, datetime]:
    spec = time_window_spec(window_id, matrix)
    before = timedelta(
        minutes=int(spec.get("before_minutes") or 0),
        hours=int(spec.get("before_hours") or 0),
    )
    after = timedelta(
        minutes=int(spec.get("after_minutes") or 0),
        hours=int(spec.get("after_hours") or 0),
    )
    return anchor_ts - before, anchor_ts + after


def fill_investigation_window(
    params: dict[str, Any],
    window_id: str,
    *,
    matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive params.time_start/time_end from alert_time using a matrix time_window."""
    out = dict(params)
    if out.get("time_start") and out.get("time_end"):
        return out
    anchor = parse_ts(out.get("alert_time"))
    if anchor is None:
        anchor = parse_ts(out.get("time_start"))
    if anchor is None:
        return out
    start, end = time_window_bounds(anchor, window_id, matrix)
    if not out.get("time_start"):
        out["time_start"] = start.isoformat()
    if not out.get("time_end"):
        out["time_end"] = end.isoformat()
    return out


def resolve_anchor_params(
    anchor_pattern_id: str,
    params: dict[str, Any],
    *,
    matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply anchor_patterns.investigation_window to fill fetch time range when missing."""
    matrix = matrix or load_matrix()
    pattern = get_anchor_pattern(anchor_pattern_id) or {}
    window_id = pattern.get("investigation_window")
    out = apply_investigation_param_aliases(params, matrix=matrix)
    if not window_id:
        return out
    return fill_investigation_window(out, str(window_id), matrix=matrix)


def apply_investigation_param_aliases(
    params: dict[str, Any],
    *,
    matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fill canonical investigation params from aliases defined in correlation-matrix.json.

    Ops maintain ``investigation_param_aliases`` only — e.g. seed_hosts[0] → target_ip.
    """
    matrix = matrix or load_matrix()
    aliases = matrix.get("investigation_param_aliases") or {}
    out = dict(params)
    for dest, sources in aliases.items():
        if dest == "description":
            continue
        current = out.get(dest)
        if current not in (None, ""):
            if isinstance(current, list) and current:
                out[dest] = str(current[0])
            continue
        src_list = sources if isinstance(sources, list) else [sources]
        for src in src_list:
            val = out.get(src)
            if isinstance(val, list) and val:
                out[dest] = str(val[0])
                break
            if val not in (None, ""):
                out[dest] = str(val)
                break
    return out


def in_time_window(
    event_ts: datetime | None,
    anchor_ts: datetime | None,
    window_id: str,
    matrix: dict[str, Any] | None = None,
) -> bool:
    if event_ts is None or anchor_ts is None:
        return True
    start, end = time_window_bounds(anchor_ts, window_id, matrix)
    return start <= event_ts <= end


def normalize_url_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        path = parsed.path or ""
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path.lower()
    return text.lower()


def extract_ip_addresses(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        ips: set[str] = set()
        for item in value:
            ips.update(extract_ip_addresses(item))
        return ips
    if isinstance(value, dict):
        ips = set()
        for item in value.values():
            ips.update(extract_ip_addresses(item))
        return ips
    text = str(value)
    found = set(IP_IN_TEXT.findall(text))
    for token in re.split(r"[\s,;|]+", text):
        token = token.strip()
        if not token:
            continue
        try:
            ipaddress.ip_address(token)
            found.add(token)
        except ValueError:
            continue
    return found


def build_host_ip_map(
    bundles: dict[str, list[dict[str, Any]]],
    params: dict[str, Any] | None = None,
) -> dict[str, str]:
    mapping: dict[str, str] = dict((params or {}).get("host_ips") or {})
    for item in bundles.get("asset_inventory") or []:
        host = item.get("hostname") or item.get("host")
        ip = item.get("ip")
        if host and ip:
            mapping[str(host)] = str(ip)
            mapping[str(ip)] = str(ip)
    for bundle in ("host_exec", "host_connect", "host_file_op", "ssh_auth"):
        for ev in bundles.get(bundle) or []:
            for key in ("host_ip", "_victim_host", "log_source", "__source__"):
                ip = ev.get(key)
                if ip:
                    mapping[str(ip)] = str(ip)
            host = ev.get("host") or ev.get("host_name") or ev.get("hostname")
            ip = ev.get("host_ip") or ev.get("_victim_host") or ev.get("__source__")
            if host and ip:
                mapping[str(host)] = str(ip)
            elif host and ip is None:
                generic = str(host).lower() in ("localhost", "localhost.localdomain", "127.0.0.1")
                if generic:
                    for key in ("host_ip", "_victim_host", "__source__"):
                        val = ev.get(key)
                        if val:
                            mapping[str(host)] = str(val)
                            break
    return mapping


def _matched_via(
    event: dict[str, Any],
    canonical: str,
    *,
    asset: dict[str, Any] | None = None,
    asset_type: str | None = None,
    extra_variants: list[str] | None = None,
    matrix: dict[str, Any] | None = None,
) -> str | None:
    matrix = matrix or load_matrix()
    asset_type = asset_type or (asset or {}).get("asset_type")
    if canonical in event and event[canonical] not in (None, ""):
        return "canonical"
    for key in canonical_variants(canonical, matrix=matrix, asset_type=asset_type, extra_variants=extra_variants):
        if key != canonical and key in event and event[key] not in (None, ""):
            return "variant"
    for key in alias_source_keys(canonical, asset, matrix):
        if key in event and event[key] not in (None, ""):
            return "alias"
    return None


def read_join_field(
    event: dict[str, Any],
    join_key: dict[str, Any],
    side: str,
    *,
    asset: dict[str, Any] | None = None,
    asset_type: str | None = None,
    matrix: dict[str, Any] | None = None,
) -> tuple[Any, str | None]:
    canonical = str(join_key.get(side) or "")
    variant_key = f"{side}_variants"
    extra = [str(v) for v in (join_key.get(variant_key) or [])]
    value = resolve_field_value(
        event,
        canonical,
        asset=asset,
        asset_type=asset_type,
        extra_variants=extra,
        matrix=matrix,
    )
    via = _matched_via(
        event,
        canonical,
        asset=asset,
        asset_type=asset_type,
        extra_variants=extra,
        matrix=matrix,
    )
    return value, via


def values_match(
    left: Any,
    right: Any,
    match: str,
    *,
    host_ip_map: dict[str, str] | None = None,
    left_field: str | None = None,
    right_field: str | None = None,
) -> bool:
    if left in (None, "") or right in (None, ""):
        return False
    match = match or "exact"
    if match == "exact":
        ip_fields = {
            "src_ip",
            "source_ip",
            "attacker_ip",
            "client_ip",
            "remote_addr",
            "rhost",
            "target_ip",
            "host_ip",
            "upstream_addr",
        }
        if str(left_field or "").strip().lower() in ip_fields or str(right_field or "").strip().lower() in ip_fields:
            left_ip = normalize_ip(left)
            right_ip = normalize_ip(right)
            return left_ip is not None and left_ip == right_ip
        return str(left).strip().lower() == str(right).strip().lower()
    if match == "path_prefix":
        lp = normalize_url_path(left)
        rp = normalize_url_path(right)
        if not lp or not rp:
            return False
        return lp.startswith(rp) or rp.startswith(lp)
    if match == "hostname_to_ip_via_cmdb":
        host_ip_map = host_ip_map or {}
        host = str(left).strip()
        ip = str(right).strip()
        resolved = host_ip_map.get(host)
        if resolved:
            return resolved == ip
        try:
            return ipaddress.ip_address(host) == ipaddress.ip_address(ip)
        except ValueError:
            return False
    if match == "dns_answer_ip":
        ips = extract_ip_addresses(right)
        return str(left).strip() in ips
    return str(left).strip().lower() == str(right).strip().lower()


def evaluate_join_key(
    left_event: dict[str, Any],
    right_event: dict[str, Any],
    join_key: dict[str, Any],
    *,
    left_asset: dict[str, Any] | None = None,
    right_asset: dict[str, Any] | None = None,
    host_ip_map: dict[str, str] | None = None,
    matrix: dict[str, Any] | None = None,
) -> tuple[bool, dict[str, Any]]:
    matrix = matrix or load_matrix()
    left_type = (left_asset or {}).get("asset_type")
    right_type = (right_asset or {}).get("asset_type")
    left_val, left_via = read_join_field(
        left_event, join_key, "left", asset=left_asset, asset_type=left_type, matrix=matrix
    )
    right_val, right_via = read_join_field(
        right_event, join_key, "right", asset=right_asset, asset_type=right_type, matrix=matrix
    )
    optional = bool(join_key.get("optional"))
    if left_val in (None, "") or right_val in (None, ""):
        if optional:
            return True, {}
        return False, {}

    match = str(join_key.get("match") or "exact")
    ok = values_match(
        left_val,
        right_val,
        match,
        host_ip_map=host_ip_map,
        left_field=str(join_key.get("left") or ""),
        right_field=str(join_key.get("right") or ""),
    )
    if not ok:
        return False, {}

    canonical_left = str(join_key.get("left") or "")
    canonical_right = str(join_key.get("right") or "")
    detail = {
        canonical_left: left_val,
        canonical_right: right_val,
        "matched_via": {
            "left": left_via or "canonical",
            "right": right_via or "canonical",
        },
    }
    return True, detail


def evaluate_join_keys(
    left_event: dict[str, Any],
    right_event: dict[str, Any],
    join_def: dict[str, Any],
    *,
    left_asset: dict[str, Any] | None = None,
    right_asset: dict[str, Any] | None = None,
    host_ip_map: dict[str, str] | None = None,
    matrix: dict[str, Any] | None = None,
    include_secondary: bool = True,
) -> tuple[bool, dict[str, Any], float]:
    matrix = matrix or load_matrix()
    match_keys: dict[str, Any] = {}
    required_failed = False
    optional_hits = 0
    optional_total = 0

    for key_row in join_def.get("join_keys") or []:
        ok, detail = evaluate_join_key(
            left_event,
            right_event,
            key_row,
            left_asset=left_asset,
            right_asset=right_asset,
            host_ip_map=host_ip_map,
            matrix=matrix,
        )
        optional = bool(key_row.get("optional"))
        if not detail and optional:
            optional_total += 1
            continue
        if not ok:
            if optional:
                optional_total += 1
                continue
            required_failed = True
            break
        match_keys.update({k: v for k, v in detail.items() if k != "matched_via"})
        if optional:
            optional_hits += 1
            optional_total += 1

    if required_failed:
        return False, {}, 0.0

    if include_secondary:
        for key_row in join_def.get("secondary_keys") or []:
            ok, detail = evaluate_join_key(
                left_event,
                right_event,
                key_row,
                left_asset=left_asset,
                right_asset=right_asset,
                host_ip_map=host_ip_map,
                matrix=matrix,
            )
            if ok and detail:
                match_keys.update({k: v for k, v in detail.items() if k != "matched_via"})
                optional_hits += 1
            optional_total += 1

    confidence_policy = join_def.get("confidence") if isinstance(join_def.get("confidence"), dict) else {}
    base_confidence = confidence_policy.get("base", 0.85 if match_keys else 0.75)
    max_confidence = confidence_policy.get("max", 0.95)
    optional_increment = confidence_policy.get("optional_key_increment", 0.05)
    try:
        confidence = float(base_confidence)
        confidence_ceiling = float(max_confidence)
        increment = float(optional_increment)
    except (TypeError, ValueError):
        confidence = 0.85 if match_keys else 0.75
        confidence_ceiling = 0.95
        increment = 0.05
    if optional_total and optional_hits:
        confidence = min(confidence_ceiling, confidence + increment * optional_hits)
    return True, match_keys, round(confidence, 2)


def event_ref(event: dict[str, Any], default: str = "unknown") -> str:
    return str(event.get("evidence_id") or event.get("_ref") or default)


def make_join_edge(
    join_id: str,
    left_event: dict[str, Any],
    right_event: dict[str, Any],
    *,
    match_keys: dict[str, Any],
    time_window: str | None,
    confidence: float,
    join_def: dict[str, Any] | None = None,
) -> dict[str, Any]:
    edge: dict[str, Any] = {
        "join_id": join_id,
        "left_ref": event_ref(left_event),
        "right_ref": event_ref(right_event),
        "match_keys": match_keys,
        "time_window": time_window,
        "confidence": confidence,
    }
    if join_def:
        edge["from_asset_type"] = join_def.get("from_asset_type")
        edge["to_asset_type"] = join_def.get("to_asset_type")
        if join_def.get("priority") is not None:
            edge["priority"] = join_def.get("priority")
        confidence_policy = join_def.get("confidence") if isinstance(join_def.get("confidence"), dict) else {}
        if confidence_policy:
            edge["confidence_base"] = confidence_policy.get("base")
            edge["confidence_ceiling"] = confidence_policy.get("max")
            edge["confidence_reason"] = confidence_policy.get("reason")
    return edge


def match_join_pair(
    join_id: str,
    left_event: dict[str, Any],
    right_event: dict[str, Any],
    *,
    anchor_ts: datetime | None = None,
    left_asset: dict[str, Any] | None = None,
    right_asset: dict[str, Any] | None = None,
    host_ip_map: dict[str, str] | None = None,
    matrix: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    matrix = matrix or load_matrix()
    join_def = get_join(join_id, matrix)
    if not join_def or join_def.get("path"):
        return None

    window_id = join_def.get("time_window")
    if window_id and anchor_ts is not None:
        left_ts = event_timestamp(left_event, matrix)
        right_ts = event_timestamp(right_event, matrix)
        anchor = left_ts or anchor_ts
        if right_ts and not in_time_window(right_ts, anchor, str(window_id), matrix):
            return None

    ok, match_keys, confidence = evaluate_join_keys(
        left_event,
        right_event,
        join_def,
        left_asset=left_asset,
        right_asset=right_asset,
        host_ip_map=host_ip_map,
        matrix=matrix,
    )
    if not ok or not match_keys:
        return None

    return make_join_edge(
        join_id,
        left_event,
        right_event,
        match_keys=match_keys,
        time_window=window_id,
        confidence=confidence,
        join_def=join_def,
    )


def bundles_by_type(bundles: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    return {k: list(v or []) for k, v in bundles.items()}


def find_join_pairs(
    join_id: str,
    bundles: dict[str, list[dict[str, Any]]],
    *,
    anchor_ts: datetime | None = None,
    assets_by_type: dict[str, list[dict[str, Any]]] | None = None,
    host_ip_map: dict[str, str] | None = None,
    matrix: dict[str, Any] | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    matrix = matrix or load_matrix()
    join_def = get_join(join_id, matrix)
    if not join_def:
        return []
    if join_def.get("path"):
        edges: list[dict[str, Any]] = []
        for step in expand_path(join_id, matrix):
            edges.extend(
                find_join_pairs(
                    step,
                    bundles,
                    anchor_ts=anchor_ts,
                    assets_by_type=assets_by_type,
                    host_ip_map=host_ip_map,
                    matrix=matrix,
                    limit=limit,
                )
            )
        return edges[:limit]

    left_type = str(join_def.get("from_asset_type") or "")
    right_type = str(join_def.get("to_asset_type") or "")
    left_events = bundles_by_type(bundles).get(left_type) or []
    right_events = bundles_by_type(bundles).get(right_type) or []
    left_asset = (assets_by_type or {}).get(left_type, [None])[0]
    right_asset = (assets_by_type or {}).get(right_type, [None])[0]
    host_ip_map = host_ip_map or build_host_ip_map(bundles)

    edges: list[dict[str, Any]] = []
    for left in left_events:
        for right in right_events:
            edge = match_join_pair(
                join_id,
                left,
                right,
                anchor_ts=anchor_ts,
                left_asset=left_asset,
                right_asset=right_asset,
                host_ip_map=host_ip_map,
                matrix=matrix,
            )
            if edge:
                edges.append(edge)
                if len(edges) >= limit:
                    return edges
    return edges


def anchor_pattern_for_scenarios(scenarios: list[str], matrix: dict[str, Any] | None = None) -> str | None:
    patterns = load_anchor_patterns()
    scenario_set = set(scenarios or [])
    for sid, pid in load_scenario_priority():
        if sid in scenario_set and pid in patterns:
            return pid
    return None


def run_recommended_chain(
    anchor_pattern_id: str,
    bundles: dict[str, list[dict[str, Any]]],
    params: dict[str, Any] | None = None,
    *,
    anchor_ts: datetime | None = None,
    matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    matrix = matrix or load_matrix()
    pattern = get_anchor_pattern(anchor_pattern_id)
    if not pattern:
        return {"anchor_pattern_id": anchor_pattern_id, "join_edges": [], "data_gaps": [f"unknown anchor: {anchor_pattern_id}"]}

    params = params or {}
    if anchor_ts is None:
        anchor_ts = parse_ts(params.get("alert_time")) or parse_ts(params.get("time_start"))

    chain = list(pattern.get("recommended_chain") or [])
    host_ip_map = build_host_ip_map(bundles, params)
    edges: list[dict[str, Any]] = []
    data_gaps: list[str] = []
    seen: set[str] = set()

    for join_id in chain:
        for step in expand_path(join_id, matrix):
            if step in seen:
                continue
            seen.add(step)
            pairs = find_join_pairs(
                step,
                bundles,
                anchor_ts=anchor_ts,
                host_ip_map=host_ip_map,
                matrix=matrix,
            )
            if pairs:
                edges.extend(pairs)
            else:
                join_def = get_join(step, matrix)
                label = (join_def or {}).get("purpose") or step
                data_gaps.append(f"no_match:{step} ({label})")

    return {
        "anchor_pattern_id": anchor_pattern_id,
        "recommended_chain": chain,
        "join_edges": edges,
        "data_gaps": data_gaps,
    }


def _resolve_param_path(path: str, context: dict[str, Any]) -> Any:
    if not path:
        return None
    if path.startswith("$"):
        path = path[1:]
    parts = path.split(".")
    cur: Any = context
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _plan_join_side(
    side_spec: dict[str, Any],
    *,
    context: dict[str, Any],
    asset_ids: list[str],
    load_asset: Any,
    matrix: dict[str, Any],
    join_id: str,
    side: str,
) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    asset_types = side_spec.get("asset_types") or []
    requested_asset_types = {str(t) for t in asset_types if t}
    template_id = side_spec.get("template_id")
    param_map = side_spec.get("param_map") or {}

    resolved_params: dict[str, Any] = {}
    for dest, src in param_map.items():
        val = _resolve_param_path(str(src), context)
        if val not in (None, ""):
            resolved_params[str(dest)] = val

    for asset_id in asset_ids:
        asset = load_asset(asset_id)
        atype = str(asset.get("asset_type") or "")
        covered_types = {atype, *(str(t) for t in (asset.get("covers_asset_types") or []))}
        matched_requested = requested_asset_types & covered_types
        if requested_asset_types and not matched_requested:
            continue
        if not template_id:
            continue
        params = dict(resolved_params)
        if not param_map:
            params.update(context.get("params") or {})
        tasks.append(
            {
                "join_id": join_id,
                "side": side,
                "asset_id": asset_id,
                "asset_type": atype,
                "matched_asset_type": sorted(matched_requested)[0] if matched_requested else atype,
                "requested_asset_types": sorted(requested_asset_types),
                "template_id": template_id,
                "params": params,
                "purpose": side_spec.get("purpose"),
            }
        )
    return tasks


def plan_fetch(
    anchor_pattern_id: str,
    params: dict[str, Any],
    *,
    asset_ids: list[str] | None = None,
    load_asset: Any | None = None,
    matrix: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build ordered fetch task queue from anchor recommended_chain + join fetch_plan."""
    matrix = matrix or load_matrix()
    pattern = get_anchor_pattern(anchor_pattern_id)
    if not pattern:
        return []

    params = resolve_anchor_params(anchor_pattern_id, params, matrix=matrix)

    if load_asset is None:
        from registry import load_asset as _load_asset

        load_asset = _load_asset

    bundle_id = pattern.get("bundle_id")
    if not asset_ids and bundle_id:
        from registry import load_bundle

        asset_ids = list(load_bundle(bundle_id).get("asset_ids") or [])
    asset_ids = asset_ids or []

    context: dict[str, Any] = {
        "params": dict(params),
        "bridge": {},
        "left": {},
        "anchor": dict(params),
    }
    if params.get("attacker_ip") and not context["params"].get("src_ip"):
        context["params"]["src_ip"] = params["attacker_ip"]

    tasks: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for join_id in pattern.get("recommended_chain") or []:
        for step in expand_path(join_id, matrix):
            join_def = get_join(step, matrix)
            if not join_def:
                continue
            fetch_plan = join_def.get("fetch_plan") or {}
            for side in ("left", "right"):
                side_spec = fetch_plan.get(side)
                if not side_spec:
                    continue
                for task in _plan_join_side(
                    side_spec,
                    context=context,
                    asset_ids=asset_ids,
                    load_asset=load_asset,
                    matrix=matrix,
                    join_id=step,
                    side=side,
                ):
                    key = (task["asset_id"], task["template_id"], json.dumps(task["params"], sort_keys=True))
                    if key in seen:
                        continue
                    seen.add(key)
                    tasks.append(task)

            bridge_keys = join_def.get("anchor_keys") or []
            for ak in bridge_keys:
                role = ak.get("role")
                field = ak.get("field")
                if role and field:
                    val = _resolve_param_path(f"params.{field}", context) or context["params"].get(field)
                    if val not in (None, ""):
                        context["bridge"][str(role)] = val
                        if role == "victim_host":
                            context["bridge"]["host"] = val
                            context["params"]["host"] = val

    return tasks


def correlate_bundles(
    bundles: dict[str, list[dict[str, Any]]],
    *,
    scenarios: list[str] | None = None,
    anchor_pattern_id: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """High-level entry: run anchor chain correlation on evidence bundles."""
    matrix = load_matrix()
    pid = anchor_pattern_id or anchor_pattern_for_scenarios(scenarios or [], matrix)
    if not pid:
        return {"join_edges": [], "data_gaps": ["no anchor_pattern for scenarios"]}
    return run_recommended_chain(pid, bundles, params=params, matrix=matrix)
