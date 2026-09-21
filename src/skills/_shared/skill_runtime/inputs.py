"""Adapt DataAsset evidence to Skill inputs, including optional completeness checks.

Concrete Skill helpers and execution are dependencies of this upper layer, not
of data-access. Fetch planning/expansion is delegated to scenario_fetch; normal
offline inputs and CLI flags retain their existing behavior.
"""

from __future__ import annotations

import json
import sys
from functools import wraps
from pathlib import Path
from typing import Any, Callable

# DATA_ACCESS_ROOT and _load_module retain historical skill_input import access.
from . import DATA_ACCESS_ROOT, SKILLS_ROOT
from .contracts import ensure_skill_envelope
from .execution import load_skill_module as _load_module, run_completeness_assess

import fetch as data_fetch
from fetch import begin_fetch_attempt_collection, end_fetch_attempt_collection
from fetch_metadata import build_asset_execution_meta, task_asset_ids, unique_ids
from fetch_summary import attach_fetch_summary
from registry import bundle_to_registered_assets, load_bundle
# Keep fetch_template_map/_coalesce_trace_tasks available to existing importers.
from scenario_fetch import (
    _coalesce_trace_tasks,
    _fetch_asset_list_lateral_evidence,
    _fetch_asset_list_waf_target_fallback,
    _has_source_ip_context,
    _has_target_context,
    _merge_trace_evidence,
    _scenario_for_anchor_pattern_id,
    append_anchor_bundle_assets_for_chain,
    attach_correlation_fetch_plan,
    fetch_scenario_evidence,
    fetch_template_map,
    resolve_investigation_params,
)

DEFAULT_INTENT: dict[str, str] = {
    "completeness": "数据源完整性评估",
    "traceability": "外网攻击IP溯源，查第一个攻破点和横向范围",
    "alert": "分析 WEB 安全告警，确认误报/真实/是否成功",
    "risk": "识别对外监听进程的高危命令执行与主动外连",
    "fetch": "按调查参数从 dataasset 拉取多源证据（仅取数，不做研判）",
}

DEFAULT_BUNDLE: dict[str, str] = {
    # This committed bundle is present in both source and Community exports.
    "completeness": "bundle-incident-trace-default",
    "traceability": "bundle-incident-trace-default",
    "alert": "bundle-alert-confirm-min",
    "risk": "bundle-host-risk-default",
    "fetch": "bundle-incident-trace-default",
}

BUILDER_SKILL_IDS = {
    "build_alert_payload": "alert-confirmation",
    "build_risk_payload": "risk-identification",
    "build_evidence_fetch_payload": "evidence-fetch",
}


def parse_params(params_json: str | None = None, params_file: str | None = None) -> dict[str, Any]:
    """Read file parameters preferentially; JSON errors fail before any fetch."""
    if params_file:
        return json.loads(Path(params_file).read_text(encoding="utf-8"))
    if params_json:
        return json.loads(params_json)
    return {}


def bundle_scenarios(bundle_id: str) -> list[str]:
    """Use the selected asset bundle as the default scenario contract."""
    bundle = load_bundle(bundle_id)
    return list(bundle.get("investigation_scenarios") or [])


def waf_events_to_primary_alerts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adapt normalized WAF evidence without making a triage decision."""
    from waf_payload import extract_waf_request_method, resolve_waf_payload

    alerts: list[dict[str, Any]] = []
    for i, ev in enumerate(events):
        payload, payload_meta = resolve_waf_payload(ev)
        if not payload and ev.get("request.header"):
            payload = ev.get("request.header")
        method = extract_waf_request_method(ev)
        alert: dict[str, Any] = {
            "alert_id": ev.get("alert_id") or ev.get("trace_id") or ev.get("rule_id") or f"WAF-FETCH-{i + 1:03d}",
            "source": "waf",
            "timestamp": ev.get("timestamp") or ev.get("__time__"),
            "src_ip": ev.get("src_ip") or ev.get("ip"),
            "url": ev.get("url"),
            "rule_id": ev.get("rule_id") or ev.get("plugin_name"),
            "rule_name": ev.get("rule_name") or ev.get("event"),
            "payload": payload,
            "action": ev.get("action", "logged"),
            "host": ev.get("host"),
            "target_ip": ev.get("target_ip") or ev.get("upstream_addr"),
            "level": ev.get("level"),
            "plugin_name": ev.get("plugin_name"),
        }
        if method:
            alert["method"] = method
        if payload_meta:
            alert["payload_meta"] = payload_meta
        alerts.append(alert)
    return alerts


def correlated_from_bundles(bundles: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Expose only the evidence types accepted by alert confirmation."""
    keys = ("web_access_log", "host_exec", "host_connect", "host_file_op", "host_persistence")
    return {k: list(bundles.get(k, [])) for k in keys}


def build_completeness_payload(
    bundle_id: str,
    params: dict[str, Any],
    *,
    investigation_intent: str | None = None,
    scenarios: list[str] | None = None,
) -> dict[str, Any]:
    """Build a metadata-only input; never read credentials or fetch logs."""
    return ensure_skill_envelope({
        "investigation_intent": investigation_intent or DEFAULT_INTENT["completeness"],
        "scenarios": scenarios if scenarios is not None else bundle_scenarios(bundle_id),
        "params": params,
        "registered_assets": bundle_to_registered_assets(bundle_id),
        "bundle_id": bundle_id,
    }, "data-source-completeness")


def _trace_anchor_pattern_ids(
    scenarios: list[str],
    anchor_pattern_id: str | None = None,
) -> list[str]:
    """Resolve traceability anchor patterns (S1+S3 → merged chains)."""
    trace_scripts = SKILLS_ROOT / "traceability-analysis" / "scripts"
    if str(trace_scripts) not in sys.path:
        sys.path.insert(0, str(trace_scripts))
    from correlation_trace import anchor_patterns_for_trace

    return anchor_patterns_for_trace(scenarios, anchor_pattern_id=anchor_pattern_id)


def build_traceability_payload(
    bundle_id: str | None,
    params: dict[str, Any],
    *,
    investigation_intent: str | None = None,
    scenarios: list[str] | None = None,
    anchor_pattern_id: str | None = None,
    fetch_live: bool = False,
    dry_run: bool = False,
    skip_completeness: bool = False,
    completeness_precheck: dict[str, Any] | None = None,
    asset_ids: list[str] | None = None,
    full_impact_fetch: bool = False,
) -> dict[str, Any]:
    """Build traceability input and, for asset lists, execute lateral expansion.

    Asset-list mode uses the same source-host SSH discovery and target-host
    impact fetch contract as bundle mode; it is not a one-pass convenience path.
    """
    full_impact_fetch = bool(full_impact_fetch or params.get("full_impact_fetch") is True)
    bid = bundle_id or (None if asset_ids else DEFAULT_BUNDLE["traceability"])
    if scenarios is not None:
        scenarios = scenarios
    elif bid:
        scenarios = bundle_scenarios(bid)
    elif anchor_pattern_id:
        inferred_scenario = _scenario_for_anchor_pattern_id(anchor_pattern_id)
        scenarios = [inferred_scenario] if inferred_scenario else ["S1"]
    else:
        scenarios = ["S1"]
    pattern_ids = _trace_anchor_pattern_ids(scenarios, anchor_pattern_id)
    params = resolve_investigation_params(
        params,
        scenarios=scenarios,
        anchor_pattern_id=pattern_ids[0] if pattern_ids else anchor_pattern_id,
    )
    payload: dict[str, Any] = {
        "investigation_intent": investigation_intent or DEFAULT_INTENT["traceability"],
        "scenarios": scenarios,
        "params": params,
    }
    if scenarios:
        payload["scenario"] = scenarios[0]
    if bid:
        payload["bundle_id"] = bid
    if asset_ids:
        payload["asset_ids"] = list(asset_ids)
    if pattern_ids:
        payload["correlation_anchor_pattern"] = pattern_ids[0]
        if len(pattern_ids) > 1:
            payload["correlation_anchor_patterns"] = pattern_ids

    if completeness_precheck is not None:
        payload["completeness_precheck"] = completeness_precheck
    elif not skip_completeness and bid:
        pre = build_completeness_payload(
            bid, params, investigation_intent=investigation_intent, scenarios=scenarios
        )
        payload["completeness_precheck"] = run_completeness_assess(pre)
    else:
        payload["completeness_precheck"] = {
            "overall_verdict": "partial_traceable",
            "confidence": 0.5,
            "next_skill_blocked": False,
            "data_gaps": ["completeness skipped"],
        }

    if fetch_live or dry_run:
        fetch_attempts, fetch_attempt_token = begin_fetch_attempt_collection()
        try:
            if asset_ids:
                fetch_payload = build_evidence_fetch_payload(
                    params,
                    asset_ids=asset_ids,
                    scenarios=scenarios,
                    anchor_pattern_id=pattern_ids[0] if pattern_ids else anchor_pattern_id,
                    fetch_live=fetch_live,
                    dry_run=dry_run,
                    full_impact_fetch=full_impact_fetch,
                )
                evidence = fetch_payload.get("evidence_bundles") or {}
                access_meta = dict(fetch_payload.get("data_access") or {})
                payload["params"] = fetch_payload.get("params") or params
                if fetch_payload.get("correlation_fetch_plan"):
                    payload["correlation_fetch_plan"] = fetch_payload["correlation_fetch_plan"]
                if fetch_payload.get("correlation_anchor_pattern"):
                    payload["correlation_anchor_pattern"] = fetch_payload["correlation_anchor_pattern"]
            else:
                evidence, access_meta = fetch_scenario_evidence(
                    bid,
                    params,
                    scenarios=scenarios,
                    anchor_pattern_id=anchor_pattern_id,
                    anchor_pattern_ids=pattern_ids if len(pattern_ids) > 1 else None,
                    resolve_secrets=not dry_run,
                    full_impact_fetch=full_impact_fetch,
                )
        finally:
            end_fetch_attempt_collection(fetch_attempt_token)
        access_meta["fetch_attempts"] = fetch_attempts
        payload["evidence_bundles"] = evidence
        payload["data_access"] = {
            **access_meta,
            "fetch_mode": "dry_run" if dry_run else "live",
        }
        payload["correlation_fetch_plan"] = access_meta.get(
            "correlation_fetch_plan", payload.get("correlation_fetch_plan", [])
        )
        if access_meta.get("correlation_anchor_pattern"):
            payload["correlation_anchor_pattern"] = access_meta["correlation_anchor_pattern"]
        if access_meta.get("correlation_anchor_patterns"):
            payload["correlation_anchor_patterns"] = access_meta["correlation_anchor_patterns"]
    else:
        payload.setdefault("evidence_bundles", {})

    _inject_hosts_into_trace_payload(payload)
    data_access = payload.get("data_access") or {}
    enriched = data_access.get("enriched_params")
    if isinstance(enriched, dict) and enriched:
        payload["params"] = {**(payload.get("params") or {}), **enriched}
    attach_fetch_summary(payload)
    return ensure_skill_envelope(payload, "traceability-analysis")


def _inject_hosts_into_trace_payload(payload: dict[str, Any]) -> None:
    """Merge dataasset/hosts/ into evidence_bundles.asset_inventory when in scope."""
    trace_scripts = SKILLS_ROOT / "traceability-analysis" / "scripts"
    if str(trace_scripts) not in sys.path:
        sys.path.insert(0, str(trace_scripts))
    from host_normalize import inject_registered_hosts, merge_registry_host_ips

    params = dict(payload.get("params") or {})
    bundles = dict(payload.get("evidence_bundles") or {})
    enriched, injected = inject_registered_hosts(bundles, params)
    if injected:
        payload["evidence_bundles"] = enriched
        payload["params"] = merge_registry_host_ips(params, enriched.get("asset_inventory") or [])
        payload["host_registry"] = {
            "source": "dataasset/hosts",
            "injected_host_ids": injected,
        }


def _collect_fetch_metadata(builder: Callable) -> Callable:
    """Retain all attempts across bootstrap/early-return paths of input builders.

    Reuse a caller's context-local collector/cache when present, but attach only
    this call's attempts. The owner resets both contexts in finally, including
    failed fetches, so independent investigations cannot share evidence caches.
    """
    @wraps(builder)
    def collected(*args: Any, **kwargs: Any) -> dict[str, Any]:
        attempts = data_fetch.current_fetch_attempt_collection()
        tokens = None
        if attempts is None:
            attempts, tokens = begin_fetch_attempt_collection()
        start = len(attempts)
        try:
            payload = builder(*args, **kwargs)
            access = payload.get("data_access") or {}
            if access.get("fetch_mode") in {"live", "dry_run"}:
                access["fetch_attempts"] = list(attempts[start:])
                payload["data_access"] = access
                attach_fetch_summary(payload)
            # Decorated builders include early-return bootstrap paths. Stamp at
            # the wrapper boundary so every path emits the same public envelope.
            return ensure_skill_envelope(payload, BUILDER_SKILL_IDS[builder.__name__])
        finally:
            if tokens is not None:
                end_fetch_attempt_collection(tokens)
    return collected


@_collect_fetch_metadata
def build_alert_payload(
    bundle_id: str | None,
    params: dict[str, Any],
    *,
    investigation_intent: str | None = None,
    fetch_live: bool = False,
    dry_run: bool = False,
    skip_completeness: bool = False,
    primary_alerts: list[dict[str, Any]] | None = None,
    completeness_precheck: dict[str, Any] | None = None,
    asset_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Preserve supplied checks; otherwise assess completeness before live fetch."""
    bid = bundle_id or (None if asset_ids else DEFAULT_BUNDLE["alert"])
    payload: dict[str, Any] = {
        "investigation_intent": investigation_intent or DEFAULT_INTENT["alert"],
        "scenario": "S4",
        "params": params,
    }
    if bid:
        payload["bundle_id"] = bid
    if asset_ids:
        payload["asset_ids"] = list(asset_ids)

    if completeness_precheck is not None:
        payload["completeness_precheck"] = completeness_precheck
    elif not skip_completeness and bid:
        pre = build_completeness_payload(bid, params, scenarios=["S4"])
        payload["completeness_precheck"] = run_completeness_assess(pre)
    else:
        payload["completeness_precheck"] = {
            "overall_verdict": "partial_traceable" if (asset_ids or skip_completeness) else "alert_triage_only",
            "confidence": 0.5,
            "next_skill_blocked": False,
            "data_gaps": ["completeness skipped"],
        }

    evidence: dict[str, list[dict[str, Any]]] = {}
    if fetch_live or dry_run:
        if asset_ids:
            fetch_payload = build_evidence_fetch_payload(
                params,
                asset_ids=asset_ids,
                scenarios=["S4"],
                anchor_pattern_id="S4_alert_confirmation",
                fetch_live=fetch_live,
                dry_run=dry_run,
            )
            evidence = fetch_payload.get("evidence_bundles") or {}
            access_meta = dict(fetch_payload.get("data_access") or {})
            payload["params"] = fetch_payload.get("params") or params
            payload["fetch_summary"] = fetch_payload.get("fetch_summary")
        else:
            evidence, access_meta = fetch_scenario_evidence(
                bid,
                params,
                scenarios=["S4"],
                anchor_pattern_id="S4_alert_confirmation",
                resolve_secrets=not dry_run,
            )
        payload["data_access"] = {
            **access_meta,
            "fetch_mode": "dry_run" if dry_run else "live",
        }
        payload["correlation_fetch_plan"] = access_meta.get("correlation_fetch_plan", [])
        if access_meta.get("correlation_anchor_pattern"):
            payload["correlation_anchor_pattern"] = access_meta["correlation_anchor_pattern"]
        enriched = access_meta.get("enriched_params")
        if isinstance(enriched, dict) and enriched:
            payload["params"] = {**params, **enriched}
        if evidence:
            from waf_enrich import enrich_evidence_waf_targets

            payload["waf_target_enrich"] = enrich_evidence_waf_targets(evidence)

    if primary_alerts is not None:
        payload["primary_alerts"] = primary_alerts
    elif params.get("primary_alerts"):
        payload["primary_alerts"] = params["primary_alerts"]
    elif evidence.get("waf_alert"):
        payload["primary_alerts"] = waf_events_to_primary_alerts(evidence["waf_alert"])
    else:
        payload["primary_alerts"] = []

    if evidence:
        payload["evidence_bundles"] = evidence
    payload["correlated_evidence"] = (
        correlated_from_bundles(evidence) if evidence else params.get("correlated_evidence", {})
    )
    attach_fetch_summary(payload)
    return payload


@_collect_fetch_metadata
def build_risk_payload(
    bundle_id: str,
    params: dict[str, Any],
    *,
    investigation_intent: str | None = None,
    scenarios: list[str] | None = None,
    risk_modules: list[str] | None = None,
    fetch_live: bool = False,
    dry_run: bool = False,
    skip_completeness: bool = False,
    completeness_precheck: dict[str, Any] | None = None,
    user_rules: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Adapt one bundle and optional rules; dry-run never resolves Vault secrets."""
    scenario_list = scenarios if scenarios is not None else bundle_scenarios(bundle_id) or ["S5"]
    scenario = scenario_list[0] if scenario_list else "S5"
    payload: dict[str, Any] = {
        "investigation_intent": investigation_intent or DEFAULT_INTENT["risk"],
        "scenario": scenario,
        "params": params,
        "bundle_id": bundle_id,
    }
    if risk_modules is not None:
        payload["risk_modules"] = risk_modules
    if user_rules is not None:
        payload["user_rules"] = user_rules
    elif params.get("user_rules"):
        payload["user_rules"] = params["user_rules"]

    if completeness_precheck is not None:
        payload["completeness_precheck"] = completeness_precheck
    elif not skip_completeness:
        pre = build_completeness_payload(
            bundle_id,
            params,
            investigation_intent=investigation_intent,
            scenarios=scenario_list,
        )
        payload["completeness_precheck"] = run_completeness_assess(pre)
    else:
        payload["completeness_precheck"] = {
            "overall_verdict": "partial_traceable",
            "confidence": 0.5,
            "next_skill_blocked": False,
            "data_gaps": ["completeness skipped"],
        }

    if fetch_live or dry_run:
        evidence, access_meta = fetch_scenario_evidence(
            bundle_id,
            params,
            scenarios=scenario_list,
            resolve_secrets=not dry_run,
        )
        payload["evidence_bundles"] = evidence
        payload["data_access"] = {
            **access_meta,
            "fetch_mode": "dry_run" if dry_run else "live",
        }
        payload["correlation_fetch_plan"] = access_meta.get("correlation_fetch_plan", [])
        if access_meta.get("correlation_anchor_pattern"):
            payload["correlation_anchor_pattern"] = access_meta["correlation_anchor_pattern"]
    else:
        payload.setdefault("evidence_bundles", {})

    attach_fetch_summary(payload)
    return payload


@_collect_fetch_metadata
def build_evidence_fetch_payload(
    params: dict[str, Any],
    *,
    bundle_id: str | None = None,
    asset_ids: list[str] | None = None,
    investigation_intent: str | None = None,
    scenarios: list[str] | None = None,
    anchor_pattern_id: str | None = None,
    fetch_live: bool = True,
    dry_run: bool = False,
    include_completeness: bool = False,
    full_impact_fetch: bool = False,
) -> dict[str, Any]:
    """Build payload for evidence-fetch skill (fetch only, no triage).

    When an explicit asset list includes host/syslog evidence, the fetch also
    performs bounded SSH lateral discovery and target-host expansion so later
    triage cannot miss a successful login outside the entry host scope.
    """
    full_impact_fetch = bool(full_impact_fetch or params.get("full_impact_fetch") is True)
    if asset_ids and not bundle_id:
        bid = None
        scenario_list = list(scenarios) if scenarios is not None else []
    else:
        bid = bundle_id or DEFAULT_BUNDLE["fetch"]
        scenario_list = scenarios if scenarios is not None else bundle_scenarios(bid)
    resolved_params = resolve_investigation_params(
        params,
        scenarios=scenario_list,
        anchor_pattern_id=anchor_pattern_id,
    )
    payload: dict[str, Any] = {
        "skill": "evidence-fetch",
        "investigation_intent": investigation_intent or DEFAULT_INTENT["fetch"],
        "params": resolved_params,
    }
    if bid:
        payload["bundle_id"] = bid
    if scenario_list:
        payload["scenarios"] = scenario_list
        payload["scenario"] = scenario_list[0]
    if anchor_pattern_id:
        payload["correlation_anchor_pattern"] = anchor_pattern_id
    if asset_ids:
        payload["asset_ids"] = list(asset_ids)

    if include_completeness and bid:
        pre = build_completeness_payload(
            bid,
            resolved_params,
            investigation_intent=investigation_intent,
            scenarios=scenario_list,
        )
        payload["completeness_precheck"] = run_completeness_assess(pre)

    if fetch_live or dry_run:
        if asset_ids:
            from s4_gateway_bootstrap import (  # noqa: WPS433
                ensure_s4_alert_asset_ids,
                should_s4_gateway_append,
                s4_gateway_bootstrap_meta,
            )
            from s4_fetch_bootstrap import fetch_s4_bootstrap, should_s4_bootstrap  # noqa: WPS433
            from trace_d1_bootstrap import (  # noqa: WPS433
                ensure_d1_asset_ids,
                fetch_trace_d1_bootstrap,
                infer_d1_targets_from_host_exec,
                should_trace_d1_bootstrap_for_asset_fetch,
            )

            fetch_params = dict(resolved_params)
            d1_meta: dict[str, Any] | None = None
            d1_evidence: dict[str, list[dict[str, Any]]] = {}
            original_assets = list(asset_ids)
            asset_list = list(asset_ids)
            chain_appended_assets: list[dict[str, str]] = []
            s4_gw_meta: dict[str, Any] | None = None
            s4_asset_list = list(asset_list)
            if should_s4_gateway_append(asset_list):
                s4_asset_list = ensure_s4_alert_asset_ids(asset_list)
                s4_gw_meta = s4_gateway_bootstrap_meta(original_assets, s4_asset_list)
            anchor_pattern_ids = [anchor_pattern_id] if anchor_pattern_id else None
            explicit_s4_time_only = should_s4_bootstrap(
                scenario_list,
                anchor_pattern_ids,
                fetch_params,
            )
            waf_only_time_window = (
                not scenario_list
                and not anchor_pattern_id
                and should_s4_bootstrap(["S4"], None, fetch_params)
            )
            explicit_s4_context = anchor_pattern_id == "S4_alert_confirmation" or "S4" in scenario_list
            source_ip_bootstrap = (
                _has_source_ip_context(fetch_params)
                and not _has_target_context(fetch_params)
                and (explicit_s4_context or (not scenario_list and not anchor_pattern_id))
            )
            s4_time_only_bootstrap = bool(
                s4_gw_meta
                and (explicit_s4_time_only or waf_only_time_window or source_ip_bootstrap)
            )
            if s4_time_only_bootstrap:
                evidence, s4_meta = fetch_s4_bootstrap(
                    s4_asset_list,
                    fetch_params,
                    resolve_secrets=not dry_run,
                )
                enriched = s4_meta.get("enriched_params") or {}
                if enriched:
                    fetch_params = {**fetch_params, **enriched}
                    payload["params"] = fetch_params
                fetch_strategy = "s4_gateway_bootstrap+s4_bootstrap"
                access_meta = {
                    **s4_meta,
                    "fetch_strategy": fetch_strategy,
                    "asset_ids": s4_asset_list,
                    **build_asset_execution_meta(
                        declared_asset_ids=original_assets,
                        fetch_asset_ids=s4_asset_list,
                        executed_asset_ids=s4_meta.get("executed_asset_ids") or [],
                        skip_reason="not_selected_by_s4_bootstrap",
                    ),
                }
                if s4_gw_meta:
                    access_meta["s4_gateway_bootstrap"] = s4_gw_meta.get("s4_gateway_bootstrap")
                if bid:
                    access_meta["bundle_id"] = bid
                payload["evidence_bundles"] = evidence
                payload["data_access"] = {
                    **access_meta,
                    "fetch_mode": "dry_run" if dry_run else "live",
                }
                payload["correlation_fetch_plan"] = access_meta.get("correlation_fetch_plan", [])
                attach_fetch_summary(payload)
                return payload
            asset_list = s4_asset_list
            if anchor_pattern_id:
                asset_list, chain_appended_assets = append_anchor_bundle_assets_for_chain(
                    asset_list,
                    anchor_pattern_id,
                )
            if should_trace_d1_bootstrap_for_asset_fetch(fetch_params, asset_list):
                d1_evidence, d1_meta = fetch_trace_d1_bootstrap(
                    ensure_d1_asset_ids(asset_list),
                    fetch_params,
                    resolve_secrets=not dry_run,
                )
                enriched = d1_meta.get("enriched_params") or {}
                if enriched:
                    fetch_params = {**fetch_params, **enriched}
                    payload["params"] = fetch_params
                asset_list = ensure_d1_asset_ids(asset_list)

            evidence = data_fetch.fetch_bundle_evidence(
                asset_list,
                fetch_params,
                resolve_secrets=not dry_run,
            )
            inferred_d1_targets: list[dict[str, Any]] = []
            if (
                not d1_meta
                and fetch_params.get("resolve_attacker_ip") is not False
                and not fetch_params.get("attacker_ip")
                and not fetch_params.get("attacker_ips")
                and fetch_params.get("time_start")
            ):
                inferred_d1_targets = infer_d1_targets_from_host_exec(evidence)
                if inferred_d1_targets:
                    target_ip = str(inferred_d1_targets[0]["target_ip"])
                    d1_params = {
                        **fetch_params,
                        "target_ip": target_ip,
                        "hosts": [target_ip],
                    }
                    d1_evidence, d1_meta = fetch_trace_d1_bootstrap(
                        ensure_d1_asset_ids(asset_list),
                        d1_params,
                        resolve_secrets=not dry_run,
                    )
                    enriched = d1_meta.get("enriched_params") or {}
                    if enriched:
                        fetch_params = {**fetch_params, **enriched}
                        payload["params"] = fetch_params
                    asset_list = ensure_d1_asset_ids(asset_list)
            if d1_evidence:
                evidence = _merge_trace_evidence(d1_evidence, evidence)
            waf_fallback_evidence, waf_fallback_meta = _fetch_asset_list_waf_target_fallback(
                asset_list,
                fetch_params,
                evidence,
                resolve_secrets=not dry_run,
            )
            if waf_fallback_evidence:
                evidence = _merge_trace_evidence(evidence, waf_fallback_evidence)
            lateral_evidence, lateral_meta = _fetch_asset_list_lateral_evidence(
                asset_list,
                fetch_params,
                evidence,
                resolve_secrets=not dry_run,
            )
            if lateral_evidence:
                evidence = _merge_trace_evidence(evidence, lateral_evidence)
            fetch_strategy = "asset_list"
            if s4_gw_meta and d1_meta:
                fetch_strategy = "s4_gateway_bootstrap+trace_d1_bootstrap+asset_list"
            elif s4_gw_meta:
                fetch_strategy = s4_gw_meta.get("fetch_strategy") or "s4_gateway_bootstrap+asset_list"
            elif d1_meta:
                fetch_strategy = "trace_d1_bootstrap+asset_list"
            if lateral_meta:
                fetch_strategy = f"{fetch_strategy}+lateral_ssh_discovery"
            executed_asset_ids = unique_ids(
                asset_list
                + (lateral_meta or {}).get("asset_ids", [])
                + (lateral_meta or {}).get("discovery_asset_ids", [])
            )
            access_meta: dict[str, Any] = {
                "source": "dataasset",
                "fetch_strategy": fetch_strategy,
                "asset_ids": asset_list,
                "correlation_fetch_plan": (
                    (d1_meta.get("correlation_fetch_plan", []) if d1_meta else [])
                    + ((lateral_meta or {}).get("correlation_fetch_plan") or [])
                ),
                **build_asset_execution_meta(
                    declared_asset_ids=original_assets,
                    fetch_asset_ids=asset_list,
                    executed_asset_ids=unique_ids(
                        task_asset_ids((d1_meta or {}).get("correlation_fetch_plan") or [])
                        + executed_asset_ids
                    ),
                    skip_reason="not_selected_by_asset_fetch",
                ),
            }
            if s4_gw_meta:
                access_meta["s4_gateway_bootstrap"] = s4_gw_meta.get("s4_gateway_bootstrap")
            if d1_meta:
                access_meta["trace_d1_bootstrap"] = d1_meta.get("trace_d1_bootstrap")
                access_meta["enriched_params"] = d1_meta.get("enriched_params")
            if inferred_d1_targets:
                access_meta["trace_d1_inferred_targets"] = inferred_d1_targets
            if waf_fallback_meta:
                access_meta["waf_target_fallback"] = waf_fallback_meta
            if lateral_meta:
                access_meta["second_hop_impact_fetch"] = lateral_meta
            if chain_appended_assets:
                access_meta["trace_chain_appended_assets"] = chain_appended_assets
            if bid:
                access_meta["bundle_id"] = bid
        else:
            evidence, access_meta = fetch_scenario_evidence(
                bid,
                resolved_params,
                scenarios=scenario_list,
                anchor_pattern_id=anchor_pattern_id,
                resolve_secrets=not dry_run,
                full_impact_fetch=full_impact_fetch,
            )
        payload["evidence_bundles"] = evidence
        payload["data_access"] = {
            **access_meta,
            "fetch_mode": "dry_run" if dry_run else "live",
        }
        payload["correlation_fetch_plan"] = access_meta.get("correlation_fetch_plan", [])
        if access_meta.get("correlation_anchor_pattern"):
            payload["correlation_anchor_pattern"] = access_meta["correlation_anchor_pattern"]
    else:
        if asset_ids:
            payload.setdefault("evidence_bundles", {})
            access_meta = {
                "source": "dataasset",
                "fetch_mode": "plan_only",
                "fetch_strategy": "asset_list",
                "asset_ids": list(asset_ids),
            }
            if bid:
                access_meta["bundle_id"] = bid
            payload["data_access"] = access_meta
        else:
            attach_correlation_fetch_plan(payload, anchor_pattern_id=anchor_pattern_id)
            payload.setdefault("evidence_bundles", {})
            plan = payload.get("correlation_fetch_plan") or []
            declared_asset_ids = list(load_bundle(bid).get("asset_ids") or []) if bid else []
            planned_asset_ids = task_asset_ids(plan)
            asset_meta = build_asset_execution_meta(
                declared_asset_ids=declared_asset_ids,
                fetch_asset_ids=planned_asset_ids,
                executed_asset_ids=planned_asset_ids,
                skip_reason="not_selected_by_correlation_plan",
            )
            asset_meta["planned_asset_ids"] = list(asset_meta.get("executed_asset_ids") or [])
            asset_meta["executed_asset_ids"] = []
            payload["data_access"] = {
                "source": "dataasset",
                "fetch_mode": "plan_only",
                "bundle_id": bid,
                "fetch_strategy": "correlation_fetch_plan" if plan else "plan_only",
                "correlation_fetch_plan": plan,
                **asset_meta,
            }

    attach_fetch_summary(payload)
    return payload


def add_bundle_arguments(parser: Any, skill: str) -> None:
    """Keep shared CLI flags stable while builders live outside data-access."""
    group = parser.add_argument_group("dataasset / Vault")
    group.add_argument(
        "--from-bundle",
        action="store_true",
        help=f"从 dataasset/bundles 加载（配合 --bundle，默认 {DEFAULT_BUNDLE[skill]}）",
    )
    group.add_argument(
        "--bundle",
        metavar="BUNDLE_ID",
        help="资产包 ID",
    )
    group.add_argument("--intent", help="investigation_intent 文本")
    group.add_argument("--params", default="{}", help="调查参数 JSON")
    group.add_argument("--params-file", help="调查参数 JSON 文件")
    group.add_argument(
        "--fetch",
        action="store_true",
        help="经 SOPS Vault 拉 live 证据（SLS / SSH 读日志）",
    )
    group.add_argument(
        "--dry-run",
        action="store_true",
        help="构建 DataRequest，不解密 Vault",
    )
    if skill in ("traceability", "alert", "risk"):
        group.add_argument(
            "--skip-completeness",
            action="store_true",
            help="跳过内置完整性预检",
        )
    if skill in ("alert", "fetch", "traceability"):
        group.add_argument(
            "--asset-id",
            action="append",
            dest="asset_ids",
            metavar="ASSET_ID",
            help=(
                "指定资产 ID（可重复）；traceability/alert 在仅有受害 IP 时会自动 D1 反查；"
                "S4 仅 WAF 时会自动追加网关 access + host_exec/connect/file_op"
            ),
        )
    if skill == "fetch":
        group.add_argument(
            "--plan-only",
            action="store_true",
            help="只输出 correlation_fetch_plan，不执行 fetch",
        )
        group.add_argument(
            "--include-completeness",
            action="store_true",
            help="附带数据源完整性预检结果（不阻断取数）",
        )
    if skill == "traceability":
        group.add_argument(
            "--anchor-pattern",
            metavar="PATTERN_ID",
            help="覆盖 anchor-patterns 默认编排（如 S1_external_ip_trace）",
        )
        group.add_argument(
            "--full-impact-fetch",
            action="store_true",
            help="按资产包补拉完整影响面资产，避免 correlation plan 跳过 host_file_op/host_persistence 等声明资产",
        )
    if skill == "fetch":
        group.add_argument(
            "--anchor-pattern",
            metavar="PATTERN_ID",
            help="覆盖默认 correlation anchor pattern",
        )


def resolve_payload_from_cli(args: Any, skill: str, builder: Callable[..., dict[str, Any]]) -> dict[str, Any] | None:
    """Prefer explicit asset scope; do not invent a bundle for asset-list mode."""
    asset_ids = getattr(args, "asset_ids", None) if skill in ("fetch", "alert", "traceability") else None
    if not getattr(args, "from_bundle", False) and not asset_ids:
        return None
    params = parse_params(getattr(args, "params", "{}"), getattr(args, "params_file", None))
    explicit_bundle = getattr(args, "bundle", None)
    if (
        skill in ("fetch", "alert", "traceability")
        and asset_ids
        and not explicit_bundle
        and not getattr(args, "from_bundle", False)
    ):
        bundle_id = None
    else:
        bundle_id = explicit_bundle or DEFAULT_BUNDLE[skill]
    kwargs: dict[str, Any] = {
        "params": params,
        "investigation_intent": getattr(args, "intent", None),
        "bundle_id": bundle_id,
    }
    if bundle_id:
        pass  # bundle_id already in kwargs
    if skill in ("traceability", "alert", "risk"):
        kwargs["fetch_live"] = getattr(args, "fetch", False)
        kwargs["dry_run"] = getattr(args, "dry_run", False)
        kwargs["skip_completeness"] = getattr(args, "skip_completeness", False)
    if skill == "traceability":
        kwargs["anchor_pattern_id"] = getattr(args, "anchor_pattern", None)
        kwargs["full_impact_fetch"] = getattr(args, "full_impact_fetch", False)
        if asset_ids:
            kwargs["asset_ids"] = asset_ids
    if skill == "alert" and asset_ids:
        kwargs["asset_ids"] = asset_ids
    if skill == "fetch":
        kwargs["fetch_live"] = not getattr(args, "plan_only", False)
        kwargs["dry_run"] = getattr(args, "dry_run", False)
        kwargs["include_completeness"] = getattr(args, "include_completeness", False)
        kwargs["anchor_pattern_id"] = getattr(args, "anchor_pattern", None)
        asset_ids = getattr(args, "asset_ids", None)
        if asset_ids:
            kwargs["asset_ids"] = asset_ids
    return builder(**kwargs)


def load_input_payload(args: Any, skill: str, builder: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    """Select configured assets before file/stdin; fail rather than invent evidence."""
    bundled = resolve_payload_from_cli(args, skill, builder)
    if bundled is not None:
        return bundled
    input_path = getattr(args, "input", None)
    if input_path:
        return json.loads(Path(input_path).read_text(encoding="utf-8"))
    if not sys.stdin.isatty():
        return json.load(sys.stdin)
    raise SystemExit(
        f"no input: use --from-bundle, --asset-id, -i file.json, or pipe JSON to stdin\n"
        f"example: {Path(sys.argv[0]).name} --from-bundle "
        f'--params \'{{"attacker_ip":"203.0.113.10","time_start":"...","time_end":"..."}}\''
    )
