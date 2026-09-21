"""Fetch evidence from dataasset connectors. Credentials resolved via SOPS Vault."""

from __future__ import annotations

import json
import time
from copy import deepcopy
from collections import defaultdict
from contextvars import ContextVar, Token
from datetime import datetime
from typing import Any

from aggregate import filter_connectors_by_host, merge_aggregate_events, resolve_connector_ids
from connector_fetch_dispatch import ConnectorFetchRequest, enrich_connector_params, fetch_connector
from normalizer import normalize_events
from registry import get_connector_for_asset, load_asset, load_connector, load_templates, render_template
from template_select import resolve_src_ip_web_access_template_id
from template_select import build_fetch_plan, expand_multi_host_fetch_params
from vault import credentials_ref_only, resolve_credentials


_FETCH_ATTEMPTS: ContextVar[list[dict[str, Any]] | None] = ContextVar(
    "dataasset_fetch_attempts",
    default=None,
)
_FETCH_CACHE: ContextVar[dict[str, dict[str, Any]] | None] = ContextVar(
    "dataasset_fetch_cache",
    default=None,
)

EXECUTION_MODE_SKILL = "skill"
EXECUTION_MODE_ONBOARDING_TEST = "onboarding_test"
_EXECUTION_MODES = {EXECUTION_MODE_SKILL, EXECUTION_MODE_ONBOARDING_TEST}
_ASSET_STATUSES = {"discovery", "draft", "active", "disabled"}
_CONNECTOR_STATUSES = {"draft", "active", "disabled"}


def _enforce_execution_status(
    asset: dict[str, Any],
    connector: dict[str, Any],
    execution_mode: str,
) -> None:
    """Enforce lifecycle state at the last boundary before query execution.

    Normal Skill execution accepts only active objects. Onboarding diagnostics may
    exercise draft/discovery objects so operators can prove connectivity before
    promotion, but disabled objects remain an unconditional kill switch.
    """
    if execution_mode not in _EXECUTION_MODES:
        raise ValueError(f"unsupported DataAsset execution_mode={execution_mode!r}")

    asset_status = str(asset.get("status") or "draft")
    connector_status = str(connector.get("status") or "draft")
    if asset_status not in _ASSET_STATUSES:
        raise PermissionError(
            f"asset {asset.get('asset_id')!r} has unsupported status={asset_status!r}"
        )
    if connector_status not in _CONNECTOR_STATUSES:
        raise PermissionError(
            f"connector {connector.get('connector_id')!r} has unsupported status={connector_status!r}"
        )
    if asset_status == "disabled":
        raise PermissionError(f"asset {asset.get('asset_id')!r} is disabled")
    if connector_status == "disabled":
        raise PermissionError(f"connector {connector.get('connector_id')!r} is disabled")
    if execution_mode == EXECUTION_MODE_SKILL:
        if asset_status != "active":
            raise PermissionError(
                f"asset {asset.get('asset_id')!r} is not active (status={asset_status!r})"
            )
        if connector_status != "active":
            raise PermissionError(
                f"connector {connector.get('connector_id')!r} is not active "
                f"(status={connector_status!r})"
            )


def begin_fetch_attempt_collection() -> tuple[list[dict[str, Any]], tuple[Token, Token]]:
    """Start collecting connector query counts and caching identical requests."""
    attempts: list[dict[str, Any]] = []
    return attempts, (
        _FETCH_ATTEMPTS.set(attempts),
        _FETCH_CACHE.set({}),
    )


def end_fetch_attempt_collection(tokens: tuple[Token, Token]) -> None:
    attempt_token, cache_token = tokens
    _FETCH_ATTEMPTS.reset(attempt_token)
    _FETCH_CACHE.reset(cache_token)


def current_fetch_attempt_collection() -> list[dict[str, Any]] | None:
    """Return the active fetch-attempt collector, if a caller already opened one."""
    return _FETCH_ATTEMPTS.get()


def _record_fetch_attempt(attempt: dict[str, Any]) -> None:
    collector = _FETCH_ATTEMPTS.get()
    if collector is None:
        return
    collector.append({"attempt_index": len(collector) + 1, **attempt})


def fetch(
    asset_id: str,
    template_id: str,
    params: dict[str, Any],
    *,
    connector_id: str | None = None,
    resolve_secrets: bool = True,
    execution_mode: str = EXECUTION_MODE_SKILL,
) -> dict[str, Any]:
    """Execute one DataRequest, applying the asset's explicit masking rules.

    Connector credentials are not attached to events. Sensitive values already
    present in source logs are retained unless the asset masks their fields.
    Preserve incomplete-query metadata on cache hits as well as live attempts.
    The default mode is the production Skill boundary; onboarding callers must
    opt in explicitly before they can test draft/discovery configuration.
    """
    asset = load_asset(asset_id)
    connector = load_connector(connector_id) if connector_id else get_connector_for_asset(asset_id)
    _enforce_execution_status(asset, connector, execution_mode)
    fetch_params = enrich_connector_params(asset, connector, dict(params))
    ctype_pre = connector.get("connector_type")
    templates = load_templates()
    effective_template_id = resolve_src_ip_web_access_template_id(
        asset,
        connector,
        fetch_params,
        templates,
        template_id,
    )
    rendered = render_template(effective_template_id, fetch_params)
    credentials_ref = credentials_ref_only(connector) if ctype_pre != "local_file" else ""

    meta = {
        "asset_id": asset_id,
        "asset_type": asset["asset_type"],
        "template_id": effective_template_id,
        "requested_template_id": template_id if effective_template_id != template_id else None,
        "credentials_ref": credentials_ref,
        "connector_id": connector["connector_id"],
        "connector_type": connector["connector_type"],
    }

    attempt_base = {
        "asset_id": asset_id,
        "asset_type": str(asset.get("asset_type") or ""),
        "connector_id": str(connector.get("connector_id") or ""),
        "template_id": effective_template_id,
        "requested_template_id": template_id if effective_template_id != template_id else None,
        "time_start": fetch_params.get("time_start"),
        "time_end": fetch_params.get("time_end"),
    }
    try:
        if not resolve_secrets:
            _record_fetch_attempt(
                {
                    **attempt_base,
                    "status": "dry_run",
                    "returned_event_count": 0,
                    "truncated": False,
                }
            )
            return {
                **meta,
                "events": [],
                "query_meta": {"mode": "dry_run", "rendered": rendered},
            }

        cache = _FETCH_CACHE.get()
        cache_key = json.dumps(
            {
                "asset_id": asset_id,
                "connector_id": connector.get("connector_id"),
                "rendered": rendered,
            },
            ensure_ascii=True,
            sort_keys=True,
            default=str,
        )
        if cache is not None and cache_key in cache:
            cached = deepcopy(cache[cache_key])
            _record_fetch_attempt(
                {
                    **attempt_base,
                    "status": "cache_hit",
                    "returned_event_count": len(cached.get("events") or []),
                    "truncated": bool((cached.get("query_meta") or {}).get("truncated")),
                    "partial": bool((cached.get("query_meta") or {}).get("partial")),
                    "incomplete_reasons": list((cached.get("query_meta") or {}).get("incomplete_reasons") or []),
                }
            )
            return cached

        connector_type = connector["connector_type"]
        credentials: dict[str, Any] = {}
        if connector_type != "local_file":
            credentials = resolve_credentials(credentials_ref)
        rendered_for_fetch = dict(rendered)
        rendered_for_fetch["_templates"] = templates
        events, fetch_meta = fetch_connector(
            ConnectorFetchRequest(
                asset=asset,
                connector=connector,
                credentials=credentials,
                rendered=rendered_for_fetch,
                requested_template_id=template_id,
                effective_template_id=effective_template_id,
                load_connector=load_connector,
                resolve_credentials=resolve_credentials,
            )
        )
        query_meta = {"truncated": False, **fetch_meta}
        query_meta.setdefault("fetched_at", datetime.now().astimezone().isoformat())

        for ev in events:
            ev["_source_connector_id"] = connector["connector_id"]
            ev["_source_asset_id"] = asset_id
        events = normalize_events(events, asset)
        _record_fetch_attempt(
            {
                **attempt_base,
                "status": "success",
                "returned_event_count": len(events),
                "truncated": bool(query_meta.get("truncated")),
                "partial": bool(query_meta.get("partial")),
                "incomplete_reasons": list(query_meta.get("incomplete_reasons") or []),
            }
        )

        result = {
            **meta,
            "events": events,
            "query_meta": query_meta,
        }
        if cache is not None:
            cache[cache_key] = deepcopy(result)
        return result
    except Exception as exc:
        _record_fetch_attempt(
            {
                **attempt_base,
                "status": "failed",
                "returned_event_count": 0,
                "truncated": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
            }
        )
        raise


def _merge_pending_by_asset(pending: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    bundles: dict[str, list[dict[str, Any]]] = {}
    for asset_id, events in pending.items():
        asset = load_asset(asset_id)
        merged = merge_aggregate_events(asset, events)
        bundles.setdefault(asset["asset_type"], []).extend(merged)
    return bundles


def fetch_correlation_plan_evidence(
    tasks: list[dict[str, Any]],
    *,
    resolve_secrets: bool = True,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch evidence by ordered correlation_fetch_plan tasks.

    Each task comes from correlation_engine.plan_fetch and carries a join_id,
    side, asset_id, template_id and task-local params. Connectors are expanded
    per asset so multi-connector assets still work under the scenario plan.
    """
    import sys

    pending: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[tuple[str, str, str, str]] = set()
    for task in tasks:
        asset_id = str(task.get("asset_id") or "")
        template_id = str(task.get("template_id") or "")
        if not asset_id or not template_id:
            continue
        asset = load_asset(asset_id)
        task_params = dict(task.get("params") or {})
        connector_ids = [str(task["connector_id"])] if task.get("connector_id") else filter_connectors_by_host(
            asset,
            resolve_connector_ids(asset),
            task_params,
            load_connector,
        )
        for connector_id in connector_ids:
            key = (asset_id, connector_id, template_id, json.dumps(task_params, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            try:
                result = fetch(
                    asset_id,
                    template_id,
                    task_params,
                    connector_id=connector_id,
                    resolve_secrets=resolve_secrets,
                )
                pending[asset_id].extend(result.get("events", []))
            except NotImplementedError as exc:
                print(f"warning: skip {asset_id}:{connector_id}: {exc}", file=sys.stderr)
            except Exception as exc:
                print(
                    f"warning: fetch failed {asset_id}:{connector_id}: {exc}",
                    file=sys.stderr,
                )
            time.sleep(0.05)
    return _merge_pending_by_asset(pending)


def fetch_bundle_evidence(
    asset_ids: list[str],
    params: dict[str, Any],
    *,
    resolve_secrets: bool = True,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch multiple assets; multi-connector assets are merged and deduped."""
    import sys

    pending: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for host_params in expand_multi_host_fetch_params(params):
        plan = build_fetch_plan(
            asset_ids,
            host_params,
            load_asset=load_asset,
            load_connector=load_connector,
            load_templates=load_templates,
        )
        for item in plan:
            try:
                result = fetch(
                    item["asset_id"],
                    item["template_id"],
                    host_params,
                    connector_id=item["connector_id"],
                    resolve_secrets=resolve_secrets,
                )
                victim_host = (
                    host_params.get("host_ip")
                    or host_params.get("host")
                    or host_params.get("host_name")
                )
                for ev in result.get("events", []):
                    tagged = dict(ev)
                    if victim_host:
                        tagged["_victim_host"] = str(victim_host)
                    pending[item["asset_id"]].append(tagged)
            except NotImplementedError as exc:
                print(f"warning: skip {item['asset_id']}:{item['connector_id']}: {exc}", file=sys.stderr)
            except Exception as exc:
                print(
                    f"warning: fetch failed {item['asset_id']}:{item['connector_id']}: {exc}",
                    file=sys.stderr,
                )
            time.sleep(0.05)

    return _merge_pending_by_asset(pending)
