"""Helpers for reporting which data assets were actually queried."""

from __future__ import annotations

from typing import Any, Iterable


def unique_ids(values: Iterable[Any] | None) -> list[str]:
    """Return stable, non-empty string ids without duplicates."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def task_asset_ids(tasks: Iterable[dict[str, Any]] | None) -> list[str]:
    """Extract unique asset ids from fetch tasks."""
    return unique_ids(task.get("asset_id") for task in tasks or [])


def build_asset_execution_meta(
    *,
    declared_asset_ids: Iterable[Any] | None,
    executed_asset_ids: Iterable[Any] | None,
    fetch_asset_ids: Iterable[Any] | None = None,
    skip_reason: str = "not_selected_by_fetch_strategy",
) -> dict[str, Any]:
    """Describe declared vs executed assets for fetch_summary and reports."""
    declared = unique_ids(declared_asset_ids)
    executed = unique_ids(executed_asset_ids)
    fetch_assets = unique_ids(fetch_asset_ids) or executed
    executed_set = set(executed)
    skipped = [asset_id for asset_id in declared if asset_id not in executed_set]

    meta: dict[str, Any] = {
        "declared_asset_ids": declared,
        "fetch_asset_ids": fetch_assets,
        "executed_asset_ids": executed,
    }
    if skipped:
        meta["skipped_asset_ids"] = skipped
        meta["skipped_assets"] = [
            {"asset_id": asset_id, "reason": skip_reason}
            for asset_id in skipped
        ]
    else:
        meta["skipped_asset_ids"] = []
        meta["skipped_assets"] = []
    return meta
