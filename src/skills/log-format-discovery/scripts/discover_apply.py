"""Apply log-format-discovery mapping JSON to dataasset files."""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

SKILL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_ROOT.parents[2]
DATA_ACCESS = REPO_ROOT / "src" / "skills" / "_shared" / "data-access"
if str(DATA_ACCESS) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS))
from dataasset_paths import DATAASSET_ROOT  # noqa: E402

SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
from dataasset.registry_write import registry_write_lock, write_json_atomic  # noqa: E402

DATAASSET = DATAASSET_ROOT


def _rel_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _registry_paths() -> tuple[Path, Path, Path, Path]:
    """Resolve mutable registry and Schema paths at call time.

    Tests and private deployments can override the DataAsset root after module
    import. Keeping these paths dynamic prevents writes or validation from
    accidentally falling back to the public registry.
    """
    return (
        DATAASSET / "configure" / "evidence-minimum-fields.json",
        DATAASSET / "query-templates" / "templates.json",
        DATAASSET / "schema" / "data-asset.schema.json",
        DATAASSET / "schema" / "query-templates.schema.json",
    )


def _validate_apply_input(mapping: dict[str, Any], asset_id: str, asset: dict[str, Any]) -> None:
    """Reject cross-asset or malformed mappings before any registry mutation."""
    if not re.fullmatch(r"asset-[a-z0-9-]+", asset_id):
        raise ValueError(f"invalid asset_id for discovery apply: {asset_id!r}")
    mapped_id = str(mapping.get("asset_id") or "").strip()
    if mapped_id and mapped_id != asset_id:
        raise ValueError(
            f"mapping asset_id {mapped_id!r} does not match target asset {asset_id!r}"
        )
    if asset.get("status") != "discovery":
        raise ValueError(
            f"asset {asset_id!r} status={asset.get('status')!r}; discovery apply only accepts status=discovery"
        )
    mapped_type = mapping.get("asset_type")
    if mapped_type and mapped_type != asset.get("asset_type"):
        raise ValueError(
            f"mapping asset_type {mapped_type!r} does not match target asset {asset.get('asset_type')!r}"
        )
    aliases = mapping.get("proposed_field_aliases") or {}
    if not isinstance(aliases, dict) or any(
        not isinstance(src, str) or not isinstance(dst, str) or not src or not dst
        for src, dst in aliases.items()
    ):
        raise ValueError("proposed_field_aliases must map non-empty strings to non-empty strings")
    proposed_schema = mapping.get("proposed_asset_schema") or {}
    if not isinstance(proposed_schema, dict):
        raise ValueError("proposed_asset_schema must be an object")
    fields = proposed_schema.get("fields")
    if fields is not None and (not isinstance(fields, list) or any(not isinstance(f, str) for f in fields)):
        raise ValueError("proposed_asset_schema.fields must be a list of strings")
    template_ids = proposed_schema.get("query_template_ids")
    if template_ids is not None and (
        not isinstance(template_ids, list)
        or any(not isinstance(value, str) or not value for value in template_ids)
    ):
        raise ValueError("proposed_asset_schema.query_template_ids must be non-empty strings")
    masking = mapping.get("proposed_masking") or {}
    if not isinstance(masking, dict):
        raise ValueError("proposed_masking must be an object")
    template = mapping.get("proposed_query_template")
    if template is not None and not isinstance(template, dict):
        raise ValueError("proposed_query_template must be an object")


def _validate_json_schema(path: Path, payload: dict[str, Any]) -> None:
    """Validate a staged object with local-only resolution for sibling Schemas."""
    if not path.is_file():
        return
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError as exc:  # pragma: no cover - declared project dependency
        raise RuntimeError("jsonschema is required before applying discovery changes") from exc

    schema = _load_json(path)
    registry = Registry()
    base_id = str(schema.get("$id") or path.resolve().as_uri())
    for sibling in sorted(path.parent.glob("*.json")):
        document = _load_json(sibling)
        resource = Resource.from_contents(document)
        # Register both the document's canonical id and the relative-name URI
        # used by DataAsset Schemas. No remote retrieval is installed.
        uris = {sibling.resolve().as_uri(), urljoin(base_id, sibling.name)}
        if document.get("$id"):
            uris.add(str(document["$id"]))
        for uri in uris:
            registry = registry.with_resource(uri, resource)
    errors = sorted(
        Draft202012Validator(schema, registry=registry).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"schema validation failed [{location}]: {error.message}")


def _write_staged_json(
    changes: list[tuple[Path, dict[str, Any], dict[str, Any]]],
) -> None:
    """Replace staged JSON files and restore prior objects after write errors.

    The caller owns the registry lock. Atomic replacement prevents truncated
    individual files; this rollback covers ordinary exceptions across a batch.
    It cannot provide crash-consistent multi-file transactions if the process is
    forcibly terminated between replacements.
    """
    applied: list[tuple[Path, dict[str, Any]]] = []
    try:
        for path, payload, original in changes:
            write_json_atomic(path, payload)
            applied.append((path, original))
    except BaseException as write_error:
        rollback_errors: list[str] = []
        for path, original in reversed(applied):
            try:
                write_json_atomic(path, original)
            except BaseException as rollback_error:  # pragma: no cover - double I/O failure
                rollback_errors.append(f"{path}: {rollback_error}")
        if rollback_errors:
            raise RuntimeError(
                "discovery apply failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from write_error
        raise


def _infer_text_parser(mapping: dict[str, Any], report: dict[str, Any] | None = None) -> str | None:
    if mapping.get("text_parser"):
        return str(mapping["text_parser"])
    hints = (report or {}).get("discovery_asset_hints") or {}
    fmt = mapping.get("detected_format") or (report or {}).get("detected_format")
    if fmt in ("json_lines", "syslog_auth", "nginx_combined"):
        return fmt
    pn = mapping.get("proposed_normalizer") or {}
    if pn.get("parser_name"):
        return str(pn["parser_name"])
    th = mapping.get("proposed_template_hint") or (report or {}).get("proposed_template_hint") or {}
    tp = th.get("text_parser")
    if isinstance(tp, str):
        m = re.search(r":\s*(\w+)", tp)
        if m:
            return m.group(1)
    return None


def merge_aliases_into_spec(
    spec: dict[str, Any],
    new_aliases: dict[str, str],
    *,
    force: bool = False,
) -> tuple[dict[str, str], dict[str, str]]:
    """Return (added, skipped)."""
    existing = dict(spec.get("field_aliases") or {})
    added: dict[str, str] = {}
    skipped: dict[str, str] = {}
    for src, dst in new_aliases.items():
        if not src or not dst:
            continue
        if src in existing and existing[src] != dst and not force:
            skipped[src] = existing[src]
            continue
        if src not in existing or existing[src] != dst:
            added[src] = dst
            existing[src] = dst
    spec["field_aliases"] = existing
    return added, skipped


def merge_template_into_catalog(
    catalog: dict[str, Any],
    snippet: dict[str, Any],
) -> tuple[str | None, bool]:
    """Merge proposed_query_template; return (template_id, created)."""
    if not snippet:
        return None, False
    tid = snippet.get("template_id")
    if not tid:
        return None, False
    templates = catalog.setdefault("templates", {})
    body = {k: v for k, v in snippet.items() if k != "template_id"}
    if not body:
        return tid, False
    created = tid not in templates
    merged = copy.deepcopy(templates.get(tid, {}))
    merged.update(body)
    templates[tid] = merged
    return tid, created


def apply_discovery_mapping(
    mapping: dict[str, Any],
    *,
    asset_id: str | None = None,
    dry_run: bool = False,
    global_aliases: bool = False,
    force_aliases: bool = False,
    promote_draft: bool = True,
) -> dict[str, Any]:
    """Apply one discovery report through the shared registry write boundary.

    By default new field aliases go to asset.field_aliases (per-asset override).
    Use global_aliases=True to merge into evidence-minimum-fields.json instead.
    All affected objects are staged and validated before the first replacement;
    the registry lock prevents Studio/CLI writers from racing this operation.
    """
    if not isinstance(mapping, dict):
        raise ValueError("discovery mapping must be a JSON object")
    aid = str(asset_id or mapping.get("asset_id") or "").strip()
    if not aid:
        raise ValueError("asset_id required in mapping or --asset-id")
    if not re.fullmatch(r"asset-[a-z0-9-]+", aid):
        raise ValueError(f"invalid asset_id for discovery apply: {aid!r}")

    evidence_spec_path, templates_path, asset_schema_path, templates_schema_path = _registry_paths()
    asset_path = DATAASSET / "assets" / f"{aid}.json"
    result: dict[str, Any]

    # The lock covers both the last read and all replacements. This closes the
    # time-of-check/time-of-write window with Studio and CLI registry editors.
    with registry_write_lock(DATAASSET):
        if not asset_path.is_file():
            raise FileNotFoundError(f"asset not found: {asset_path}")

        original_asset = _load_json(asset_path)
        asset = copy.deepcopy(original_asset)
        _validate_apply_input(mapping, aid, asset)
        proposed_aliases = dict(mapping.get("proposed_field_aliases") or {})
        proposed_schema = dict(mapping.get("proposed_asset_schema") or {})
        proposed_masking = dict(mapping.get("proposed_masking") or {})
        proposed_template = mapping.get("proposed_query_template")
        staged_spec: dict[str, Any] | None = None
        original_spec: dict[str, Any] | None = None
        staged_catalog: dict[str, Any] | None = None
        original_catalog: dict[str, Any] | None = None

        result = {
            "asset_id": aid,
            "dry_run": dry_run,
            "global_aliases": global_aliases,
            "files_touched": [],
        }

        if proposed_aliases:
            if global_aliases:
                original_spec = _load_json(evidence_spec_path)
                staged_spec = copy.deepcopy(original_spec)
                added, skipped = merge_aliases_into_spec(
                    staged_spec,
                    proposed_aliases,
                    force=force_aliases,
                )
                result["global_aliases_added"] = added
                result["global_aliases_skipped"] = skipped
                if added:
                    result["files_touched"].append(_rel_path(evidence_spec_path))
            else:
                per = dict(asset.get("field_aliases") or {})
                per.update(proposed_aliases)
                asset["field_aliases"] = per
                result["asset_field_aliases"] = per

        schema = dict(asset.get("schema") or {})
        if proposed_schema.get("fields"):
            schema["fields"] = proposed_schema["fields"]
        schema.pop("correlation_keys", None)
        if proposed_schema.get("time_field"):
            schema["time_field"] = proposed_schema["time_field"]
        if proposed_schema.get("retention_days"):
            schema["retention_days"] = proposed_schema["retention_days"]
        asset["schema"] = schema

        if proposed_schema.get("query_template_ids"):
            existing_ids = list(asset.get("query_template_ids") or [])
            for template_id in proposed_schema["query_template_ids"]:
                if template_id not in existing_ids:
                    existing_ids.append(template_id)
            asset["query_template_ids"] = existing_ids

        text_parser = _infer_text_parser(mapping)
        if text_parser:
            asset["text_parser"] = text_parser
        if proposed_masking:
            asset["masking"] = {**(asset.get("masking") or {}), **proposed_masking}
        if promote_draft:
            asset["status"] = "draft"
            result["status_promoted"] = "discovery → draft"

        if proposed_template and proposed_template.get("template_id"):
            original_catalog = _load_json(templates_path)
            staged_catalog = copy.deepcopy(original_catalog)
            template_id, created = merge_template_into_catalog(staged_catalog, proposed_template)
            if template_id:
                ids = list(asset.get("query_template_ids") or [])
                if template_id not in ids:
                    ids.append(template_id)
                    asset["query_template_ids"] = ids
                result["template_id"] = template_id
                result["template_created"] = created
                result["files_touched"].append(_rel_path(templates_path))

        # Validate every staged object before the first write. Missing optional
        # schemas preserve compatibility with minimal private registries.
        _validate_json_schema(asset_schema_path, asset)
        if staged_catalog is not None:
            _validate_json_schema(templates_schema_path, staged_catalog)

        result["files_touched"].append(_rel_path(asset_path))
        if not dry_run:
            changes: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
            if (
                staged_spec is not None
                and original_spec is not None
                and result.get("global_aliases_added")
            ):
                changes.append((evidence_spec_path, staged_spec, original_spec))
            if staged_catalog is not None and original_catalog is not None:
                changes.append((templates_path, staged_catalog, original_catalog))
            changes.append((asset_path, asset, original_asset))
            _write_staged_json(changes)

    result["asset_preview"] = {
        "status": asset.get("status"),
        "text_parser": asset.get("text_parser"),
        "query_template_ids": asset.get("query_template_ids"),
        "field_aliases": asset.get("field_aliases"),
        "schema_fields": (asset.get("schema") or {}).get("fields"),
    }
    try:
        import sys
        da = DATAASSET.parent / "src" / "skills" / "_shared" / "data-access"
        if str(da) not in sys.path:
            sys.path.insert(0, str(da))
        from correlation_keys import derive_correlation_keys

        result["derived_correlation_keys"] = derive_correlation_keys(asset)
    except Exception:
        pass
    return result


def apply_from_report_file(
    path: Path,
    *,
    dry_run: bool = False,
    global_aliases: bool = False,
    force_aliases: bool = False,
    promote_draft: bool = True,
) -> dict[str, Any]:
    mapping = _load_json(path)
    return apply_discovery_mapping(
        mapping,
        asset_id=mapping.get("asset_id"),
        dry_run=dry_run,
        global_aliases=global_aliases,
        force_aliases=force_aliases,
        promote_draft=promote_draft,
    )
