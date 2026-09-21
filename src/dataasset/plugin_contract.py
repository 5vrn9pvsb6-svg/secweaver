"""Shared stdio-json plugin contract for discovery, CLI checks and execution.

This module has no Skill or vendor dependencies. Invalid event rows fail the
whole response: silently dropping evidence can make a successful query misleading.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

API_VERSION = "1.0"
DEFAULT_TIMEOUT_SECONDS = 30
EVENT_KEYS = ("events", "data", "results", "records", "items", "alerts")
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]*$")
REQUIRED_FIELDS = ("api_version", "connector_type", "query_key", "runtime", "protocol", "entrypoint")
ONBOARDING_PROFILE_FIELDS = (
    "label",
    "fields",
    "required",
    "defaults",
    "default_asset_type",
    "template_params",
    "template_defaults",
    "default_query",
    "hint",
)


class PluginContractError(ValueError):
    """A manifest, executable path or response violates the plugin contract."""


def positive_timeout(value: Any) -> int:
    """Accept integer seconds, including CLI strings, but reject lossy coercion."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise PluginContractError("timeout_sec must be a positive integer")
    try:
        seconds = int(value)
    except ValueError as exc:
        raise PluginContractError("timeout_sec must be a positive integer") from exc
    if seconds <= 0:
        raise PluginContractError("timeout_sec must be a positive integer")
    return seconds


def manifest_errors(manifest: Any) -> list[str]:
    """Return all format errors without resolving paths or running plugin code."""
    if not isinstance(manifest, dict):
        return ["plugin.json must be a JSON object"]
    errors = [f"{field} is required" for field in REQUIRED_FIELDS if manifest.get(field) in (None, "")]
    for field in ("connector_type", "query_key"):
        value = manifest.get(field)
        if value not in (None, "") and (not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value)):
            errors.append(f"{field} must match {IDENTIFIER_RE.pattern}")
    for field, expected in (("api_version", API_VERSION), ("runtime", "plugin"), ("protocol", "stdio-json")):
        if manifest.get(field) not in (None, "", expected):
            errors.append(f"{field} must be {expected}")
    for field in ("entrypoint", "python"):
        value = manifest.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{field} must be a non-empty path")
    try:
        positive_timeout(manifest.get("timeout_sec", DEFAULT_TIMEOUT_SECONDS))
    except PluginContractError as exc:
        errors.append(str(exc))
    onboarding_template = manifest.get("onboarding_template")
    if onboarding_template is not None and (
        not isinstance(onboarding_template, str) or not IDENTIFIER_RE.fullmatch(onboarding_template)
    ):
        errors.append(f"onboarding_template must match {IDENTIFIER_RE.pattern}")
    profile = manifest.get("onboarding_profile")
    if profile is not None:
        if not isinstance(profile, dict):
            errors.append("onboarding_profile must be an object")
        else:
            missing = [field for field in ONBOARDING_PROFILE_FIELDS if field not in profile]
            if missing:
                errors.append(f"onboarding_profile missing required fields: {', '.join(missing)}")
    return errors


def normalize_manifest(manifest: Any) -> dict[str, Any]:
    """Validate required version-1 fields; only optional timeout receives a default.

    Discovery must validate the raw manifest before adding UI metadata, so a
    synthesized runtime/entrypoint cannot hide an invalid on-disk declaration.
    """
    errors = manifest_errors(manifest)
    if errors:
        raise PluginContractError("; ".join(errors))
    return {**manifest, "timeout_sec": positive_timeout(manifest.get("timeout_sec", DEFAULT_TIMEOUT_SECONDS))}


def resolve_entrypoint(plugin_dir: Path, manifest: dict[str, Any]) -> Path:
    """Resolve symlinks before checking containment; never allow directory escape."""
    try:
        root = plugin_dir.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise PluginContractError("invalid plugin directory path") from exc
    if not root.is_dir():
        raise PluginContractError("plugin directory does not exist")
    value = manifest.get("entrypoint")
    if not isinstance(value, str) or not value.strip():
        raise PluginContractError("entrypoint is required")
    try:
        candidate = (root / value).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise PluginContractError("invalid plugin entrypoint path") from exc
    if root not in candidate.parents:
        raise PluginContractError("entrypoint escapes plugin directory")
    if not candidate.is_file():
        raise PluginContractError("entrypoint file does not exist")
    return candidate


def resolve_python(plugin_dir: Path, manifest: dict[str, Any]) -> str:
    """Allow an operator-selected interpreter outside the plugin; use no shell."""
    value = manifest.get("python")
    if value is None:
        return sys.executable
    if not isinstance(value, str) or not value.strip():
        raise PluginContractError("python must be a non-empty path")
    try:
        candidate = (plugin_dir.resolve() / value).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise PluginContractError("invalid plugin python path") from exc
    if not candidate.is_file():
        raise PluginContractError("plugin python executable does not exist")
    return str(candidate)


def extract_events(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Select the first supported array in fixed order and reject invalid rows."""
    for key in EVENT_KEYS:
        value = response.get(key)
        if isinstance(value, list):
            if any(not isinstance(item, dict) for item in value):
                raise PluginContractError("event array items must be JSON objects")
            return value
    raise PluginContractError(f"stdout must include one event array: {', '.join(EVENT_KEYS)}")


def decode_response(stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate the entire response before returning rows or applying a row limit.

    Failure messages intentionally omit stdout: it may contain logs or secrets.
    Optional/null meta remains compatible; any other non-object meta is invalid.
    """
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise PluginContractError("stdout must be JSON") from exc
    if not isinstance(response, dict):
        raise PluginContractError("stdout must be a JSON object")
    events = extract_events(response)
    meta = response.get("meta")
    if meta is not None and not isinstance(meta, dict):
        raise PluginContractError("meta must be a JSON object when provided")
    return events, meta or {}
