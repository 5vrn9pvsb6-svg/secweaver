"""Subprocess-backed connector plugin executor."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from connector_fetch_common import max_rows
from connector_registry import REPO_ROOT, connector_registry

# Resolve the dependency from the source root, independently of the asset root.
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
from dataasset.plugin_contract import (  # noqa: E402
    API_VERSION as SUPPORTED_PLUGIN_API_VERSION,
    PluginContractError,
    decode_response,
    normalize_manifest,
    positive_timeout,
    resolve_entrypoint,
    resolve_python,
)


def _trim(text: str, limit: int = 1200) -> str:
    clean = (text or "").strip()
    if len(clean) <= limit:
        return clean
    return clean[:limit] + "\n..."


def _credential_values(value: Any) -> set[str]:
    """Collect scalar credential values without retaining names or structure."""
    if isinstance(value, dict):
        secrets: set[str] = set()
        for nested in value.values():
            secrets.update(_credential_values(nested))
        return secrets
    if isinstance(value, (list, tuple, set)):
        secrets = set()
        for nested in value:
            secrets.update(_credential_values(nested))
        return secrets
    if value is None or isinstance(value, bool):
        return set()
    text = str(value)
    return {text} if text else set()


def _safe_stderr(stderr: str, credentials: dict[str, Any]) -> str:
    """Return bounded plugin diagnostics without reflecting credential payloads.

    Exact credential values are removed recursively. Very short values cannot be
    replaced safely without corrupting arbitrary diagnostics, so stderr is omitted
    entirely in that case. Plugin stdout is never an error-detail source because it
    is the protocol response channel and may contain source records or secrets.
    """
    secrets = _credential_values(credentials)
    if any(len(secret) < 4 for secret in secrets):
        return ""
    detail = _trim(stderr)
    for secret in sorted(secrets, key=len, reverse=True):
        detail = detail.replace(secret, "[REDACTED]")
    return detail


def _plugin_spec(connector_type: str) -> dict[str, Any]:
    spec = connector_registry().get(connector_type)
    if not spec or spec.get("runtime") != "plugin":
        raise NotImplementedError(f"connector_type={connector_type} is not a plugin connector")
    return spec


def _resolve_entrypoint(spec: dict[str, Any]) -> tuple[Path, Path]:
    """Adapt registry location metadata; containment is owned by the shared contract."""
    plugin_dir_value = str(spec.get("plugin_dir") or "").strip()
    if not plugin_dir_value:
        raise RuntimeError(f"plugin connector {spec.get('connector_type')} has no plugin_dir")

    plugin_dir = Path(plugin_dir_value)
    if not plugin_dir.is_absolute():
        plugin_dir = REPO_ROOT / plugin_dir
    candidate = resolve_entrypoint(plugin_dir, spec)
    plugin_dir = plugin_dir.resolve()
    return plugin_dir, candidate


def fetch(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Execute one validated plugin and validate every row before applying limits.

    A connector may explicitly override the shared 30-second default. Timeout
    ends this attempt without retrying; no malformed response is partially used.
    """
    connector_type = str(connector.get("connector_type") or "")
    spec = normalize_manifest(_plugin_spec(connector_type))

    plugin_dir, entrypoint = _resolve_entrypoint(spec)
    python_bin = resolve_python(plugin_dir, spec)
    # Read the raw override before coercion so floats/bools cannot change policy.
    override = (connector.get("constraints") or {}).get("request_timeout_sec", spec["timeout_sec"])
    timeout = positive_timeout(override)
    payload = {
        "connector": connector,
        "credentials": credentials,
        "query": query,
        "params": params,
    }

    try:
        result = subprocess.run(
            [python_bin, str(entrypoint)],
            input=json.dumps(payload, ensure_ascii=False),
            cwd=plugin_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"plugin connector_type={connector_type} timed out after {timeout}s") from exc

    if result.returncode != 0:
        detail = _safe_stderr(result.stderr or "", credentials)
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"plugin connector_type={connector_type} failed with exit code {result.returncode}{suffix}"
        )

    try:
        events, meta = decode_response(result.stdout)
    except PluginContractError as exc:
        raise RuntimeError(f"plugin connector_type={connector_type}: {exc}") from exc
    row_limit = max_rows(connector, params, default=int(spec.get("max_records_per_request") or 1000))
    if len(events) > row_limit:
        events = events[:row_limit]
    return events, {
        **meta,
        "mode": "plugin",
        "backend": connector_type,
        "plugin_dir": spec.get("plugin_dir"),
        "entrypoint": spec.get("entrypoint"),
        "query": query,
        "rows_returned": len(events),
    }
