"""Aliyun SLS connector fetcher."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit
from sls_proxy_config import proxy_project
from sls_tls import tls_policy


def _project_proxy_client(base: type, project: str) -> type:
    """Add Project before official SDK signing, without changing the Proxy host.

    The per-client subclass avoids global monkey patches and concurrent request
    leakage. The SDK's project argument stays empty; the query-string selector
    is authenticated by its normal SLS canonical-resource signature.
    """
    class ProjectProxyClient(base):
        def _send(self, method, sdk_project, body, resource, params, headers, *args, **kwargs):
            selected = dict(params or {})
            selected["project"] = project
            return super()._send(method, "", body, resource, selected, headers, *args, **kwargs)

    return ProjectProxyClient


def _parse_iso_ts(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def _configure_sdk_endpoint(client: Any, endpoint: str, *, force_direct_host: bool = False) -> None:
    """Keep SDK requests on the configured endpoint instead of a project subdomain."""
    parsed = urlsplit(endpoint if "://" in endpoint else f"//{endpoint}")
    if force_direct_host:
        client._isRowIp = True
        default_port = 443 if parsed.scheme == "https" else 80
        if parsed.port and parsed.port != default_port:
            # The official SDK strips non-default ports from Host. Preserve the
            # authority so WAF routing and SLS request signing see the same Host.
            client._logHost = parsed.netloc
        return
    try:
        ip_address(parsed.hostname or "")
    except ValueError:
        return
    client._isRowIp = True


def _postprocess_events(events: list[dict[str, Any]], asset: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse raw SLS payloads only when indexed structured fields are absent."""
    tp = asset.get("text_parser")
    if not tp:
        return events

    from syslog_risk_normalize import is_null_field
    from text_log_parser import parse_text_line, resolve_text_parser_id

    out: list[dict[str, Any]] = []
    payload_fields = ("__line__", "content", "message", "raw_line", "log", "body")
    declared_fields = set((asset.get("schema") or {}).get("fields") or []) - set(payload_fields)
    parser_id = resolve_text_parser_id(asset)
    for ev in events:
        row = dict(ev)
        if any(not is_null_field(row.get(field)) for field in declared_fields):
            out.append(row)
            continue

        host = str(row.get("__source__") or row.get("host_ip") or row.get("host") or "")
        parsed_row: dict[str, Any] | None = None
        for key in payload_fields:
            blob = row.get(key)
            if is_null_field(blob):
                continue
            parsed = parse_text_line(str(blob), parser_id=parser_id, host=host, asset=asset)
            meaningful_fields = set(parsed) - {"host", "timestamp", "raw_line"}
            if meaningful_fields:
                merged = dict(row)
                merged.update(parsed)
                parsed_row = merged
                break

        out.append(parsed_row if parsed_row else row)
    return out


def fetch(
    asset: dict[str, Any],
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Query SLS with verified transport by default, including Proxy routes."""
    verify = tls_policy(connector["config"])
    try:
        from aliyun.log import GetLogsRequest, LogClient
    except ImportError as exc:
        raise RuntimeError(
            "live SLS fetch requires: pip install aliyun-log-python-sdk"
        ) from exc

    if credentials.get("type") != "aliyun_ram":
        raise ValueError(f"unsupported SLS credential type: {credentials.get('type')}")

    config = connector["config"]
    limit = int(params.get("limit", connector.get("constraints", {}).get("max_rows", 2000)))
    security_token = credentials.get("security_token") or None
    is_proxy = connector.get("connector_type") == "sls_proxy"
    selected_project = proxy_project(config) if is_proxy else config["project"]
    client_type = _project_proxy_client(LogClient, selected_project) if is_proxy and selected_project else LogClient
    client = client_type(
        config["endpoint"],
        credentials["access_key_id"],
        credentials["access_key_secret"],
        security_token,
    )
    _configure_sdk_endpoint(
        client,
        config["endpoint"],
        force_direct_host=connector.get("connector_type") == "sls_proxy",
    )
    # Probe and actual SDK query share trust settings. Private CA deployments
    # supply ca_file rather than silently disabling server authentication.
    if hasattr(client, "_session") and hasattr(client._session, "verify"):
        client._session.verify = verify
    request = GetLogsRequest(
        "" if is_proxy else selected_project,
        config["logstore"],
        _parse_iso_ts(params["time_start"]),
        _parse_iso_ts(params["time_end"]),
        query=query,
        line=limit,
        offset=0,
        reverse=False,
    )
    response = client.get_logs(request)
    events: list[dict[str, Any]] = []
    for log in response.get_logs() or []:
        item = dict(log.contents)
        source = getattr(log, "source", None)
        topic = getattr(log, "topic", None)
        if source:
            item.setdefault("__source__", source)
        if topic:
            item.setdefault("__topic__", topic)
        # SLS time is a transport fallback, not the collector's event time.
        # Keeping it separate also lets raw JSON parsers discover source fields.
        item["_sls_timestamp"] = datetime.fromtimestamp(log.timestamp, tz=timezone.utc).isoformat()
        events.append(item)

    events = _postprocess_events(events, asset)
    return events, {
        "rows_returned": len(events),
        "truncated": len(events) >= limit,
        "time_range": [params.get("time_start"), params.get("time_end")],
    }
