"""SecWeaver SLS Proxy fetcher using the official Aliyun SLS SDK."""

from __future__ import annotations

import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sls_fetch import fetch as fetch_sls
from sls_proxy_config import proxy_project
from sls_tls import tls_policy

def _endpoint_candidates(config: dict[str, Any]) -> list[str]:
    primary = str(config.get("endpoint") or "").strip().rstrip("/")
    if not primary:
        raise ValueError("sls_proxy config.endpoint is required")

    fallback_values: list[Any] = []
    if config.get("fallback_endpoint"):
        fallback_values.append(config["fallback_endpoint"])
    configured_fallbacks = config.get("fallback_endpoints") or []
    if not isinstance(configured_fallbacks, list):
        raise ValueError("sls_proxy config.fallback_endpoints must be an array")
    fallback_values.extend(configured_fallbacks)

    endpoints: list[str] = []
    for value in [primary, *fallback_values]:
        endpoint = str(value or "").strip().rstrip("/")
        if endpoint and endpoint not in endpoints:
            endpoints.append(endpoint)
    return endpoints


def _probe_timeout(config: dict[str, Any]) -> float:
    try:
        timeout = float(config.get("endpoint_probe_timeout_seconds", 5))
    except (TypeError, ValueError) as exc:
        raise ValueError("endpoint_probe_timeout_seconds must be numeric") from exc
    if not 0.5 <= timeout <= 30:
        raise ValueError("endpoint_probe_timeout_seconds must be between 0.5 and 30")
    return timeout


def _endpoint_available(endpoint: str, *, tls_verify: bool | str, timeout: float) -> bool:
    """Probe reachability with the query's trust policy; trust errors are fatal."""
    request = Request(f"{endpoint}/livez", headers={"User-Agent": "SecWeaver-DataAccess/1"})
    context = None
    if endpoint.startswith("https://"):
        context = (
            ssl._create_unverified_context()  # noqa: SLF001 - explicit diagnostic opt-out.
            if tls_verify is False
            else ssl.create_default_context(cafile=tls_verify if isinstance(tls_verify, str) else None)
        )
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            return 200 <= int(response.status) < 400
    except HTTPError as exc:
        # A policy response still proves that the network route is reachable;
        # the signed SLS request will return the actionable authentication error.
        return 400 <= exc.code < 500 and exc.code != 404
    except (OSError, TimeoutError, URLError) as exc:
        # A certificate failure is not an outage. Do not silently skip a bad
        # primary certificate and make the signed request on another endpoint.
        if isinstance(exc, ssl.SSLError) or isinstance(getattr(exc, "reason", None), ssl.SSLError):
            raise
        return False


def _retryable_endpoint_error(exc: Exception) -> bool:
    status_getter = getattr(exc, "get_resp_status", None)
    status = status_getter() if callable(status_getter) else getattr(exc, "resp_status", 0)
    message_getter = getattr(exc, "get_error_message", None)
    message = str(message_getter() if callable(message_getter) else exc).lower()
    # SDKs wrap SSLError in generic transport errors (often "max retries
    # exceeded"). Classify trust failures before the availability markers.
    if isinstance(exc, ssl.SSLError) or any(marker in message for marker in (
        "ssl", "certificate", "hostname mismatch", "tls",
    )):
        return False
    if "route not found" in message and (status in {0, 404} or "404" in message):
        return True
    if status in {408, 502, 503, 504}:
        return True
    return any(
        marker in message
        for marker in (
            "connection refused",
            "connection reset",
            "connect timeout",
            "connection timed out",
            "failed to establish a new connection",
            "max retries exceeded",
            "name or service not known",
            "name resolution",
            "temporary failure in name resolution",
        )
    )


def fetch(
    asset: dict[str, Any],
    connector: dict[str, Any],
    credentials: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Select only the Proxy endpoint; pass Project as a signed resource selector.

    A retry preserves Project and never downgrades to the default project on an
    authorization or validation failure. Upstream region remains server-owned.
    """
    config = connector.get("config") or {}
    project = proxy_project(config)
    forbidden = [field for field in ("region", "enterprise_id") if config.get(field)]
    if forbidden:
        raise ValueError(
            "sls_proxy config must not contain server-managed fields: "
            + ", ".join(forbidden)
        )
    endpoints = _endpoint_candidates(config)
    tls_verify = tls_policy(config)
    candidates = endpoints
    if len(endpoints) > 1:
        timeout = _probe_timeout(config)
        for index, endpoint in enumerate(endpoints):
            if _endpoint_available(endpoint, tls_verify=tls_verify, timeout=timeout):
                candidates = endpoints[index:]
                break

    last_error: Exception | None = None
    for index, endpoint in enumerate(candidates):
        proxy_connector = {
            **connector,
            "config": {
                **config,
                "endpoint": endpoint,
                "project": project,
            },
        }
        try:
            events, meta = fetch_sls(asset, proxy_connector, credentials, query, params)
        except Exception as exc:  # noqa: BLE001 - SDK boundary classifies retryable transport failures.
            last_error = exc
            if index + 1 < len(candidates) and _retryable_endpoint_error(exc):
                continue
            raise
        return events, {
            **meta,
            "endpoint_used": endpoint,
            "fallback_used": endpoint != endpoints[0],
            "project": project,
            "logstore": config.get("logstore"),
        }

    assert last_error is not None
    raise last_error
