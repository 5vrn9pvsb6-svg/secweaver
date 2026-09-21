"""Unified connector fetch dispatcher.

The public fetch pipeline should not know every vendor/backend branch.  It
renders templates, resolves credentials, then delegates live execution here via
one uniform strategy interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from db_fetch import fetch_database
from es_fetch import fetch_es
from extended_fetch import fetch_extended_connector, is_extended_connector
from http_fetch import fetch_http_api
from local_file_fetch import enrich_local_file_params, fetch_local_file
from sls_fetch import fetch as fetch_sls
from sls_proxy_fetch import fetch as fetch_sls_proxy
from ssh_fetch import enrich_ssh_params, fetch_ssh_file

ConnectorLoader = Callable[[str], dict[str, Any]]
CredentialResolver = Callable[[str], dict[str, Any]]
ConnectorFetchFn = Callable[["ConnectorFetchRequest"], tuple[list[dict[str, Any]], dict[str, Any]]]


@dataclass(frozen=True)
class ConnectorFetchRequest:
    """Runtime context passed to connector fetch strategies."""

    asset: dict[str, Any]
    connector: dict[str, Any]
    credentials: dict[str, Any]
    rendered: dict[str, Any]
    requested_template_id: str
    effective_template_id: str
    load_connector: ConnectorLoader
    resolve_credentials: CredentialResolver

    @property
    def connector_type(self) -> str:
        return str(self.connector.get("connector_type") or "")

    @property
    def params(self) -> dict[str, Any]:
        params = self.rendered.get("params") or {}
        return params if isinstance(params, dict) else {}


def enrich_connector_params(
    asset: dict[str, Any],
    connector: dict[str, Any],
    params: dict[str, Any],
) -> dict[str, Any]:
    """Apply connector-specific parameter enrichment before template rendering."""
    connector_type = str(connector.get("connector_type") or "")
    if connector_type in {"ssh_file", "ssh_command"}:
        return enrich_ssh_params(asset, connector, params)
    if connector_type == "local_file":
        return enrich_local_file_params(asset, connector, params)
    return params


def _required_rendered(request: ConnectorFetchRequest, key: str, connector_type: str | None = None) -> Any:
    value = request.rendered.get(key)
    if not value:
        ctype = connector_type or request.connector_type
        raise ValueError(
            f"template {request.requested_template_id} has no {key} for {ctype} connector"
        )
    return value


def _fetch_sls(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sls_query = _required_rendered(request, "sls_query", "SLS")
    return fetch_sls(request.asset, request.connector, request.credentials, sls_query, request.params)


def _fetch_sls_proxy(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sls_query = _required_rendered(request, "sls_query", "SLS Proxy")
    return fetch_sls_proxy(
        request.asset,
        request.connector,
        request.credentials,
        sls_query,
        request.params,
    )


def _fetch_ssh(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    ssh_command = _required_rendered(request, "ssh_command")
    return fetch_ssh_file(
        request.asset,
        request.connector,
        request.credentials,
        ssh_command,
        load_connector=request.load_connector,
        resolve_credentials=request.resolve_credentials,
    )


def _fetch_database(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sql = _required_rendered(request, "sql")
    return fetch_database(request.connector, request.credentials, sql, request.params)


def _fetch_http_api(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    templates = request.rendered.get("_templates") or {}
    http_spec = (
        templates.get("templates", {})
        .get(request.effective_template_id, {})
        .get("http")
    )
    if not http_spec:
        raise ValueError(
            f"template {request.requested_template_id} has no http for http_api connector"
        )
    return fetch_http_api(request.connector, request.credentials, http_spec, request.params)


def _fetch_es(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    templates = request.rendered.get("_templates") or {}
    es_query = (
        templates.get("templates", {})
        .get(request.effective_template_id, {})
        .get("es_query")
    )
    if not es_query:
        raise ValueError(f"template {request.requested_template_id} has no es_query for es connector")
    return fetch_es(request.connector, request.credentials, es_query, request.params)


def _fetch_local_file(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    local_file_command = _required_rendered(request, "local_file_command")
    return fetch_local_file(request.asset, request.connector, local_file_command)


CONNECTOR_FETCHERS: dict[str, ConnectorFetchFn] = {
    "sls": _fetch_sls,
    "sls_proxy": _fetch_sls_proxy,
    "ssh_file": _fetch_ssh,
    "ssh_command": _fetch_ssh,
    "database_ro": _fetch_database,
    "http_api": _fetch_http_api,
    "es": _fetch_es,
    "local_file": _fetch_local_file,
}


def fetch_connector(request: ConnectorFetchRequest) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Execute one connector using registered strategy functions."""
    fetcher = CONNECTOR_FETCHERS.get(request.connector_type)
    if fetcher:
        return fetcher(request)
    if is_extended_connector(request.connector_type):
        return fetch_extended_connector(request.connector, request.credentials, request.rendered)
    raise NotImplementedError(
        f"live fetch not implemented for connector_type={request.connector_type}; "
        "use --dry-run or supply evidence_bundles manually"
    )
