"""Discovery and onboarding helpers for customer-managed Elasticsearch clusters."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
SENSITIVE_PARTS = ("password", "passwd", "secret", "token", "authorization", "cookie", "api_key")
TIME_FIELD_PRIORITY = ("@timestamp", "timestamp", "event.created", "event.ingested", "time", "datetime")


class ElasticsearchOnboardingError(RuntimeError):
    """A safe, operator-facing Elasticsearch onboarding error."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise ElasticsearchOnboardingError("Elasticsearch endpoint redirects are not allowed")


def _endpoint(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ElasticsearchOnboardingError("endpoint must be a valid http(s) URL")
    if parsed.username or parsed.password:
        raise ElasticsearchOnboardingError("do not put credentials in the endpoint URL")
    if parsed.scheme == "http":
        host = parsed.hostname.lower()
        is_loopback = host == "localhost"
        try:
            is_loopback = is_loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if not is_loopback:
            raise ElasticsearchOnboardingError("remote Elasticsearch endpoints must use HTTPS")
    return value


def _auth_header(credentials: dict[str, Any]) -> str | None:
    api_key = str(credentials.get("api_key") or "").strip()
    if api_key:
        return "ApiKey " + base64.b64encode(api_key.encode()).decode()
    username = str(credentials.get("username") or "")
    if username:
        raw = f"{username}:{credentials.get('password') or ''}".encode()
        return "Basic " + base64.b64encode(raw).decode()
    return None


def _flatten(value: Any, prefix: str = "", output: set[str] | None = None) -> set[str]:
    output = output or set()
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            output.add(name)
            _flatten(child, name, output)
    return output


def _safe_sample(value: Any, key: str = "") -> Any:
    if any(part in key.lower() for part in SENSITIVE_PARTS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _safe_sample(v, str(k)) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return [_safe_sample(item, key) for item in value[:5]]
    if isinstance(value, str) and len(value) > 240:
        return value[:240] + "..."
    return value


class ElasticsearchDiscoveryClient:
    def __init__(
        self,
        endpoint: str,
        credentials: dict[str, Any] | None = None,
        *,
        ca_file: str = "",
        tls_verify: bool = True,
        dataasset_root: Path | None = None,
        timeout: int = 15,
    ) -> None:
        """Authenticate HTTPS peers unless diagnostics explicitly opt out.

        Validate the flag before building a credential-bearing client; false-like
        JSON values must not be interpreted as permission to disable TLS checks.
        """
        if not isinstance(tls_verify, bool):
            raise ElasticsearchOnboardingError("tls_verify must be a boolean")
        self.endpoint = _endpoint(endpoint)
        self.timeout = max(1, min(int(timeout), 60))
        context = None
        if self.endpoint.startswith("https://"):
            if not tls_verify:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            elif ca_file:
                ca_path = Path(ca_file).expanduser()
                if not ca_path.is_absolute() and dataasset_root:
                    ca_path = dataasset_root / ca_path
                if not ca_path.is_file():
                    raise ElasticsearchOnboardingError(f"CA file not found: {ca_path}")
                context = ssl.create_default_context(cafile=str(ca_path))
            else:
                context = ssl.create_default_context()
        handlers: list[Any] = [_NoRedirect()]
        if context:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        auth = _auth_header(credentials or {})
        if auth:
            self.headers["Authorization"] = auth

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = self.endpoint + "/" + path.lstrip("/")
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(1000).decode("utf-8", errors="replace")
            raise ElasticsearchOnboardingError(f"Elasticsearch HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise ElasticsearchOnboardingError(f"cannot connect to Elasticsearch: {exc}") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ElasticsearchOnboardingError("Elasticsearch response exceeds 4 MiB discovery limit")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ElasticsearchOnboardingError("Elasticsearch returned a non-JSON response") from exc


def _field_types(payload: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for field, definitions in (payload.get("fields") or {}).items():
        if isinstance(definitions, dict):
            result[str(field)] = sorted(str(item) for item in definitions)
    return result


def _time_fields(types: dict[str, list[str]]) -> list[str]:
    values = [field for field, kinds in types.items() if set(kinds) & {"date", "date_nanos"}]
    rank = {name: index for index, name in enumerate(TIME_FIELD_PRIORITY)}
    return sorted(values, key=lambda item: (rank.get(item, len(rank)), item))


def discover_elasticsearch(
    endpoint: str,
    credentials: dict[str, Any] | None = None,
    *,
    index: str = "",
    ca_file: str = "",
    tls_verify: bool = True,
    dataasset_root: Path | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """Probe a cluster and optionally inspect an index pattern without leaking secrets."""
    client = ElasticsearchDiscoveryClient(
        endpoint,
        credentials,
        ca_file=ca_file,
        tls_verify=tls_verify,
        dataasset_root=dataasset_root,
        timeout=timeout,
    )
    root = client.request("GET", "/")
    version = root.get("version") or {}
    result: dict[str, Any] = {
        "ok": True,
        "endpoint": client.endpoint,
        "cluster": {
            "name": root.get("cluster_name") or root.get("name"),
            "version": version.get("number"),
            "distribution": version.get("distribution") or ("opensearch" if "opensearch" in str(root).lower() else "elasticsearch"),
        },
        "indices": [],
        "warnings": [],
    }
    try:
        health = client.request("GET", "/_cluster/health")
        result["cluster"]["status"] = health.get("status")
    except ElasticsearchOnboardingError as exc:
        result["warnings"].append(f"cluster health unavailable: {exc}")

    pattern = index.strip() or "*"
    encoded = urllib.parse.quote(pattern, safe="*,-._")
    try:
        resolved = client.request("GET", f"/_resolve/index/{encoded}?expand_wildcards=open,hidden")
        items = [{"name": item.get("name"), "type": "index"} for item in resolved.get("indices", [])]
        items += [{"name": item.get("name"), "type": "data_stream"} for item in resolved.get("data_streams", [])]
        result["indices"] = [item for item in items if item.get("name")][:200]
    except ElasticsearchOnboardingError as exc:
        result["warnings"].append(f"index discovery unavailable: {exc}")

    if index.strip():
        field_caps = client.request("POST", f"/{encoded}/_field_caps?fields=*", {})
        types = _field_types(field_caps)
        time_fields = _time_fields(types)
        result["field_types"] = types
        result["time_field_candidates"] = time_fields
        result["suggested_time_field"] = time_fields[0] if time_fields else ""
        query: dict[str, Any] = {"size": 3, "query": {"match_all": {}}}
        if time_fields:
            query["sort"] = [{time_fields[0]: {"order": "desc", "unmapped_type": "date"}}]
        sample = client.request("POST", f"/{encoded}/_search", query)
        hits = (sample.get("hits") or {}).get("hits") or []
        sources = [hit.get("_source") for hit in hits if isinstance(hit, dict) and isinstance(hit.get("_source"), dict)]
        fields = set(types)
        for source in sources:
            fields.update(_flatten(source))
        result["selected_index"] = index
        result["sample_fields"] = sorted(fields)[:500]
        result["sample_documents"] = [_safe_sample(source) for source in sources]
        result["sample_count"] = len(sources)
    return result


def build_es_onboarding_config(payload: dict[str, Any], probe: dict[str, Any], credential_ref: str) -> dict[str, Any]:
    """Build the standard asset-apply input from a successful discovery result."""
    name = str(payload.get("name") or "customer-es-security-events").strip()
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "customer-es"
    index = str(payload.get("index") or probe.get("selected_index") or "").strip()
    time_field = str(payload.get("time_field") or probe.get("suggested_time_field") or "@timestamp").strip()
    fields = [str(item) for item in (probe.get("sample_fields") or []) if str(item).strip()]
    if time_field not in fields:
        fields.append(time_field)
    aliases: dict[str, str] = {}
    candidates = {"client.ip": "src_ip", "source.ip": "src_ip", "remote_addr": "src_ip", "url.path": "url", "request_uri": "url"}
    for source, target in candidates.items():
        if source in fields:
            aliases[source] = target
    # Discovery may use an explicit diagnostic opt-out, but generated active
    # Connectors must never persist or execute that weaker transport policy.
    tls_verify = payload.get("tls_verify", True)
    if not isinstance(tls_verify, bool):
        raise ElasticsearchOnboardingError("tls_verify must be a boolean")
    if not tls_verify:
        raise ElasticsearchOnboardingError(
            "active Elasticsearch connectors require tls_verify=true; configure ca_file for a private CA"
        )
    connector_config: dict[str, Any] = {"time_field": time_field, "tls_verify": tls_verify}
    if tls_verify and payload.get("ca_file"):
        connector_config["ca_file"] = str(payload["ca_file"]).strip()
    return {
        "version": "1.0",
        "output_dir": str(payload.get("output_dir") or "dataasset"),
        "defaults": {"owner_team": str(payload.get("owner_team") or "security-ops"), "environment": str(payload.get("environment") or "production")},
        "data_sources": [{
            "name": name,
            "template_id": f"{slug}-by-time",
            "connector_type": "es",
            "asset_type": str(payload.get("asset_type") or "web_access_log"),
            "credentials_ref": credential_ref,
            "url": str(payload.get("endpoint") or probe.get("endpoint") or ""),
            "index": index,
            "status": "active",
            "connector": {"config": connector_config, "constraints": {"request_timeout_sec": 30, "max_records_per_request": 2000}},
            "asset": {"schema": {"fields": fields, "time_field": time_field, "retention_days": int(payload.get("retention_days") or 30)}, "field_aliases": aliases},
            "template": {
                "params": ["time_start", "time_end", "limit"],
                "defaults": {"limit": 1000},
                "es_query": {"query": {"bool": {"must": [], "filter": [{"range": {time_field: {"gte": "{time_start}", "lte": "{time_end}"}}}]}}, "size": "{limit}", "sort": [{time_field: "desc"}]},
            },
        }],
    }
