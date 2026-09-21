"""Attacker IP network profile — evidence geo + optional online enrichment."""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import copy
from collections import Counter
from pathlib import Path
from typing import Any

from dataasset_paths import DATAASSET_ROOT
from normalizer import normalize_ip

ATTACKER_IP_FIELDS = ("src_ip", "ip", "remote_addr", "client_ip")
GEO_FIELDS = ("country", "province", "city", "geo_info")
EVIDENCE_BUNDLE_TYPES = (
    "waf_alert",
    "web_access_log",
    "firewall_log",
    "dns_log",
    "network_traffic_audit",
)

IP_API_URL = "http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,message,query,country,regionName,city,isp,org,as,mobile,proxy,hosting"
IPWHOIS_URL = "https://ipwho.is/{ip}?fields=success,message,ip,country,region,city,connection,security,type"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VIRUSTOTAL_KEY_CONFIG_HINT = (
    "请配置 VirusTotal API Key：可在运行参数传 virustotal_api_key/vt_api_key，"
    "或设置环境变量 VIRUSTOTAL_API_KEY/VT_API_KEY，"
    "或修复 ip-intel.json 中 virustotal.credentials_ref 指向的 vault 密钥。"
)
DEFAULT_IP_INTEL_CONFIG = DATAASSET_ROOT / "configure" / "ip-intel.json"
DEFAULT_IP_INTEL = {
    "enabled": True,
    "default_provider": "auto",
    "include_virustotal": True,
    "providers": {
        "virustotal": {
            "enabled": True,
            "base_url": VIRUSTOTAL_IP_URL,
            "timeout_seconds": 6.0,
            "fallback_on_failure": True,
        },
        "ipwhois": {
            "enabled": True,
            "base_url": IPWHOIS_URL,
            "timeout_seconds": 4.0,
        },
        "ip-api": {
            "enabled": True,
            "base_url": IP_API_URL,
            "timeout_seconds": 4.0,
        },
    },
}


def _normalize_ip(value: Any) -> str | None:
    """Compatibility wrapper for the shared source-IP normalizer."""
    return normalize_ip(value)


def _event_attacker_ip(ev: dict[str, Any]) -> str | None:
    for field in ATTACKER_IP_FIELDS:
        ip = _normalize_ip(ev.get(field))
        if ip:
            return ip
    return None


def _pick_mode(counter: Counter[str]) -> str | None:
    if not counter:
        return None
    return counter.most_common(1)[0][0]


def collect_geo_from_evidence(
    attacker_ip: str,
    bundles: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Aggregate geo fields from D1/WAF/web logs for the attacker IP."""
    needle = _normalize_ip(attacker_ip)
    if not needle:
        return {}

    countries: Counter[str] = Counter()
    provinces: Counter[str] = Counter()
    cities: Counter[str] = Counter()
    geo_infos: Counter[str] = Counter()
    evidence_refs: list[str] = []
    event_count = 0

    for bundle_type in EVIDENCE_BUNDLE_TYPES:
        for ev in bundles.get(bundle_type) or []:
            if _event_attacker_ip(ev) != needle:
                continue
            event_count += 1
            ref = ev.get("evidence_id")
            if ref and ref not in evidence_refs:
                evidence_refs.append(str(ref))
            for field, counter in (
                ("country", countries),
                ("province", provinces),
                ("city", cities),
                ("geo_info", geo_infos),
            ):
                val = ev.get(field)
                if val not in (None, ""):
                    counter[str(val).strip()] += 1

    if event_count == 0:
        return {"event_count": 0, "evidence_refs": []}

    return {
        "event_count": event_count,
        "country": _pick_mode(countries),
        "province": _pick_mode(provinces),
        "city": _pick_mode(cities),
        "geo_info": _pick_mode(geo_infos),
        "evidence_refs": evidence_refs[:10],
        "source_bundles": [
            bundle
            for bundle in EVIDENCE_BUNDLE_TYPES
            if any(_event_attacker_ip(ev) == needle for ev in (bundles.get(bundle) or []))
        ],
    }


def _public_ip_or_status(attacker_ip: str) -> tuple[str | None, dict[str, Any] | None]:
    needle = _normalize_ip(attacker_ip)
    if not needle:
        return None, {"status": "invalid_ip", "query": attacker_ip}

    try:
        addr = ipaddress.ip_address(needle)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return needle, {
                "status": "private_or_reserved",
                "query": needle,
                "is_private": True,
            }
    except ValueError:
        return None, {"status": "invalid_ip", "query": attacker_ip}
    return needle, None


def _deep_merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_ip_intel_config(params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load non-secret IP intelligence settings from dataasset/configure."""
    config_path = (
        (params or {}).get("ip_intel_config")
        or os.environ.get("SECWEAVER_IP_INTEL_CONFIG")
        or str(DEFAULT_IP_INTEL_CONFIG)
    )
    cfg = copy.deepcopy(DEFAULT_IP_INTEL)
    try:
        path = Path(str(config_path)).expanduser()
        if path.is_file():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg = _deep_merge_dict(cfg, loaded)
                cfg["_config_path"] = str(path)
    except (OSError, json.JSONDecodeError) as exc:
        cfg["_config_error"] = str(exc)
    return cfg


def _provider_config(config: dict[str, Any] | None, provider: str) -> dict[str, Any]:
    providers = (config or {}).get("providers") or {}
    return providers.get(provider) or {}


def _provider_enabled(config: dict[str, Any] | None, provider: str) -> bool:
    return _provider_config(config, provider).get("enabled", True) is not False


def _float_setting(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _resolve_credentials_ref(credentials_ref: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        from vault import resolve_credentials  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - import environment edge case
        return None, str(exc)

    try:
        return resolve_credentials(credentials_ref), None
    except Exception as exc:
        return None, str(exc)


def _lookup_ip_api(
    attacker_ip: str,
    *,
    timeout: float = 4.0,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query ip-api.com public IP metadata. Best-effort fallback provider."""
    needle, status = _public_ip_or_status(attacker_ip)
    if status:
        return status
    assert needle is not None

    provider_cfg = _provider_config(config, "ip-api")
    timeout = _float_setting(provider_cfg.get("timeout_seconds"), timeout)
    url_template = provider_cfg.get("base_url") or IP_API_URL
    url = str(url_template).format(ip=urllib.parse.quote(needle))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecWeaver-traceability/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "ip-api.com",
            "error": str(exc.reason or exc),
        }
    except (TimeoutError, json.JSONDecodeError) as exc:
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "ip-api.com",
            "error": str(exc),
        }

    if payload.get("status") != "success":
        return {
            "status": payload.get("status") or "lookup_failed",
            "query": needle,
            "provider": "ip-api.com",
            "message": payload.get("message"),
        }

    asn_raw = str(payload.get("as") or "")
    asn_id = asn_raw.split()[0] if asn_raw else None
    return {
        "status": "success",
        "query": payload.get("query") or needle,
        "country": payload.get("country"),
        "region": payload.get("regionName"),
        "city": payload.get("city"),
        "isp": payload.get("isp"),
        "org": payload.get("org"),
        "as": asn_raw or None,
        "asn": asn_id,
        "mobile": bool(payload.get("mobile")),
        "proxy": bool(payload.get("proxy")),
        "hosting": bool(payload.get("hosting")),
        "provider": "ip-api.com",
    }


def _lookup_ipwhois(
    attacker_ip: str,
    *,
    timeout: float = 4.0,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query ipwho.is public IP metadata. Best-effort no-key provider."""
    needle, status = _public_ip_or_status(attacker_ip)
    if status:
        return {**status, "provider": "ipwho.is"}
    assert needle is not None

    provider_cfg = _provider_config(config, "ipwhois")
    timeout = _float_setting(provider_cfg.get("timeout_seconds"), timeout)
    url_template = provider_cfg.get("base_url") or IPWHOIS_URL
    url = str(url_template).format(ip=urllib.parse.quote(needle))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecWeaver-traceability/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "ipwho.is",
            "error": str(exc.reason or exc),
        }
    except (TimeoutError, json.JSONDecodeError) as exc:
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "ipwho.is",
            "error": str(exc),
        }

    if payload.get("success") is False:
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "ipwho.is",
            "message": payload.get("message"),
        }

    connection = payload.get("connection") or {}
    security = payload.get("security") if isinstance(payload.get("security"), dict) else {}
    asn = connection.get("asn")
    asn_id = f"AS{asn}" if asn not in (None, "") and not str(asn).startswith("AS") else asn
    org = connection.get("org")
    isp = connection.get("isp")
    as_text = " ".join(str(v) for v in (asn_id, org or isp) if v) or None
    proxy_values = [
        security[key]
        for key in ("proxy", "vpn", "tor", "anonymous")
        if key in security
    ]
    proxy = bool(any(proxy_values)) if proxy_values else None
    tags = [
        label
        for label, enabled in (
            ("anonymous", security.get("anonymous")),
            ("proxy", security.get("proxy")),
            ("vpn", security.get("vpn")),
            ("tor", security.get("tor")),
            ("hosting", security.get("hosting")),
        )
        if enabled
    ]
    return {
        "status": "success",
        "query": payload.get("ip") or needle,
        "country": payload.get("country"),
        "region": payload.get("region"),
        "city": payload.get("city"),
        "isp": isp,
        "org": org,
        "domain": connection.get("domain"),
        "as": as_text,
        "asn": asn_id,
        "mobile": bool(security.get("mobile")) if "mobile" in security else None,
        "proxy": proxy,
        "hosting": bool(security.get("hosting")) if "hosting" in security else None,
        "vpn": bool(security.get("vpn")) if "vpn" in security else None,
        "tor": bool(security.get("tor")) if "tor" in security else None,
        "anonymous": bool(security.get("anonymous")) if "anonymous" in security else None,
        "security": security,
        "tags": tags,
        "provider": "ipwho.is",
    }


def _vt_api_key(
    params_key: str | None = None,
    provider_cfg: dict[str, Any] | None = None,
) -> tuple[str | None, dict[str, Any]]:
    if params_key:
        return str(params_key), {"source": "params"}

    cfg = provider_cfg or {}
    credentials_ref = cfg.get("credentials_ref")
    if credentials_ref:
        credentials, error = _resolve_credentials_ref(str(credentials_ref))
        if credentials:
            for field in ("token", "access_token", "api_key"):
                value = credentials.get(field)
                if value:
                    return str(value), {
                        "source": "vault",
                        "credentials_ref": str(credentials_ref),
                    }
        return None, {
            "source": "vault",
            "credentials_ref": str(credentials_ref),
            "error": error or "credential did not contain token/access_token/api_key",
        }

    env_var = cfg.get("api_key_env") or cfg.get("token_env")
    if env_var and os.environ.get(str(env_var)):
        return str(os.environ[str(env_var)]), {"source": "env", "env_var": str(env_var)}

    for env_name in ("VIRUSTOTAL_API_KEY", "VT_API_KEY"):
        value = os.environ.get(env_name)
        if value:
            return str(value), {"source": "env", "env_var": env_name}

    return None, {"source": "none"}


def _lookup_virustotal(
    attacker_ip: str,
    *,
    api_key: str | None = None,
    timeout: float = 6.0,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query VirusTotal v3 IP report. Requires an API key."""
    needle, status = _public_ip_or_status(attacker_ip)
    if status:
        return {**status, "provider": "virustotal"}
    assert needle is not None

    provider_cfg = _provider_config(config, "virustotal")
    timeout = _float_setting(provider_cfg.get("timeout_seconds"), timeout)
    key, key_meta = _vt_api_key(api_key, provider_cfg)
    if not key:
        return {
            "status": "config_missing",
            "query": needle,
            "provider": "virustotal",
            "message": key_meta.get("error")
            or "missing virustotal credentials_ref/token or VIRUSTOTAL_API_KEY",
            "action_required": "configure_virustotal_api_key",
            "action_required_label": VIRUSTOTAL_KEY_CONFIG_HINT,
            "config_hint": VIRUSTOTAL_KEY_CONFIG_HINT,
            "credential_source": key_meta.get("source"),
            "credentials_ref": key_meta.get("credentials_ref"),
        }

    url_template = provider_cfg.get("base_url") or VIRUSTOTAL_IP_URL
    url = str(url_template).format(ip=urllib.parse.quote(needle, safe=""))
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SecWeaver-traceability/1.0",
                "x-apikey": key,
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8")[:500]
        except Exception:  # pragma: no cover - defensive for urllib edge cases
            body = ""
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "virustotal",
            "http_status": exc.code,
            "error": body or str(exc),
        }
    except urllib.error.URLError as exc:
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "virustotal",
            "error": str(exc.reason or exc),
        }
    except (TimeoutError, json.JSONDecodeError) as exc:
        return {
            "status": "lookup_failed",
            "query": needle,
            "provider": "virustotal",
            "error": str(exc),
        }

    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    votes = attrs.get("total_votes") or {}
    asn = attrs.get("asn")
    asn_id = f"AS{asn}" if asn not in (None, "") else None
    return {
        "status": "success",
        "query": data.get("id") or needle,
        "provider": "virustotal",
        "country": attrs.get("country"),
        "asn": asn_id,
        "as_owner": attrs.get("as_owner"),
        "network": attrs.get("network"),
        "regional_internet_registry": attrs.get("regional_internet_registry"),
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": {
            "harmless": int(stats.get("harmless") or 0),
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "timeout": int(stats.get("timeout") or 0),
            "undetected": int(stats.get("undetected") or 0),
        },
        "total_votes": {
            "harmless": int(votes.get("harmless") or 0),
            "malicious": int(votes.get("malicious") or 0),
        },
        "tags": list(attrs.get("tags") or []),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def lookup_ip_online(
    attacker_ip: str,
    *,
    timeout: float = 4.0,
    provider: str | None = None,
    virustotal_api_key: str | None = None,
    config: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query public IP metadata. Supports VirusTotal, ipwho.is, and ip-api fallback."""
    cfg = config or _load_ip_intel_config(params)
    if cfg.get("enabled") is False:
        return {"status": "disabled", "query": attacker_ip}
    needle, status = _public_ip_or_status(attacker_ip)
    if status:
        return status

    selected = str(
        provider
        or (params or {}).get("ip_intel_provider")
        or cfg.get("default_provider")
        or os.environ.get("SECWEAVER_IP_INTEL_PROVIDER")
        or "auto"
    ).strip().lower()
    if selected in {"vt", "virustotal", "virus-total"}:
        if not _provider_enabled(cfg, "virustotal"):
            return {"status": "disabled", "query": needle, "provider": "virustotal"}
        return _lookup_virustotal(attacker_ip, api_key=virustotal_api_key, timeout=timeout, config=cfg)
    if selected in {"ipwhois", "ip-whois", "ipwho.is", "ip-who.is"}:
        if not _provider_enabled(cfg, "ipwhois"):
            return {"status": "disabled", "query": needle, "provider": "ipwho.is"}
        return _lookup_ipwhois(attacker_ip, timeout=timeout, config=cfg)
    if selected in {"ip-api", "ip_api", "ipapi", "ip-api.com"}:
        if not _provider_enabled(cfg, "ip-api"):
            return {"status": "disabled", "query": needle, "provider": "ip-api.com"}
        return _lookup_ip_api(attacker_ip, timeout=timeout, config=cfg)
    if selected != "auto":
        return {
            "status": "invalid_provider",
            "query": attacker_ip,
            "provider": selected,
        }

    vt_key = None
    if _provider_enabled(cfg, "virustotal"):
        vt_key, _key_meta = _vt_api_key(virustotal_api_key, _provider_config(cfg, "virustotal"))
    if vt_key:
        vt_result = _lookup_virustotal(attacker_ip, api_key=vt_key, timeout=timeout, config=cfg)
        if vt_result.get("status") == "success":
            return vt_result
        vt_cfg = _provider_config(cfg, "virustotal")
        if vt_cfg.get("fallback_on_failure") is False:
            return vt_result
        fallback = _lookup_best_effort_ip_provider(attacker_ip, timeout=timeout, config=cfg)
        fallback["fallback_from"] = {
            "provider": "virustotal",
            "status": vt_result.get("status"),
            "http_status": vt_result.get("http_status"),
            "error": vt_result.get("error") or vt_result.get("message"),
        }
        return fallback

    return _lookup_best_effort_ip_provider(attacker_ip, timeout=timeout, config=cfg)


def _lookup_best_effort_ip_provider(
    attacker_ip: str,
    *,
    timeout: float,
    config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Use no-key providers in preferred order, preserving failure details."""
    first_failure: dict[str, Any] | None = None
    if _provider_enabled(config, "ipwhois"):
        result = _lookup_ipwhois(attacker_ip, timeout=timeout, config=config)
        if result.get("status") == "success":
            return result
        first_failure = result
    if _provider_enabled(config, "ip-api"):
        result = _lookup_ip_api(attacker_ip, timeout=timeout, config=config)
        if result.get("status") == "success":
            if first_failure:
                result["fallback_from"] = {
                    "provider": first_failure.get("provider"),
                    "status": first_failure.get("status"),
                    "error": first_failure.get("error") or first_failure.get("message"),
                }
            return result
        if first_failure:
            result["fallback_from"] = {
                "provider": first_failure.get("provider"),
                "status": first_failure.get("status"),
                "error": first_failure.get("error") or first_failure.get("message"),
            }
        return result
    return first_failure or {
        "status": "disabled",
        "query": attacker_ip,
        "provider": "ipwho.is/ip-api.com",
    }


def _include_virustotal_lookup(params: dict[str, Any] | None, config: dict[str, Any]) -> bool:
    for key in ("ip_intel_include_virustotal", "ip_intel_include_vt"):
        if (params or {}).get(key) is False:
            return False
    return config.get("include_virustotal", True) is not False


def _build_virustotal_context(
    attacker_ip: str,
    *,
    online: dict[str, Any] | None,
    params: dict[str, Any] | None,
    config: dict[str, Any],
) -> dict[str, Any] | None:
    if not _include_virustotal_lookup(params, config):
        return None
    if online and online.get("provider") == "virustotal":
        return online
    if not _provider_enabled(config, "virustotal"):
        return {"status": "disabled", "query": attacker_ip, "provider": "virustotal"}
    return _lookup_virustotal(
        attacker_ip,
        api_key=(params or {}).get("virustotal_api_key") or (params or {}).get("vt_api_key"),
        config=config,
    )


def classify_network_attributes(
    attacker_ip: str,
    *,
    evidence_geo: dict[str, Any] | None = None,
    online: dict[str, Any] | None = None,
) -> list[str]:
    """Human-readable attribute tags for reports."""
    tags: list[str] = []
    needle = _normalize_ip(attacker_ip)
    if not needle:
        return tags

    try:
        addr = ipaddress.ip_address(needle)
        if addr.is_private:
            tags.append("内网地址")
        elif addr.is_global:
            tags.append("公网地址")
    except ValueError:
        tags.append("无效 IP")
        return tags

    ev = evidence_geo or {}
    if ev.get("country"):
        loc = " / ".join(x for x in (ev.get("country"), ev.get("province"), ev.get("city")) if x)
        tags.append(f"日志地理: {loc}")

    ol = online or {}
    if ol.get("status") == "success":
        if ol.get("provider") == "virustotal":
            tags.append("情报源: VirusTotal")
            stats = ol.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            if malicious or suspicious:
                tags.append(f"VT 检测: malicious={malicious}, suspicious={suspicious}")
            elif stats:
                tags.append("VT 检测: 未见恶意命中")
            if ol.get("reputation") not in (None, ""):
                tags.append(f"VT reputation: {ol['reputation']}")
            if ol.get("network"):
                tags.append(f"网络段: {ol['network']}")
        elif ol.get("provider"):
            tags.append(f"情报源: {ol['provider']}")
        if ol.get("mobile"):
            tags.append("移动网络")
        if ol.get("hosting"):
            tags.append("数据中心/托管")
        if ol.get("proxy"):
            tags.append("代理/VPN 疑似")
        if ol.get("isp"):
            tags.append(f"ISP: {ol['isp']}")
        if ol.get("asn"):
            tags.append(f"ASN: {ol['asn']}")
        owner = ol.get("as_owner") or ol.get("org")
        if owner and owner != ol.get("isp"):
            tags.append(f"组织: {owner}")
        elif ol.get("org") and ol.get("org") != ol.get("isp"):
            tags.append(f"组织: {ol['org']}")
    elif ol.get("status") == "lookup_failed":
        provider = ol.get("provider")
        if provider == "virustotal":
            tags.append("VirusTotal 查询失败（仅日志地理）")
        else:
            tags.append("在线属性查询失败（仅日志地理）")
    elif ol.get("status") == "config_missing" and ol.get("provider") == "virustotal":
        tags.append("VirusTotal 未配置 API Key（仅日志地理）")

    if not any(t.startswith("日志地理") for t in tags) and ol.get("country"):
        loc = " / ".join(x for x in (ol.get("country"), ol.get("region"), ol.get("city")) if x)
        tags.append(f"在线地理: {loc}")

    return tags


def _merge_attribute_tags(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for tag in group or []:
            if tag not in merged:
                merged.append(tag)
    return merged


def build_attacker_ip_profile(
    attacker_ip: str | None,
    bundles: dict[str, list[dict[str, Any]]],
    params: dict[str, Any] | None = None,
    *,
    online_lookup: bool = True,
) -> dict[str, Any] | None:
    """Build attacker_ip_profile block when attacker IP is known."""
    if params and params.get("resolve_attacker_ip_profile") is False:
        return None
    if not attacker_ip:
        return None

    needle = _normalize_ip(attacker_ip)
    if not needle:
        return None

    evidence_geo = collect_geo_from_evidence(needle, bundles)
    online: dict[str, Any] | None = None
    cfg = _load_ip_intel_config(params)
    config_online = cfg.get("online_lookup", cfg.get("enabled", True))
    if online_lookup and config_online is not False and (params or {}).get("ip_intel_online") is not False:
        online = lookup_ip_online(
            needle,
            provider=(params or {}).get("ip_intel_provider"),
            virustotal_api_key=(params or {}).get("virustotal_api_key")
            or (params or {}).get("vt_api_key"),
            config=cfg,
            params=params,
        )

    vt_context = _build_virustotal_context(needle, online=online, params=params, config=cfg) if online_lookup else None
    attributes = classify_network_attributes(needle, evidence_geo=evidence_geo, online=online)
    if vt_context and vt_context is not online:
        vt_attributes = [
            tag
            for tag in classify_network_attributes(needle, online=vt_context)
            if tag not in {"公网地址", "内网地址"}
        ]
        attributes = _merge_attribute_tags(attributes, vt_attributes)
    return {
        "ip": needle,
        "scope": "private" if ipaddress.ip_address(needle).is_private else "public",
        "evidence_geo": evidence_geo,
        "online_lookup": online,
        "threat_intel": {"virustotal": vt_context} if vt_context else {},
        "attributes": attributes,
        "summary": "；".join(attributes) if attributes else None,
    }
