"""Layer 1 payload validity and attack-type classification."""

from __future__ import annotations

import re
from typing import Any

from .common import match_patterns
from .url_match import _match_attack_url_patterns, _url_text

VERDICT_RANK = {
    "false_positive": 0,
    "scanning_or_probe": 1,
    "suspicious": 2,
    "confirmed_attack": 3,
}

EXECUTION_TYPE_IDS = ("rce", "webshell")


def _technique_for_hits(meta: dict, text: str) -> str:
    for tname, tpats in meta.get("techniques", {}).items():
        if match_patterns(text, tpats):
            return tname
    return "unknown"


def _explicit_execution_hits(text: str, catalog: dict) -> list[str]:
    hits: list[str] = []
    for type_id in EXECUTION_TYPE_IDS:
        meta = (catalog.get("types") or {}).get(type_id) or {}
        hits.extend(match_patterns(text, meta.get("patterns", [])))
    return list(dict.fromkeys(hits))


def _detect_sensitive_config_probe(text: str, catalog: dict) -> tuple[str, str, list[str], str] | None:
    """Classify pure config/backup probing before generic WAF rule-name hints."""
    meta = (catalog.get("types") or {}).get("sensitive_config_probe") or {}
    hits = match_patterns(text, meta.get("patterns", []))
    if not hits:
        return None
    if _explicit_execution_hits(text, catalog):
        return None
    return (
        "sensitive_config_probe",
        meta.get("label", "敏感配置/备份文件探测"),
        hits,
        _technique_for_hits(meta, text),
    )


def detect_attack_type(text: str, rule_name: str, catalog: dict) -> tuple[str, str, list[str], str]:
    rule_lower = (rule_name or "").lower()
    sensitive_probe = _detect_sensitive_config_probe(text, catalog)
    if sensitive_probe:
        return sensitive_probe

    best_type = "unknown"
    best_label = "未知类型"
    matched: list[str] = []
    technique = "unknown"

    for type_id, meta in catalog["types"].items():
        hits = match_patterns(text, meta.get("patterns", []))
        hint_hit = any(h in rule_lower for h in meta.get("rule_name_hints", []))
        if hits or hint_hit:
            if len(hits) >= len(matched) or (hint_hit and not matched):
                best_type = type_id
                best_label = meta.get("label", type_id)
                matched = hits or ([f"rule_hint:{rule_name}"] if hint_hit else [])
                technique = _technique_for_hits(meta, text)

    return best_type, best_label, matched, technique


def check_fp(text: str, fp_catalog: dict, alert: dict) -> tuple[bool, str | None]:
    payload = (alert.get("payload") or "").strip()
    url = alert.get("url") or ""

    for frag in fp_catalog.get("whitelist_url_fragments", []):
        if frag in url:
            return True, f"whitelist_url:{frag}"

    if payload:
        for pat in fp_catalog.get("false_positive_patterns", []):
            if pat.get("contains"):
                if all(c in payload for c in pat["contains"]):
                    exploit_hits = match_patterns(payload, [" OR ", "UNION", "<script", "../", "system("])
                    if not exploit_hits:
                        return True, pat["id"]
            if pat.get("regex"):
                if re.search(pat["regex"], payload, re.I if pat.get("flags") == "i" else 0):
                    exploit_hits = match_patterns(payload, [" OR ", "UNION", "<script", "../", ";", "|"])
                    if not exploit_hits:
                        return True, pat["id"]

    ua = (alert.get("user_agent") or "").lower()
    for scanner in fp_catalog.get("scanner_user_agents", []):
        if scanner.lower() in ua and not match_patterns(text, ["union", "script", " or "]):
            return False, None  # scanner UA alone → scanning, not FP

    return False, None


def layer1_verdict(
    alert: dict,
    text: str,
    attack_type: str,
    matched: list[str],
    fp_catalog: dict,
) -> tuple[str, dict]:
    payload = (alert.get("payload") or "").strip()
    rule_name = alert.get("rule_name") or ""
    action = (alert.get("action") or "").lower()

    is_fp, fp_reason = check_fp(text, fp_catalog, alert)
    if is_fp:
        return "false_positive", {
            "has_payload": bool(payload),
            "payload_snippet": payload[:200] if payload else None,
            "technique": "benign_business",
            "validity": "invalid",
            "notes": f"匹配误报模式: {fp_reason}",
        }

    if not payload and not matched:
        rule_lower = rule_name.lower()
        if any(s in rule_lower for s in fp_catalog.get("suspicious_no_payload_rules", [])):
            return "scanning_or_probe", {
                "has_payload": False,
                "payload_snippet": None,
                "technique": "generic_rule",
                "validity": "insufficient",
                "notes": "无有效 payload，仅规则/generic 命中",
            }
        return "suspicious", {
            "has_payload": False,
            "payload_snippet": None,
            "technique": "unknown",
            "validity": "insufficient",
            "notes": "缺少 payload，无法确认为真实攻击",
        }

    if attack_type == "scanner_fingerprint" and not match_patterns(text, ["union", "script", " or ", "system("]):
        return "scanning_or_probe", {
            "has_payload": bool(payload),
            "payload_snippet": payload[:200] if payload else text[:200],
            "technique": "scanner_probe",
            "validity": "probe",
            "notes": "扫描器/探测类请求特征",
        }

    if attack_type == "sensitive_config_probe":
        return "scanning_or_probe", {
            "has_payload": bool(payload),
            "payload_snippet": payload[:200] if payload else text[:200],
            "technique": "sensitive_config_probe",
            "validity": "probe",
            "notes": f"敏感配置/备份文件探测: {', '.join(matched[:3])}",
        }

    if matched and attack_type != "unknown":
        meta = alert.get("payload_meta") or {}
        notes_extra = ""
        if meta.get("payload_decoded"):
            notes_extra = f"（body 经 {meta.get('payload_encoding', 'base64')} 解码）"
        elif meta.get("payload_source") == "request.header" or (
            not meta and payload and payload.startswith("Host:")
        ):
            # header-only 回退：HTTP 头中的 ; 不应单独触发 RCE
            if attack_type == "rce" and (
                matched == [";"]
                or all(m in (";", "|", "||", "&&") for m in matched)
            ):
                return "suspicious", {
                    "has_payload": bool(payload),
                    "payload_snippet": payload[:200],
                    "technique": "header_only_fallback",
                    "validity": "insufficient",
                    "notes": "仅 request.header 回退，无 body；RCE 特征可能为 HTTP 头分号误报",
                }
        notes = f"检测到 {attack_type} 攻击特征: {', '.join(matched[:3])}{notes_extra}"
        return "confirmed_attack", {
            "has_payload": bool(payload),
            "payload_snippet": (payload or text)[:200],
            "technique": attack_type,
            "validity": "valid",
            "notes": notes,
        }

    if payload:
        return "suspicious", {
            "has_payload": True,
            "payload_snippet": payload[:200],
            "technique": "unknown",
            "validity": "unclear",
            "notes": "有 payload 但未匹配已知 exploit 模式",
        }

    return "scanning_or_probe", {
        "has_payload": False,
        "payload_snippet": None,
        "technique": "unknown",
        "validity": "insufficient",
        "notes": "探测/扫描类告警",
    }


def _layer1_upgrade_config(catalog: dict) -> dict[str, Any]:
    return catalog.get("layer1_correlated_upgrade") or {}


def _gateway_miss_severity(item: dict, catalog: dict) -> str:
    if item.get("severity"):
        return str(item["severity"])
    config = _layer1_upgrade_config(catalog)
    critical_patterns = list(config.get("critical_patterns") or [])
    hits = [str(h).lower() for h in (item.get("pattern_hits") or [])]
    url = _url_text(str(item.get("url") or ""))
    for pattern in critical_patterns:
        needle = pattern.lower()
        if any(needle in hit for hit in hits) or needle in url:
            return "critical"
    if hits:
        return "medium"
    return "low"


def infer_attack_type_from_correlated(
    gateway_miss_scan: dict[str, Any] | None,
    success_indicator: str | None,
    catalog: dict,
) -> tuple[str, str, list[str]]:
    config = _layer1_upgrade_config(catalog)
    if success_indicator:
        type_id = str(config.get("d2_success_attack_type") or "rce")
        meta = catalog.get("types", {}).get(type_id, {})
        return type_id, meta.get("label", type_id), ["correlated_d2_success"]

    rce_patterns = list(config.get("rce_patterns") or [])
    blob_parts: list[str] = []
    for item in (gateway_miss_scan or {}).get("items") or []:
        blob_parts.extend(str(h) for h in (item.get("pattern_hits") or []))
        blob_parts.append(str(item.get("url") or ""))
    blob = _url_text(" ".join(blob_parts))

    priority = ("rce", "path_traversal", "webshell", "sqli")
    for type_id in priority:
        meta = catalog.get("types", {}).get(type_id, {})
        hits = match_patterns(blob, meta.get("patterns", []))
        extra = _match_attack_url_patterns(blob, rce_patterns if type_id == "rce" else [])
        combined = list(dict.fromkeys(hits + extra))
        if combined:
            return type_id, meta.get("label", type_id), combined[:5]
    return "unknown", "未知类型", []


def upgrade_layer1_verdict(
    alert_verdict: str,
    attack_type: str,
    attack_label: str,
    matched: list[str],
    payload_analysis: dict,
    *,
    attack_outcome: str,
    success_refs: list[str],
    success_indicator: str | None,
    gateway_miss_scan: dict[str, Any] | None,
    catalog: dict,
) -> tuple[str, str, str, list[str], dict, dict[str, Any] | None]:
    """Raise Layer 1 when D2 or gateway miss scan contradict a weak WAF-only verdict."""
    if alert_verdict == "false_positive":
        return alert_verdict, attack_type, attack_label, matched, payload_analysis, None

    config = _layer1_upgrade_config(catalog)
    miss_items = (gateway_miss_scan or {}).get("items") or []
    critical_items = [item for item in miss_items if _gateway_miss_severity(item, catalog) == "critical"]
    critical_count = len(critical_items)
    current_rank = VERDICT_RANK.get(alert_verdict, 0)
    new_verdict = alert_verdict
    reason = ""

    if success_refs and attack_outcome == "success_confirmed":
        if current_rank < VERDICT_RANK["confirmed_attack"]:
            new_verdict = "confirmed_attack"
            reason = "d2_success_confirmed"
    elif critical_count >= int(config.get("min_critical_misses_for_confirmed") or 1):
        if current_rank < VERDICT_RANK["confirmed_attack"]:
            new_verdict = "confirmed_attack"
            reason = "gateway_miss_critical"
    elif critical_count >= 1 and current_rank < VERDICT_RANK["suspicious"]:
        new_verdict = "suspicious"
        reason = "gateway_miss_critical"

    if new_verdict == alert_verdict:
        return alert_verdict, attack_type, attack_label, matched, payload_analysis, None

    upgraded_analysis = dict(payload_analysis)
    if new_verdict in ("confirmed_attack", "suspicious") and attack_type in ("scanner_fingerprint", "unknown"):
        inf_type, inf_label, inf_matched = infer_attack_type_from_correlated(
            gateway_miss_scan,
            success_indicator if reason == "d2_success_confirmed" else None,
            catalog,
        )
        if inf_type != "unknown":
            attack_type = inf_type
            attack_label = inf_label
            matched = inf_matched or matched

    reason_notes = {
        "d2_success_confirmed": "D2 已确认攻击成功，联动升级 Layer 1",
        "gateway_miss_critical": f"网关漏检 {critical_count} 条高危攻击 URL，联动升级 Layer 1",
    }
    upgraded_analysis["notes"] = reason_notes.get(reason, upgraded_analysis.get("notes", ""))
    if new_verdict == "confirmed_attack":
        upgraded_analysis["validity"] = "valid"
        if attack_type not in ("unknown", "scanner_fingerprint"):
            upgraded_analysis["technique"] = attack_type

    upgrade_meta = {
        "from_verdict": alert_verdict,
        "to_verdict": new_verdict,
        "reason": reason,
        "critical_miss_count": critical_count,
        "attack_type": attack_type,
        "success_indicator": success_indicator,
    }
    return new_verdict, attack_type, attack_label, matched, upgraded_analysis, upgrade_meta
