"""MITRE ATT&CK enrichment for traceability-analysis (shared rules/attck-map.json)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parent.parent
RISK_RULES_DIR = SKILL_ROOT.parent / "risk-identification" / "rules"
DEFAULT_ATTCK_MAP_PATH = RISK_RULES_DIR / "attck-map.json"

_map: dict[str, Any] | None = None
_catalog: dict[str, dict[str, str]] | None = None

# Legacy regex hints removed — infer_evidence_rule_keys uses risk-identification exec/behavior rules.

def get_attck_map(path: Path | str | None = None) -> dict[str, Any]:
    global _map
    if path is not None:
        return _load_map(Path(path))
    if _map is None:
        _map = _load_map(DEFAULT_ATTCK_MAP_PATH)
    return _map


def configure_attck_map(path: Path | str | None = None) -> dict[str, Any]:
    global _map, _catalog
    _map = _load_map(Path(path) if path else DEFAULT_ATTCK_MAP_PATH)
    _catalog = None
    return _map


def _load_map(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _techniques_from_entry(entry: dict[str, Any] | None) -> list[dict[str, str]]:
    if not entry:
        return []
    out: list[dict[str, str]] = []
    for tech in entry.get("techniques") or []:
        if not isinstance(tech, dict) or not tech.get("id"):
            continue
        out.append(
            {
                "id": str(tech["id"]),
                "name": str(tech.get("name") or ""),
                "tactic": str(tech.get("tactic") or ""),
                "tactic_id": str(tech.get("tactic_id") or ""),
            }
        )
    return out


def build_technique_catalog(attck_map: dict[str, Any] | None = None) -> dict[str, dict[str, str]]:
    global _catalog
    if attck_map is None and _catalog is not None:
        return _catalog
    attck_map = attck_map or get_attck_map()
    catalog: dict[str, dict[str, str]] = {}
    for section in ("matched_rules", "policy_rules"):
        for entry in (attck_map.get(section) or {}).values():
            for tech in _techniques_from_entry(entry):
                catalog[tech["id"]] = tech
    if attck_map is get_attck_map():
        _catalog = catalog
    return catalog


def resolve_techniques_from_rule_keys(
    rule_keys: list[str],
    attck_map: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    attck_map = attck_map or get_attck_map()
    matched_index = attck_map.get("matched_rules") or {}
    policy_index = attck_map.get("policy_rules") or {}
    seen: set[str] = set()
    techniques: list[dict[str, str]] = []

    def add(entries: list[dict[str, str]]) -> None:
        for tech in entries:
            tid = tech["id"]
            if tid in seen:
                continue
            seen.add(tid)
            techniques.append(tech)

    for key in rule_keys:
        key = str(key)
        if key in matched_index:
            add(_techniques_from_entry(matched_index[key]))
        if key in policy_index:
            add(_techniques_from_entry(policy_index[key]))
    return techniques


def infer_evidence_rule_keys(
    index: dict[str, dict[str, Any]],
    cmd_text_fn: Any,
) -> list[str]:
    from risk_rules_bridge import collect_rules_for_event

    keys: list[str] = []
    seen: set[str] = set()
    for ev in index.values():
        for rule_key in collect_rules_for_event(ev, cmd_text_fn):
            if rule_key in seen:
                continue
            seen.add(rule_key)
            keys.append(rule_key)
    return keys


def collect_trace_rule_keys(
    *,
    attack_chain: list[dict[str, Any]],
    initial: dict[str, Any] | None,
    matched_pattern: str | None,
    index: dict[str, dict[str, Any]],
    cmd_text_fn: Any,
) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()

    def add(key: str) -> None:
        if key and key not in seen:
            seen.add(key)
            keys.append(key)

    for key in infer_evidence_rule_keys(index, cmd_text_fn):
        add(key)

    if matched_pattern:
        from risk_rules_bridge import policy_rules_by_chain

        for policy_key in policy_rules_by_chain().get(matched_pattern, []):
            add(policy_key)

    if initial:
        vector = str(initial.get("vector") or "")
        if "webshell" in vector or "web_exploit" in vector:
            add("webshell_write")
            add("WEB-SHELL-001")
        if initial.get("correlation_source") == "exec_inferred":
            add("external_listener_shell_exec")

    for step in attack_chain:
        stage = step.get("stage") or ""
        desc = str(step.get("description") or "").lower()
        if stage == "lateral_movement" or "sshpass" in desc or "ssh" in desc:
            add("LATERAL-SSH-001")
            add("root_ssh_login")
        if stage == "execution" and ("sh -c" in desc or "shell" in desc):
            add("external_listener_shell_exec")

    return keys


def _techniques_from_stage_ids(
    attack_chain: list[dict[str, Any]],
    catalog: dict[str, dict[str, str]],
) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for step in attack_chain:
        tid = str(step.get("mitre_id") or "")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        if tid in catalog:
            out.append(dict(catalog[tid]))
        else:
            out.append({"id": tid, "name": tid, "tactic": "", "tactic_id": ""})
    return out


def merge_techniques(*groups: list[dict[str, str]]) -> dict[str, Any]:
    seen: set[str] = set()
    techniques: list[dict[str, str]] = []
    for group in groups:
        for tech in group:
            tid = tech.get("id") or ""
            if not tid or tid in seen:
                continue
            seen.add(tid)
            techniques.append(tech)

    tactics: list[dict[str, str]] = []
    tactic_seen: set[str] = set()
    for tech in techniques:
        tid = tech.get("tactic_id") or tech.get("tactic") or ""
        if not tid or tid in tactic_seen:
            continue
        tactic_seen.add(tid)
        tactics.append({"id": tech.get("tactic_id") or "", "name": tech.get("tactic") or ""})

    return {
        "techniques": techniques,
        "tactics": tactics,
        "technique_ids": [t["id"] for t in techniques],
        "tactic_ids": [t["id"] for t in tactics if t.get("id")],
    }


def build_mitre_attack_by_stage(
    attack_chain: list[dict[str, Any]],
    catalog: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for step in attack_chain:
        tid = str(step.get("mitre_id") or "")
        if not tid:
            continue
        tech = catalog.get(tid) or {"id": tid, "name": tid, "tactic": "", "tactic_id": ""}
        rows.append(
            {
                "stage": step.get("stage"),
                "host": step.get("host"),
                "timestamp": step.get("timestamp"),
                "technique_id": tid,
                "technique_name": tech.get("name") or tid,
                "tactic": tech.get("tactic") or "",
                "tactic_id": tech.get("tactic_id") or "",
            }
        )
    return rows


def build_trace_mitre_attack(
    *,
    attack_chain: list[dict[str, Any]],
    initial: dict[str, Any] | None,
    matched_pattern: str | None,
    index: dict[str, dict[str, Any]],
    cmd_text_fn: Any,
    attck_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attck_map = attck_map or get_attck_map()
    catalog = build_technique_catalog(attck_map)
    rule_keys = collect_trace_rule_keys(
        attack_chain=attack_chain,
        initial=initial,
        matched_pattern=matched_pattern,
        index=index,
        cmd_text_fn=cmd_text_fn,
    )
    evidence_techniques = resolve_techniques_from_rule_keys(rule_keys, attck_map)
    stage_techniques = _techniques_from_stage_ids(attack_chain, catalog)
    mitre = merge_techniques(stage_techniques, evidence_techniques)
    return {
        **mitre,
        "rule_keys": rule_keys,
        "by_stage": build_mitre_attack_by_stage(attack_chain, catalog),
    }


def format_mitre_attack_short(mitre: dict[str, Any] | None, *, limit: int = 5) -> str:
    if not mitre:
        return ""
    parts: list[str] = []
    for tech in mitre.get("techniques") or []:
        label = tech.get("id") or ""
        name = tech.get("name") or ""
        if name and name != label:
            label = f"{label} ({name})" if label else name
        if label:
            parts.append(label)
        if len(parts) >= limit:
            break
    extra = len(mitre.get("techniques") or []) - limit
    text = "; ".join(parts)
    if extra > 0:
        text += f"; +{extra}"
    return text
