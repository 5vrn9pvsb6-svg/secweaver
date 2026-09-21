"""MITRE ATT&CK mapping for risk-identification output (rules/attck-map.json)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rule_loader import load_rule_pack, rule_file

DEFAULT_ATTCK_MAP_PATH = rule_file("attck-map.json")

_map: dict[str, Any] | None = None


def default_attck_map_path() -> Path:
    return rule_file("attck-map.json")


def get_attck_map(path: Path | str | None = None) -> dict[str, Any]:
    global _map
    if path is not None:
        return load_rule_pack(Path(path), default_name="attck-map.json")
    if _map is None:
        _map = load_rule_pack(default_attck_map_path(), default_name="attck-map.json")
    return _map


def configure_attck_map(path: Path | str | None = None) -> dict[str, Any]:
    global _map
    if path is None:
        _map = load_rule_pack(default_attck_map_path(), default_name="attck-map.json")
    else:
        _map = load_rule_pack(Path(path), default_name="attck-map.json")
    return _map


def _techniques_from_entry(entry: dict[str, Any] | None) -> list[dict[str, str]]:
    if not entry:
        return []
    raw = entry.get("techniques") or []
    out: list[dict[str, str]] = []
    for tech in raw:
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


def resolve_mitre_attack(item: dict[str, Any], attck_map: dict[str, Any] | None = None) -> dict[str, Any]:
    """Map matched_rules + policy_rule_id to deduplicated ATT&CK techniques."""
    attck_map = attck_map or get_attck_map()
    matched_index = attck_map.get("matched_rules") or {}
    policy_index = attck_map.get("policy_rules") or {}

    seen: set[str] = set()
    techniques: list[dict[str, str]] = []

    def add_techniques(entries: list[dict[str, str]]) -> None:
        for tech in entries:
            tid = tech["id"]
            if tid in seen:
                continue
            seen.add(tid)
            techniques.append(tech)

    for rule_id in item.get("matched_rules") or []:
        add_techniques(_techniques_from_entry(matched_index.get(str(rule_id))))

    policy_id = str(item.get("policy_rule_id") or "")
    if policy_id:
        add_techniques(_techniques_from_entry(policy_index.get(policy_id)))
        if policy_id.startswith("HARD-GUARDRAIL-"):
            base = policy_id.replace("HARD-GUARDRAIL-", "", 1)
            for key in (base, base.lower(), base.replace("_", "-").lower()):
                add_techniques(_techniques_from_entry(policy_index.get(f"HARD-GUARDRAIL-{key}")))
                add_techniques(_techniques_from_entry(matched_index.get(key.lower())))

    tactics: list[dict[str, str]] = []
    tactic_seen: set[str] = set()
    for tech in techniques:
        tid = tech.get("tactic_id") or tech.get("tactic") or ""
        if not tid or tid in tactic_seen:
            continue
        tactic_seen.add(tid)
        tactics.append(
            {
                "id": tech.get("tactic_id") or "",
                "name": tech.get("tactic") or "",
            }
        )

    return {
        "techniques": techniques,
        "tactics": tactics,
        "technique_ids": [t["id"] for t in techniques],
        "tactic_ids": [t["id"] for t in tactics if t.get("id")],
    }


def apply_mitre_attack(items: list[dict[str, Any]], attck_map: dict[str, Any] | None = None) -> None:
    attck_map = attck_map or get_attck_map()
    for item in items:
        item["mitre_attack"] = resolve_mitre_attack(item, attck_map)


def format_mitre_attack_short(mitre: dict[str, Any] | None, *, limit: int = 3) -> str:
    if not mitre:
        return ""
    parts: list[str] = []
    for tech in mitre.get("techniques") or []:
        label = tech.get("id") or ""
        name = tech.get("name") or ""
        if name:
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


_map = get_attck_map()
