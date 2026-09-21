"""Bridge traceability-analysis to risk-identification rule packs (single source of truth)."""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

SKILL_ROOT = Path(__file__).resolve().parent.parent
RISK_ROOT = SKILL_ROOT.parent / "risk-identification"
RISK_RULES_DIR = RISK_ROOT / "rules"
RISK_SCRIPTS = RISK_ROOT / "scripts"
DEFAULT_CHAIN_PATTERNS_PATH = RISK_RULES_DIR / "chain-patterns.json"
DEFAULT_EXEC_RULES_PATH = RISK_RULES_DIR / "exec-rules.json"
LEGACY_ATTACK_PATTERNS_PATH = SKILL_ROOT / "attack-patterns.json"

WAF_URL_LITERALS = (
    "shell",
    "webshell",
    "cmd=",
    "eval(",
    "upload",
    ".phtml",
    "backdoor",
    "c99",
    "r57",
    "s.phtml",
)

_chain_doc: dict[str, Any] | None = None
_exec_config: dict[str, Any] | None = None


def _ensure_risk_scripts_path() -> None:
    path = str(RISK_SCRIPTS)
    if path not in sys.path:
        sys.path.insert(0, path)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def load_chain_patterns(path: Path | str | None = None) -> dict[str, Any]:
    global _chain_doc
    target = Path(path) if path else DEFAULT_CHAIN_PATTERNS_PATH
    if path is None and _chain_doc is not None:
        return _chain_doc
    doc = load_json(target)
    if path is None:
        _chain_doc = doc
    return doc


def load_exec_rules_config(path: Path | str | None = None) -> dict[str, Any]:
    global _exec_config
    target = Path(path) if path else DEFAULT_EXEC_RULES_PATH
    if path is None and _exec_config is not None:
        return _exec_config
    doc = load_json(target)
    if path is None:
        _exec_config = doc
    return doc


def _literal_tokens_from_pattern(pattern: str) -> list[str]:
    tokens: list[str] = []
    for chunk in re.findall(r"[A-Za-z0-9._/?=-]{3,}", pattern or ""):
        cleaned = chunk.replace("\\", "").strip(".")
        if len(cleaned) < 3:
            continue
        if any(ch in cleaned for ch in "()[]{}+*^$|"):
            continue
        tokens.append(cleaned)
    return tokens


def webshell_url_patterns_from_exec_rules(config: dict[str, Any] | None = None) -> list[str]:
    """URL substrings for WAF/web_access initial-access heuristics (derived from exec-rules)."""
    cfg = config or load_exec_rules_config()
    found = set(WAF_URL_LITERALS)
    for bucket in ("p0_regex", "p1_regex"):
        for entry in cfg.get(bucket) or []:
            if str(entry.get("id")) != "webshell_write":
                continue
            for token in _literal_tokens_from_pattern(str(entry.get("pattern") or "")):
                found.add(token.lower())
    return sorted(found)


def download_exec_patterns_from_exec_rules(config: dict[str, Any] | None = None) -> list[str]:
    cfg = config or load_exec_rules_config()
    found: set[str] = set()
    for bucket in ("p0_regex", "p1_regex"):
        for entry in cfg.get(bucket) or []:
            if str(entry.get("id")) != "download_and_execute":
                continue
            for token in _literal_tokens_from_pattern(str(entry.get("pattern") or "")):
                low = token.lower()
                if low in {"curl", "wget", "fetch", "python", "perl"}:
                    found.add(low)
                if low.startswith("python"):
                    found.add("python -c")
                if low.startswith("perl"):
                    found.add("perl -e")
    found.update({"curl", "wget", "fetch", "python -c", "perl -e"})
    return sorted(found)


def literal_tokens_for_rule_id(rule_id: str, config: dict[str, Any] | None = None) -> tuple[str, ...]:
    """Derive stage-matching literals from risk-identification rule packs (no hardcoded map)."""
    cfg = config or load_exec_rules_config()
    rid = str(rule_id)
    tokens: set[str] = set()
    for bucket in ("p0_regex", "p1_regex"):
        for entry in cfg.get(bucket) or []:
            if str(entry.get("id")) != rid:
                continue
            for token in _literal_tokens_from_pattern(str(entry.get("pattern") or "")):
                tokens.add(token.lower())
    for entry in cfg.get("p1_keywords") or []:
        if str(entry.get("id")) != rid:
            continue
        keyword = str(entry.get("keyword") or "").strip().lower()
        if keyword:
            tokens.add(keyword.split()[0])
    if rid == "webshell_write":
        tokens.update(t.lower() for t in webshell_url_patterns_from_exec_rules(cfg))
        tokens.update({"webshell", "upload", ".phtml", "s.phtml"})
    elif rid == "download_and_execute":
        tokens.update(t.lower() for t in download_exec_patterns_from_exec_rules(cfg))
        tokens.update({"sshpass", "sh -c", "bash"})
    elif rid == "network_exfil_tools":
        tokens.update(t.lower() for t in lateral_tool_patterns_from_exec_rules(cfg))
    elif rid == "LATERAL-SSH-001":
        tokens.update(t.lower() for t in lateral_tool_patterns_from_exec_rules(cfg))
        tokens.add("sshpass")
    elif rid == "external_listener_shell_exec":
        tokens.update({"shell", "sh -c", "bash"})
    elif rid == "root_ssh_login":
        tokens.update({"accepted", "ssh", "ssh_login_success"})
    if not tokens:
        tokens.add(rid.replace("_", " "))
    return tuple(sorted(tokens))


def web_listeners_from_exec_rules(config: dict[str, Any] | None = None) -> frozenset[str]:
    cfg = config or load_exec_rules_config()
    return frozenset(str(x).lower() for x in (cfg.get("web_listeners") or []) if str(x).strip())


def lateral_tool_patterns_from_exec_rules(config: dict[str, Any] | None = None) -> list[str]:
    cfg = config or load_exec_rules_config()
    found: set[str] = set()
    for entry in cfg.get("p1_keywords") or []:
        if str(entry.get("id")) != "network_exfil_tools":
            continue
        keyword = str(entry.get("keyword") or "").strip().lower()
        if keyword:
            found.add(keyword.split()[0])
    found.update({"hydra", "ncrack", "medusa", "sshpass", "patator"})
    return sorted(found)


def load_trace_patterns(path: Path | str | None = None) -> dict[str, Any]:
    """Build correlate-compatible patterns view from risk-identification rule packs."""
    chain_doc = load_chain_patterns(path)
    exec_cfg = load_exec_rules_config()
    return {
        "version": chain_doc.get("version"),
        "source": "risk-identification",
        "chain_patterns_path": str(path or DEFAULT_CHAIN_PATTERNS_PATH),
        "patterns": chain_doc.get("chain_patterns") or [],
        "stage_mitre_defaults": chain_doc.get("stage_mitre_defaults") or {},
        "webshell_url_patterns": webshell_url_patterns_from_exec_rules(exec_cfg),
        "download_exec_patterns": download_exec_patterns_from_exec_rules(exec_cfg),
        "lateral_tools": lateral_tool_patterns_from_exec_rules(exec_cfg),
    }


def policy_rules_by_chain(path: Path | str | None = None) -> dict[str, list[str]]:
    doc = load_chain_patterns(path)
    out: dict[str, list[str]] = {}
    for pattern in doc.get("chain_patterns") or []:
        pid = str(pattern.get("id") or "")
        rules = list(pattern.get("policy_rules") or [])
        if pid and rules:
            out[pid] = rules
    return out


def _ssh_success(ev: dict[str, Any]) -> bool:
    result = str(ev.get("result") or "").lower()
    message = str(ev.get("message") or ev.get("raw") or "").lower()
    blob = f"{result} {message}"
    return "accept" in blob or result in {"accepted", "success", "successful"}


def _event_as_risk_item(ev: dict[str, Any], cmd_text_fn: Callable[[dict[str, Any]], str]) -> dict[str, Any]:
    bundle = ev.get("_bundle")
    item = dict(ev)
    if bundle == "host_exec":
        item["risk_module"] = "exec"
        item["command"] = cmd_text_fn(ev)
    elif bundle == "host_connect":
        item["risk_module"] = "connect"
    elif bundle == "host_persistence":
        item["risk_module"] = "persistence"
    elif bundle == "ssh_auth":
        item["risk_module"] = "ssh"
    elif bundle in {"syslog_risk_alert", "linux_syslog"}:
        item["risk_module"] = "syslog"
    return item


def collect_rules_for_event(
    ev: dict[str, Any],
    cmd_text_fn: Callable[[dict[str, Any]], str],
) -> set[str]:
    """Return matched_rule + policy rule keys for one evidence event."""
    keys: set[str] = set()
    bundle = ev.get("_bundle")
    if bundle is None and (ev.get("command") is not None or ev.get("comm")):
        bundle = "host_exec"
    if bundle == "host_exec":
        _ensure_risk_scripts_path()
        from exec_rules import get_exec_rules_engine  # noqa: WPS433

        _, matched, _ = get_exec_rules_engine().match_exec_rules(ev)
        keys.update(str(x) for x in matched)
        try:
            from behavior_policy import force_alert_hits  # noqa: WPS433

            item = _event_as_risk_item(ev, cmd_text_fn)
            item["matched_rules"] = list(matched)
            for decision in force_alert_hits(item):
                keys.add(str(decision.rule_id))
        except Exception:
            text = cmd_text_fn(ev).lower()
            if "sshpass" in text:
                keys.add("LATERAL-SSH-001")
    elif bundle == "ssh_auth" and _ssh_success(ev):
        keys.add("root_ssh_login")
    elif bundle == "host_connect":
        keys.add("exec_correlated_egress")
    elif bundle == "host_persistence":
        _ensure_risk_scripts_path()
        try:
            from persistence_rules import get_persistence_rules_engine  # noqa: WPS433

            _, matched, _ = get_persistence_rules_engine().match_event(ev)
            keys.update(str(x) for x in matched)
        except Exception:
            if ev.get("path"):
                keys.add("persistence_generic_change")
    return keys


def collect_stage_rules(
    attack_chain: list[dict[str, Any]],
    index: dict[str, dict[str, Any]],
    cmd_text_fn: Callable[[dict[str, Any]], str],
) -> dict[str, set[str]]:
    by_stage: dict[str, set[str]] = defaultdict(set)
    for stage in attack_chain:
        name = str(stage.get("stage") or "")
        if not name:
            continue
        for ref in stage.get("evidence_refs") or []:
            ev = index.get(str(ref))
            if not ev:
                continue
            by_stage[name].update(collect_rules_for_event(ev, cmd_text_fn))
        desc = str(stage.get("description") or "").lower()
        if name == "lateral_movement" and ("sshpass" in desc or "ssh" in desc):
            by_stage[name].add("LATERAL-SSH-001")
        if name == "initial_access" and any(x in desc for x in ("webshell", "web_exploit", "web shell")):
            by_stage[name].update({"webshell_write", "WEB-SHELL-001"})
    return dict(by_stage)


def resolve_matched_pattern_from_payload(payload: dict[str, Any]) -> str | None:
    for key in ("risk_identification", "risk_assessment", "risk"):
        block = payload.get(key)
        if not isinstance(block, dict):
            continue
        explicit = block.get("chain_pattern") or block.get("matched_pattern")
        if explicit:
            return str(explicit)
        tags: set[str] = set()
        for inc in block.get("top_incidents") or []:
            if not isinstance(inc, dict):
                continue
            for tag in inc.get("risk_tags") or inc.get("tags") or []:
                tags.add(str(tag).lower())
            for rule in inc.get("matched_rules") or []:
                tags.add(str(rule).lower())
        if "webshell" in tags and ("lateral_movement" in tags or "network_exfil_tools" in tags):
            return "web_shell_to_ssh_lateral"
        if "exfiltration" in tags and "remote_download" in tags:
            return "exec_to_exfiltration"
    return None


def match_chain_pattern(
    attack_chain: list[dict[str, Any]],
    patterns_doc: dict[str, Any],
    *,
    stage_rules: dict[str, set[str]] | None = None,
    index: dict[str, dict[str, Any]] | None = None,
    cmd_text_fn: Callable[[dict[str, Any]], str] | None = None,
) -> str | None:
    """Match attack_chain to risk-identification chain_patterns[].id."""
    patterns = patterns_doc.get("patterns") or patterns_doc.get("chain_patterns") or []
    if not patterns or not attack_chain:
        return None

    if stage_rules is None and index is not None and cmd_text_fn is not None:
        stage_rules = collect_stage_rules(attack_chain, index, cmd_text_fn)
    stage_rules = stage_rules or {}

    best_id: str | None = None
    best_score = 0
    for pattern in patterns:
        required_stages = list(pattern.get("stages") or [])
        stage_rule_map = pattern.get("stage_rules") or {}
        if not required_stages:
            continue
        score = 0
        matched_stages = 0
        for stage_name in required_stages:
            observed = stage_rules.get(stage_name) or set()
            required = {str(x) for x in (stage_rule_map.get(stage_name) or [])}
            overlap = observed & required
            if overlap:
                matched_stages += 1
                score += len(overlap)
                continue
            if _stage_text_hits_rules(attack_chain, stage_name, required):
                matched_stages += 1
                score += 1
        if matched_stages < len(required_stages):
            continue
        if score > best_score:
            best_score = score
            best_id = str(pattern.get("id") or "")
    return best_id


def _stage_text_hits_rules(
    attack_chain: list[dict[str, Any]],
    stage_name: str,
    required_rules: set[str],
) -> bool:
    if not required_rules:
        return False
    blob_parts: list[str] = []
    for stage in attack_chain:
        if str(stage.get("stage") or "") != stage_name:
            continue
        blob_parts.extend(
            [
                str(stage.get("description") or ""),
                str(stage.get("host") or ""),
                str(stage.get("vector") or ""),
                str(stage.get("url") or ""),
            ]
        )
    blob = " ".join(blob_parts).lower()
    if not blob.strip():
        return False
    for rule_id in required_rules:
        for token in literal_tokens_for_rule_id(str(rule_id)):
            if token.lower() in blob:
                return True
    return False


def resolve_matched_pattern(
    payload: dict[str, Any],
    attack_chain: list[dict[str, Any]],
    patterns_doc: dict[str, Any],
    *,
    index: dict[str, dict[str, Any]] | None = None,
    cmd_text_fn: Callable[[dict[str, Any]], str] | None = None,
) -> str | None:
    from_payload = resolve_matched_pattern_from_payload(payload)
    if from_payload:
        return from_payload
    return match_chain_pattern(
        attack_chain,
        patterns_doc,
        index=index,
        cmd_text_fn=cmd_text_fn,
    )
