"""Match attack_chain to risk-identification chain_patterns (via risk_rules_bridge)."""

from __future__ import annotations

from typing import Any, Callable

from risk_rules_bridge import match_chain_pattern as _match_chain_pattern


def match_attack_pattern(
    attack_chain: list[dict[str, Any]],
    patterns_doc: dict[str, Any],
    *,
    index: dict[str, dict[str, Any]] | None = None,
    cmd_text_fn: Callable[[dict[str, Any]], str] | None = None,
    stage_rules: dict[str, set[str]] | None = None,
) -> str | None:
    """Return best-matching chain_patterns[].id for the given attack_chain."""
    return _match_chain_pattern(
        attack_chain,
        patterns_doc,
        stage_rules=stage_rules,
        index=index,
        cmd_text_fn=cmd_text_fn,
    )
