"""Filesystem paths for traceability-analysis."""

from __future__ import annotations

from pathlib import Path

CHAIN_PATTERNS_PATH = (
    Path(__file__).resolve().parents[3] / "risk-identification" / "rules" / "chain-patterns.json"
)
LEGACY_PATTERNS_PATH = Path(__file__).resolve().parents[2] / "attack-patterns.json"
PATTERNS_PATH = CHAIN_PATTERNS_PATH
SCRIPTS_PATH = Path(__file__).resolve().parents[1]
DATA_ACCESS_PATH = Path(__file__).resolve().parents[3] / "_shared" / "data-access"
