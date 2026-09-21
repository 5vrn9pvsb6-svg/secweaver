"""Filesystem paths for the alert-confirmation skill."""

from __future__ import annotations

from pathlib import Path

ATTACK_TYPES_PATH = Path(__file__).resolve().parents[2] / "attack-types.json"
FP_PATTERNS_PATH = Path(__file__).resolve().parents[2] / "fp-patterns.json"
DATA_ACCESS_PATH = Path(__file__).resolve().parents[3] / "_shared" / "data-access"
