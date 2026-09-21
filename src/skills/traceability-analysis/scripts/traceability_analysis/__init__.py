"""Traceability analysis implementation modules."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_PATH = Path(__file__).resolve().parents[1]
DATA_ACCESS_PATH = Path(__file__).resolve().parents[3] / "_shared" / "data-access"
for _path in (SCRIPTS_PATH, DATA_ACCESS_PATH):
    _text = str(_path)
    if _text not in sys.path:
        sys.path.insert(0, _text)
