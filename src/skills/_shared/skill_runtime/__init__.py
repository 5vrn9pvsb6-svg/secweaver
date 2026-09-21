"""Upper-layer Skill input adaptation and orchestration, not connector execution."""

from pathlib import Path
import sys

SKILLS_ROOT = Path(__file__).resolve().parents[2]
DATA_ACCESS_ROOT = SKILLS_ROOT / "_shared" / "data-access"

# Repository-local scripts are supported without installing a Python wheel.
# Resolve canonical fetch helpers once from source, independent of cwd/assets.
if str(DATA_ACCESS_ROOT) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_ROOT))
