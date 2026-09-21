"""Compatibility import for Skill input helpers; implementation lives in skill_runtime.

Alias the module rather than copying functions so existing public imports and
completeness interception use the same implementation and globals. Fetch mocks
must target the actual fetch module, which both planners and adapters now call.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Direct historical scripts add only data-access to sys.path. Bootstrap the
# sibling package from this file's location, never from DATAASSET_ROOT or cwd.
_SHARED_ROOT = Path(__file__).resolve().parent.parent
if str(_SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(_SHARED_ROOT))
from skill_runtime import inputs as _inputs  # noqa: E402

sys.modules[__name__] = _inputs
