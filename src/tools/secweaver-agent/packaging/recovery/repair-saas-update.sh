#!/usr/bin/env bash
set -euo pipefail
# Keep parsing/atomic writes shared with the migration path. Python is a recovery
# prerequisite only; neither the Agent nor normal installation depends on it.
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recover-saas-update.py" --mode repair "$@"
