#!/usr/bin/env bash
set -euo pipefail
# This is an operator-approved bridge for legacy capability gaps, not a way to
# obtain a server campaign lease or re-enroll a device with a new identity.
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recover-saas-update.py" --mode migrate "$@"
