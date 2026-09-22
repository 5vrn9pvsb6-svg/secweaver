#!/usr/bin/env python3
"""Reject tracked files covered by ignore rules; source exports have no Git index."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
if not (ROOT / '.git').exists():
    print('tracked-hygiene: source archive has no index')
else:
    # Ignore rules alone do not remove previously committed caches/private output.
    result = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-ci', '--exclude-standard'],
                            check=True, capture_output=True, text=True)
    if result.stdout.strip():
        raise SystemExit('Tracked files match ignore rules; review and untrack them:\n' + result.stdout)
    print('tracked-hygiene: OK')
