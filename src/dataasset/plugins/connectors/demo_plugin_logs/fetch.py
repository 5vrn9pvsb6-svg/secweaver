#!/usr/bin/env python3
"""Demo stdio-json connector plugin.

Input on stdin:
  {"connector": {...}, "credentials": {...}, "query": "...", "params": {...}}

Output on stdout:
  {"events": [...], "meta": {...}}
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from typing import Any


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def main() -> int:
    request = json.load(sys.stdin)
    params = request.get("params") if isinstance(request, dict) else {}
    if not isinstance(params, dict):
        params = {}
    query = str(request.get("query") or "")
    connector = request.get("connector") if isinstance(request, dict) else {}
    connector_id = connector.get("connector_id") if isinstance(connector, dict) else "conn-demo-plugin"

    src_ip = str(params.get("src_ip") or "203.0.113.10")
    limit = max(1, min(_int_value(params.get("limit"), 2), 10))
    now = dt.datetime(2026, 7, 7, 0, 0, tzinfo=dt.timezone.utc)
    events = [
        {
            "timestamp": (now + dt.timedelta(minutes=offset)).isoformat().replace("+00:00", "Z"),
            "src_ip": src_ip,
            "target_ip": "198.51.100.10",
            "action": "plugin-demo",
            "severity": "medium",
            "message": "demo plugin emitted a normalized event",
            "query": query,
            "connector_id": connector_id,
        }
        for offset in range(limit)
    ]
    print(
        json.dumps(
            {
                "events": events,
                "meta": {
                    "mode": "plugin",
                    "backend": "demo_plugin_logs",
                    "rows_returned": len(events),
                },
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
