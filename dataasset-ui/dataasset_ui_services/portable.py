"""Whitelisted local UI adapter for the portable deployment CLI."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .common import ROOT

PORTABLE_COMMAND = ROOT / "src" / "es-operator" / "secweaver-portable"
PORTABLE_STATE = ROOT / "src" / "es-operator" / "runtime" / "state.json"


def _run(arguments: list[str], *, timeout: int = 300) -> dict[str, Any]:
    if not PORTABLE_COMMAND.is_file():
        return {
            "ok": False,
            "available": False,
            "returncode": 127,
            "error": "portable deployment module is not included in this distribution",
        }
    result = subprocess.run(
        [str(PORTABLE_COMMAND), "--json", *arguments],
        cwd=ROOT,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = (result.stdout or "").strip()
    try:
        data = json.loads(output) if output else {}
    except json.JSONDecodeError:
        data = {}
    if result.returncode != 0:
        message = data.get("error") or (result.stderr or output or "portable command failed").strip()
        return {"ok": False, "returncode": result.returncode, "error": message}
    return {"ok": True, "returncode": 0, "data": data}


def portable_status() -> dict[str, Any]:
    return _run(["status"] if PORTABLE_STATE.is_file() else ["doctor"], timeout=15)


def _positive_int(payload: dict[str, Any], key: str, default: int) -> int:
    value = int(payload.get(key) or default)
    if value <= 0:
        raise ValueError(f"{key} must be positive")
    return value


def portable_action(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    if action == "init":
        host = str(payload.get("advertise_host") or "").strip()
        if not host:
            raise ValueError("advertise_host is required")
        arguments = [
            "init",
            "--advertise-host",
            host,
            "--ingest-port",
            str(_positive_int(payload, "ingest_port", 9443)),
            "--query-port",
            str(_positive_int(payload, "query_port", 9200)),
            "--retention-days",
            str(_positive_int(payload, "retention_days", 30)),
        ]
        if payload.get("force") is True:
            arguments.append("--force")
        return _run(arguments, timeout=60)
    if action in {"up", "down"}:
        return _run([action], timeout=300)
    if action == "install_assets":
        arguments = ["install-assets"]
        dataasset_root = str(payload.get("dataasset_root") or "").strip()
        if dataasset_root:
            arguments.extend(["--dataasset-root", dataasset_root])
        if payload.get("force") is True:
            arguments.append("--force")
        return _run(arguments, timeout=120)
    if action == "enroll":
        arguments = [
            "enroll",
            "--name",
            str(payload.get("name") or "").strip(),
            "--enterprise-id",
            str(payload.get("enterprise_id") or "").strip(),
            "--platform",
            str(payload.get("platform") or "linux").strip(),
            "--buffer-limit",
            str(payload.get("buffer_limit") or "2G").strip(),
        ]
        for key, flag in (
            ("agent_package", "--agent-package"),
            ("fluent_bit_package", "--fluent-bit-package"),
        ):
            value = str(payload.get(key) or "").strip()
            if value:
                arguments.extend([flag, value])
        for key, flag in (
            ("reuse_agent", "--reuse-agent"),
            ("reuse_fluent_bit", "--reuse-fluent-bit"),
            ("rotate", "--rotate"),
        ):
            if payload.get(key) is True:
                arguments.append(flag)
        return _run(arguments, timeout=120)
    if action == "revoke":
        name = str(payload.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        return _run(["revoke", "--name", name], timeout=30)
    if action == "close_enrollment":
        name = str(payload.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        return _run(["close-enrollment", "--name", name], timeout=30)
    raise ValueError(f"unsupported portable action: {action}")
