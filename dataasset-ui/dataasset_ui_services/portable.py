"""Whitelisted local UI adapter for the portable deployment CLI."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .common import DATAASSET_DIR, ROOT


def _operator_paths() -> tuple[Path, Path, Path]:
    """Resolve trusted startup configuration, never a path supplied by an HTTP request.

    Explicit command/root settings support independently installed Operators. The
    old in-repository path remains a fallback for existing developer checkouts.
    Runtime resolution is shared by status and execution so both inspect one state.
    """
    def absolute(value: str) -> Path:
        path = Path(value).expanduser()
        return (path if path.is_absolute() else ROOT / path).resolve()

    root_value = os.environ.get("SECWEAVER_PORTABLE_ROOT", "").strip()
    command_value = os.environ.get("SECWEAVER_PORTABLE_COMMAND", "").strip()
    operator_root = absolute(root_value) if root_value else ROOT / "src" / "es-operator"
    if command_value:
        command = absolute(command_value)
        if not root_value:
            operator_root = command.parent.parent if command.parent.name == "bin" else command.parent
    else:
        command = operator_root / "secweaver-portable"
        if not command.is_file():
            command = operator_root / "bin" / "secweaver-portable"
    runtime_value = os.environ.get("SECWEAVER_PORTABLE_RUNTIME", "").strip()
    runtime = absolute(runtime_value) if runtime_value else operator_root / "runtime"
    return command, operator_root, runtime


def _run(arguments: list[str], *, timeout: int = 300) -> dict[str, Any]:
    """Run only the configured local CLI, carrying the Studio's selected registry."""
    command, operator_root, runtime = _operator_paths()
    if not command.is_file():
        return {
            "ok": False,
            "available": False,
            "returncode": 127,
            "error": "ES Operator is unavailable; configure SECWEAVER_PORTABLE_ROOT or SECWEAVER_PORTABLE_COMMAND",
        }
    environment = dict(os.environ)
    environment.update({
        "SECWEAVER_PORTABLE_ROOT": str(operator_root),
        "SECWEAVER_PORTABLE_RUNTIME": str(runtime),
        "DATAASSET_ROOT": str(DATAASSET_DIR),
    })
    result = subprocess.run(
        [str(command), "--json", *arguments],
        cwd=ROOT,
        env=environment,
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
    """Probe the configured installation even when it lives outside Community."""
    _, _, runtime = _operator_paths()
    return _run(["status"] if (runtime / "state.json").is_file() else ["doctor"], timeout=15)


def _positive_int(payload: dict[str, Any], key: str, default: int) -> int:
    value = int(payload.get(key) or default)
    if value <= 0:
        raise ValueError(f"{key} must be positive")
    return value


def portable_action(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Translate Studio operations to the enterprise-profile Operator contract.

    Installer profiles are identified by enterprise/platform/architecture; ES
    credentials are revoked by enrollment key. Neither operation revokes Agent
    Gateway identities. Gateway URL/token remain trusted startup configuration.
    """
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
            "--enterprise-id",
            str(payload.get("enterprise_id") or "").strip(),
            "--platform",
            str(payload.get("platform") or "linux").strip(),
            "--buffer-limit",
            str(payload.get("buffer_limit") or "2G").strip(),
        ]
        for key, flag in (
            ("arch", "--arch"),
            ("agent_package", "--agent-package"),
        ):
            value = str(payload.get(key) or "").strip()
            if value:
                arguments.extend([flag, value])
        # Select only known shippers; never turn a request field into a CLI flag.
        shipper = str(payload.get("shipper") or "filebeat").strip()
        shipper_flags = {"filebeat": "filebeat", "fluent-bit": "fluent-bit", "secweaver": "secweaver-shipper"}
        if shipper not in shipper_flags:
            raise ValueError("unsupported shipper")
        arguments.extend(["--shipper", shipper])
        package = str(payload.get("shipper_package") or "").strip()
        if package:
            arguments.extend([f"--{shipper_flags[shipper]}-package", package])
        if payload.get("reuse_shipper") is True:
            arguments.append(f"--reuse-{shipper_flags[shipper]}")
        for key, flag in (
            ("reuse_agent", "--reuse-agent"),
            ("rotate", "--rotate"),
        ):
            if payload.get(key) is True:
                arguments.append(flag)
        return _run(arguments, timeout=120)
    if action == "revoke":
        key = str(payload.get("enrollment_key") or "").strip()
        if not key:
            raise ValueError("enrollment_key is required")
        return _run(["revoke", "--enrollment-key", key], timeout=30)
    if action == "close_enrollment":
        enterprise = str(payload.get("enterprise_id") or "").strip()
        if not enterprise:
            raise ValueError("enterprise_id is required")
        arguments = ["close-enrollment", "--enterprise-id", enterprise,
                     "--platform", str(payload.get("platform") or "linux").strip()]
        arch = str(payload.get("arch") or "").strip()
        if arch:
            arguments.extend(["--arch", arch])
        return _run(arguments, timeout=30)
    raise ValueError(f"unsupported portable action: {action}")
