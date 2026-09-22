"""One TLS policy for SLS SDK queries and Proxy availability probes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dataasset_paths import DATAASSET_ROOT


def tls_policy(config: dict[str, Any]) -> bool | str:
    """Default to trust verification; accept only an explicit boolean opt-out.

    Relative CA paths belong to the selected asset root, not the process cwd.
    Resolve missing CA files before probing or constructing a credentialed SDK
    client so a broken trust configuration cannot trigger fallback traffic.
    """
    verify = config.get("tls_verify", True)
    if not isinstance(verify, bool):
        raise ValueError("SLS tls_verify must be a boolean")
    ca = config.get("ca_file")
    if ca is not None and (not isinstance(ca, str) or not ca.strip()):
        raise ValueError("SLS ca_file must be a nonempty path string")
    if ca and not verify:
        raise ValueError("SLS ca_file requires tls_verify=true")
    if not ca:
        return verify
    path = Path(ca).expanduser()
    if not path.is_absolute():
        path = DATAASSET_ROOT / path
    if not path.is_file():
        raise FileNotFoundError(f"SLS ca_file not found: {path}")
    return str(path.resolve())
