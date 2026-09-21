"""SSH file connector: execute read-only grep/tail on remote log files."""

from __future__ import annotations

import fnmatch
import io
import ipaddress
import re
from datetime import datetime
from typing import Any, Callable

SSH_GREP_TAIL = re.compile(
    r"^grep -E '(?P<pattern>[^']+)' (?P<path>[^\s|]+) \| tail -n (?P<lines>\d+)$"
)

# nginx combined: 203.0.113.10 - - [21/Jun/2026:08:15:01 +0800] "GET /path HTTP/1.1" 200 1234
NGINX_COMBINED = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)'
)


def _load_paramiko():
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "live SSH fetch requires: pip install paramiko"
        ) from exc
    return paramiko


def _load_private_key(paramiko: Any, key_str: str) -> Any:
    key_str = key_str.strip()
    if not key_str:
        raise ValueError("empty private_key in SSH credentials")
    for key_class in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
        try:
            return key_class.from_private_key(io.StringIO(key_str))
        except paramiko.ssh_exception.SSHException:
            continue
    raise ValueError("unable to parse SSH private_key (RSA/ECDSA/Ed25519)")


def _connect_one(
    paramiko: Any,
    *,
    host: str,
    port: int,
    username: str,
    credentials: dict[str, Any],
    sock: Any | None = None,
) -> Any:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if sock is not None:
        connect_kwargs["sock"] = sock

    private_key = (credentials.get("private_key") or "").strip()
    password = credentials.get("password") or ""
    if private_key:
        connect_kwargs["pkey"] = _load_private_key(paramiko, private_key)
    elif password:
        connect_kwargs["password"] = password
    else:
        raise ValueError("SSH credentials need private_key or password")

    client.connect(**connect_kwargs)
    return client


def connect_ssh(
    connector: dict[str, Any],
    credentials: dict[str, Any],
    *,
    load_connector: Callable[[str], dict[str, Any]] | None = None,
    resolve_credentials: Callable[[str], dict[str, Any]] | None = None,
) -> Any:
    """Open SSH session to target host, optionally via bastion jump."""
    if credentials.get("type") != "ssh":
        raise ValueError(f"unsupported SSH credential type: {credentials.get('type')}")

    paramiko = _load_paramiko()
    config = connector.get("config") or {}
    host = config["host"]
    port = int(config.get("port") or 22)
    username = credentials.get("username") or "root"

    bastion_id = config.get("bastion_id")
    if not bastion_id:
        return _connect_one(
            paramiko, host=host, port=port, username=username, credentials=credentials
        )

    if not load_connector or not resolve_credentials:
        raise ValueError("bastion jump requires load_connector and resolve_credentials")

    bastion = load_connector(bastion_id)
    bastion_creds = resolve_credentials(bastion["credentials_ref"])
    bastion_cfg = bastion.get("config") or {}
    bastion_host = bastion_cfg["host"]
    bastion_port = int(bastion_cfg.get("port") or 22)
    bastion_user = bastion_creds.get("username") or "root"

    bastion_client = _connect_one(
        paramiko,
        host=bastion_host,
        port=bastion_port,
        username=bastion_user,
        credentials=bastion_creds,
    )
    transport = bastion_client.get_transport()
    if transport is None:
        bastion_client.close()
        raise RuntimeError("bastion SSH transport unavailable")

    dest_addr = (host, port)
    local_addr = (bastion_host, bastion_port)
    channel = transport.open_channel("direct-tcpip", dest_addr, local_addr)
    try:
        return _connect_one(
            paramiko,
            host=host,
            port=port,
            username=username,
            credentials=credentials,
            sock=channel,
        )
    except Exception:
        channel.close()
        bastion_client.close()
        raise


def _pattern_allowed(pattern: str, constraints: dict[str, Any]) -> bool:
    if re.search(r"[;`$&|<>(){}\\]", pattern):
        return False
    try:
        ipaddress.ip_address(pattern)
        return True
    except ValueError:
        pass
    allowed = constraints.get("allowed_grep_patterns") or []
    if any(token in pattern for token in allowed):
        return True
    # Allow simple alphanumeric / dot / dash patterns (IPs, usernames)
    return bool(re.fullmatch(r"[\w.\-+@/]+", pattern))


def _path_allowed(log_path: str, connector: dict[str, Any]) -> None:
    constraints = connector.get("constraints") or {}
    forbidden = constraints.get("forbidden_paths") or []
    for pattern in forbidden:
        if fnmatch.fnmatch(log_path, pattern):
            raise ValueError(f"log_path forbidden by connector policy: {log_path}")

    config = connector.get("config") or {}
    log_paths = config.get("log_paths") or {}
    allowed_paths: set[str] = set()
    if isinstance(log_paths, dict):
        allowed_paths.update(str(v) for v in log_paths.values())
    elif isinstance(log_paths, list):
        allowed_paths.update(str(v) for v in log_paths)

    defaults = {"/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/secure"}
    allowed_paths |= defaults
    if allowed_paths and log_path not in allowed_paths:
        raise ValueError(f"log_path not in connector allowlist: {log_path}")


def validate_ssh_command(command: str, connector: dict[str, Any]) -> dict[str, str]:
    """Ensure rendered ssh_command matches read-only grep|tail pattern."""
    constraints = connector.get("constraints") or {}
    allowed_cmds = constraints.get("allowed_read_commands") or ["grep", "tail", "cat"]
    if "grep" not in allowed_cmds or "tail" not in allowed_cmds:
        raise ValueError("connector constraints disallow grep|tail read pattern")

    match = SSH_GREP_TAIL.match(command.strip())
    if not match:
        raise ValueError(
            "ssh_command must match: grep -E '<pattern>' <log_path> | tail -n <N>"
        )

    pattern = match.group("pattern")
    log_path = match.group("path")
    lines = int(match.group("lines"))

    if not _pattern_allowed(pattern, constraints):
        raise ValueError(f"grep pattern not allowed: {pattern!r}")

    _path_allowed(log_path, connector)

    max_lines = int(constraints.get("max_lines_per_query") or 10000)
    if lines > max_lines:
        raise ValueError(f"max_lines {lines} exceeds connector limit {max_lines}")

    return {"grep_pattern": pattern, "log_path": log_path, "max_lines": str(lines)}


def execute_ssh_command(client: Any, command: str, *, timeout: int = 120) -> str:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if exit_status != 0 and not out.strip():
        raise RuntimeError(err.strip() or f"ssh command failed with exit {exit_status}")
    return out


def _auth_timestamp(month: str, day: str, time_str: str) -> str:
    year = datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
        return dt.astimezone().isoformat()
    except ValueError:
        return f"{month} {day} {time_str}"


def parse_auth_line(line: str, *, host: str) -> dict[str, Any] | None:
    text = line.strip()
    header = re.match(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+"
        r"(?P<result>Accepted|Failed|Invalid|Disconnected|Connection closed|error|fatal)\b",
        text,
    )
    if not header:
        return None
    groups = header.groupdict()
    user_m = re.search(r"for (?:invalid user )?(\S+)(?:\s+from|\s|$)", text)
    ip_m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", text)
    return {
        "host": groups.get("host") or host,
        "src_ip": ip_m.group(1) if ip_m else None,
        "user": user_m.group(1) if user_m else None,
        "result": groups.get("result"),
        "timestamp": _auth_timestamp(groups["month"], groups["day"], groups["time"]),
        "raw_line": text,
    }


def parse_nginx_line(line: str, *, host: str) -> dict[str, Any] | None:
    match = NGINX_COMBINED.match(line.strip())
    if not match:
        return None
    groups = match.groupdict()
    ts_raw = groups["ts"]
    try:
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        ts = ts_raw
    return {
        "host": host,
        "src_ip": groups["src_ip"],
        "url": groups["url"],
        "method": groups["method"],
        "status": int(groups["status"]),
        "timestamp": ts,
        "raw_line": line.strip(),
    }


def parse_log_lines(
    raw_output: str,
    *,
    asset_type: str,
    host: str,
    log_path: str,
    asset: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Parse SSH raw lines via config-driven text_log_parser."""
    from text_log_parser import parse_log_lines as config_parse

    if asset is None:
        asset = {"asset_type": asset_type}
    elif "asset_type" not in asset:
        asset = {**asset, "asset_type": asset_type}
    return config_parse(raw_output, asset=asset, host=host, log_path=log_path)


def enrich_ssh_params(asset: dict[str, Any], connector: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """Fill grep_pattern / log_path / max_lines from skill params and connector config."""
    out = dict(params)
    config = connector.get("config") or {}
    constraints = connector.get("constraints") or {}

    if not out.get("grep_pattern"):
        out["grep_pattern"] = out.get("src_ip") or out.get("attacker_ip") or out.get("ip")

    log_paths = config.get("log_paths") or {}
    if not out.get("log_path") and isinstance(log_paths, dict):
        asset_type = asset.get("asset_type", "")
        key_by_type = {
            "ssh_auth": "ssh_auth",
            "web_access_log": "web_access_log",
        }
        key = key_by_type.get(asset_type)
        if key and key in log_paths:
            out["log_path"] = log_paths[key]

    out.setdefault("max_lines", constraints.get("max_lines_per_query", 5000))
    return out


def fetch_ssh_file(
    asset: dict[str, Any],
    connector: dict[str, Any],
    credentials: dict[str, Any],
    ssh_command: str,
    *,
    load_connector: Callable[[str], dict[str, Any]] | None = None,
    resolve_credentials: Callable[[str], dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run validated ssh_command and return parsed events + query meta."""
    meta = validate_ssh_command(ssh_command, connector)
    config = connector.get("config") or {}
    host = config.get("hostname") or config.get("host", "")

    client = connect_ssh(
        connector,
        credentials,
        load_connector=load_connector,
        resolve_credentials=resolve_credentials,
    )
    try:
        raw = execute_ssh_command(client, ssh_command)
    finally:
        client.close()

    events = parse_log_lines(
        raw,
        asset_type=asset.get("asset_type", ""),
        host=host,
        log_path=meta["log_path"],
        asset=asset,
    )
    query_meta = {
        "ssh_command": ssh_command,
        "log_path": meta["log_path"],
        "grep_pattern": meta["grep_pattern"],
        "lines_raw": len(raw.splitlines()),
        "rows_returned": len(events),
    }
    return events, query_meta
