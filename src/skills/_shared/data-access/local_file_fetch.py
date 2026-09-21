"""Local file connector: read-only grep/tail on host filesystem (no SSH/shell)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ssh_fetch import enrich_ssh_params, validate_ssh_command
from text_log_parser import parse_log_lines

REPO_ROOT = Path(__file__).resolve().parents[4]


def _resolve_base_path(base: str) -> Path:
    path = Path(base)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path.resolve()


def _allowed_paths(connector: dict[str, Any]) -> set[str]:
    config = connector.get("config") or {}
    log_paths = config.get("log_paths") or {}
    allowed: set[str] = set()
    if isinstance(log_paths, dict):
        allowed.update(str(v) for v in log_paths.values())
    elif isinstance(log_paths, list):
        allowed.update(str(v) for v in log_paths)
    allowed.update({"/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/secure"})
    base = (config.get("base_path") or "").strip()
    if base:
        base_path = _resolve_base_path(base)
        resolved: set[str] = set()
        for item in allowed:
            p = Path(item)
            if p.is_absolute():
                resolved.add(str(p.resolve()))
            else:
                resolved.add(str((base_path / p).resolve()))
        return resolved
    return {str(Path(p).resolve()) for p in allowed if p}


def resolve_log_path(connector: dict[str, Any], log_path: str) -> Path:
    """Resolve log_path against base_path and enforce allowlist / traversal guard."""
    config = connector.get("config") or {}
    base = (config.get("base_path") or "").strip()
    path = Path(log_path)
    if not path.is_absolute():
        if not base:
            raise ValueError("relative log_path requires connector config.base_path")
        path = _resolve_base_path(base) / path
    resolved = path.resolve()
    if base:
        base_resolved = _resolve_base_path(base)
        try:
            resolved.relative_to(base_resolved)
        except ValueError as exc:
            raise ValueError(f"log_path escapes base_path: {resolved}") from exc

    allowed = _allowed_paths(connector)
    if allowed and str(resolved) not in allowed:
        raise ValueError(f"log_path not in connector allowlist: {resolved}")

    constraints = connector.get("constraints") or {}
    forbidden = constraints.get("forbidden_paths") or []
    for pattern in forbidden:
        from fnmatch import fnmatch

        if fnmatch(str(resolved), pattern):
            raise ValueError(f"log_path forbidden by connector policy: {resolved}")

    return resolved


def read_grep_tail(
    file_path: Path,
    grep_pattern: str,
    max_lines: int,
    *,
    max_file_size_mb: int | None = None,
) -> str:
    """Filter lines by extended regex (grep -E) and return last max_lines."""
    import re

    if not file_path.is_file():
        raise FileNotFoundError(f"log file not found: {file_path}")

    size_mb = file_path.stat().st_size / (1024 * 1024)
    limit_mb = max_file_size_mb or 100
    if size_mb > limit_mb:
        raise ValueError(f"log file {file_path} exceeds max_file_size_mb={limit_mb} ({size_mb:.1f} MB)")

    pattern = re.compile(grep_pattern)
    matched: list[str] = []
    with file_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if pattern.search(line):
                matched.append(line.rstrip("\n"))
    if max_lines > 0 and len(matched) > max_lines:
        matched = matched[-max_lines:]
    return "\n".join(matched)


def fetch_local_file(
    asset: dict[str, Any],
    connector: dict[str, Any],
    local_file_command: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run validated local_file_command and return parsed events + query meta."""
    meta = validate_ssh_command(local_file_command, connector)
    config = connector.get("config") or {}
    host = config.get("hostname") or config.get("host") or "localhost"
    constraints = connector.get("constraints") or {}

    file_path = resolve_log_path(connector, meta["log_path"])
    max_lines = int(meta["max_lines"])
    raw = read_grep_tail(
        file_path,
        meta["grep_pattern"],
        max_lines,
        max_file_size_mb=int(constraints.get("max_file_size_mb") or 100),
    )

    events = parse_log_lines(
        raw,
        asset=asset,
        host=host,
        log_path=str(file_path),
    )
    query_meta = {
        "local_file_command": local_file_command,
        "log_path": str(file_path),
        "grep_pattern": meta["grep_pattern"],
        "lines_raw": len(raw.splitlines()) if raw else 0,
        "rows_returned": len(events),
    }
    return events, query_meta


enrich_local_file_params = enrich_ssh_params
