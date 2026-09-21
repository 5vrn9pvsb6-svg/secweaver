"""Shared validation for optional Project selection on the fixed Proxy host."""

import re
from typing import Any

PROJECT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


def proxy_project(config: dict[str, Any]) -> str:
    """Accept a resource identifier, never a host/path or tenant override.

    Empty/absent project preserves the server's default-project compatibility
    route. Explicit projects require server-side project-scoped authorization.
    """
    value = config.get("project", "")
    if not isinstance(value, str) or (value and not PROJECT_NAME.fullmatch(value)):
        raise ValueError("sls_proxy config.project must be a Project name (1-128 letters, digits, _ or -; starts with a letter or digit), or empty")
    return value
