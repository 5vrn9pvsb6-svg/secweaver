"""Per-host high-risk exec summaries for traceability reports."""

from __future__ import annotations

import re
from typing import Any

from source_adapters.tigersec_target_impact import _cmd_text, classify_high_risk_exec

CATEGORY_LABEL_ZH: dict[str, str] = {
    "credential_access": "读shadow/passwd",
    "persistence": "账号持久化",
    "defense_evasion": "反取证/清日志",
    "execution": "远程下载执行",
    "command_and_control": "反弹/C2",
    "privilege_escalation": "sudo/提权",
    "discovery": "侦察扫描",
}

CATEGORY_LABEL_EN: dict[str, str] = {
    "credential_access": "shadow/passwd",
    "persistence": "account persistence",
    "defense_evasion": "defense evasion",
    "execution": "download & exec",
    "command_and_control": "C2/reverse shell",
    "privilege_escalation": "sudo/priv esc",
    "discovery": "discovery/scan",
}

# Benign ops noise in lab — skip unless no attack signal on host
_OPS_NOISE = re.compile(
    r"loongcollector|ilogtail|aliyun-observability|grepconf\.sh|unix_chkpwd|sshd -D -R",
    re.I,
)


def _host_from_event(ev: dict[str, Any]) -> str | None:
    for key in ("host_ip", "host", "__source__", "_victim_host"):
        value = ev.get(key)
        if value not in (None, "", "null"):
            text = str(value).strip()
            if text.lower() not in {"localhost", "localhost.localdomain"}:
                return text
    return None


def _attack_snippets(cmd: str, *, zh: bool = True) -> list[str]:
    """Return prioritized human-readable attack summaries (no raw command fallback)."""
    text = cmd or ""
    lower = text.lower()
    out: list[str] = []
    labels = CATEGORY_LABEL_ZH if zh else CATEGORY_LABEL_EN

    def add(label: str) -> None:
        if label and label not in out:
            out.append(label)

    if "s.phtml" in lower or ("uploads" in lower and "curl" in lower):
        add("WebShell(s.phtml)")
    if "sshpass" in lower:
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
        target = m.group(1) if m else None
        if target and not target.startswith("127."):
            add(f"sshpass→{target}")
        elif target:
            add("WebShell内联命令")
        else:
            add("sshpass横向")
    if "/etc/shadow" in lower:
        add(labels["credential_access"])
    if "db-credentials" in lower or "deploy-token" in lower:
        add("窃取凭据文件" if zh else "steal credential files")
    if re.search(r"\buseradd\b|\bchpasswd\b", lower):
        add(labels["persistence"])
    if "nmap" in lower:
        add("nmap内网扫描" if zh else "nmap scan")
    if re.search(r"truncate\s+-s0|history\s+-c", lower) and "log" in lower:
        add(labels["defense_evasion"])
    if re.search(r"rm\s+-f.*\.phtml", lower):
        add("删WebShell" if zh else "remove webshell")

    for cat in classify_high_risk_exec(text):
        add(labels.get(cat, cat))

    return out


def _is_ops_noise(cmd: str) -> bool:
    return bool(_OPS_NOISE.search(cmd or ""))


PRIORITY_ORDER = [
    "WebShell(s.phtml)",
    "WebShell内联命令",
    "sshpass→",
    "sshpass横向",
    "读shadow/passwd",
    "窃取凭据文件",
    "nmap内网扫描",
    "删WebShell",
    "账号持久化",
    "sudo/提权",
    "反取证/清日志",
    "远程下载执行",
    "侦察扫描",
]


def _snippet_priority(snippet: str) -> int:
    for idx, prefix in enumerate(PRIORITY_ORDER):
        if snippet.startswith(prefix) or snippet == prefix:
            return idx
    return len(PRIORITY_ORDER)


def build_host_high_risk_summaries(
    index: dict[str, dict[str, Any]],
    *,
    hosts: list[str] | None = None,
    max_per_host: int = 4,
    zh: bool = True,
) -> dict[str, list[str]]:
    """Map host IP → deduplicated high-risk command summary lines."""
    host_set = {str(h) for h in (hosts or []) if h}
    collected: dict[str, set[str]] = {}

    for ev in index.values():
        if ev.get("_bundle") != "host_exec":
            continue
        host = _host_from_event(ev)
        if not host:
            continue
        if host_set and host not in host_set:
            continue
        cmd = _cmd_text(ev)
        if not cmd or _is_ops_noise(cmd):
            continue
        for snippet in _attack_snippets(cmd, zh=zh):
            collected.setdefault(host, set()).add(snippet)

    per_host: dict[str, list[str]] = {}
    for host, snippets in collected.items():
        ranked = sorted(snippets, key=_snippet_priority)
        per_host[host] = ranked[:max_per_host]
    return per_host


def format_host_node_label(
    host: str,
    base_label: str,
    summaries: list[str] | None,
    *,
    zh: bool = True,
) -> str:
    label = base_label or host
    if not summaries:
        return label.replace('"', "'")
    prefix = "高危" if zh else "risk"
    joined = "; ".join(summaries[:4])
    return f"{label}<br/>{prefix}: {joined}".replace('"', "'")
