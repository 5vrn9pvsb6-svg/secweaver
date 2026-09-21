"""Full Markdown report for traceability-analysis (SKILL.md template)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from host_risk_summary import (
    CATEGORY_LABEL_EN,
    CATEGORY_LABEL_ZH,
    format_host_node_label,
)
from timeline_source_coverage import (
    build_source_coverage,
    format_source_coverage_cells,
    resolve_timeline_source_types,
    source_labels,
)

VERDICT_LABELS = {
    "confirmed_intrusion_chain": "Confirmed intrusion chain",
    "likely_intrusion_chain": "Likely intrusion chain",
    "initial_access_only": "Initial access only",
    "scanning_or_attempt_only": "Scanning or attempt only",
    "insufficient_evidence": "Insufficient evidence",
}

VERDICT_LABELS_ZH = {
    "confirmed_intrusion_chain": "已确认入侵链",
    "likely_intrusion_chain": "疑似入侵链",
    "initial_access_only": "仅初始入口",
    "scanning_or_attempt_only": "仅扫描/尝试",
    "insufficient_evidence": "证据不足",
}

LATERAL_CLASS_LABELS = {
    "confirmed_lateral": "Confirmed lateral",
    "likely_lateral": "Likely lateral",
    "suspected_lateral": "Suspected lateral",
}

LATERAL_CLASS_LABELS_ZH = {
    "confirmed_lateral": "已确认横向",
    "likely_lateral": "疑似横向",
    "suspected_lateral": "疑似尝试横向",
}

GRAPH_RAW_BEHAVIOR_PATTERNS_ZH = [
    ("db-credentials", "窃取凭据文件"),
    ("deploy-token", "窃取凭据文件"),
    ("/etc/shadow", "读shadow/passwd"),
    ("/etc/passwd", "读shadow/passwd"),
    ("/e??/shado", "读shadow/passwd"),
    ("/e??/passw", "读shadow/passwd"),
    ("sudo -l", "sudo/提权"),
    ("nmap", "侦察扫描"),
]

GRAPH_RAW_BEHAVIOR_PATTERNS_EN = [
    ("db-credentials", "steal credential files"),
    ("deploy-token", "steal credential files"),
    ("/etc/shadow", "shadow/passwd"),
    ("/etc/passwd", "shadow/passwd"),
    ("/e??/shado", "shadow/passwd"),
    ("/e??/passw", "shadow/passwd"),
    ("sudo -l", "sudo/priv esc"),
    ("nmap", "discovery/scan"),
]

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
URL_IN_TEXT = re.compile(r"https?://[^\s]+", re.I)
NBSP = "\u00a0"


def _format_scenarios(scenario: Any) -> str:
    if isinstance(scenario, list):
        return " + ".join(str(item) for item in scenario)
    return str(scenario or "")


def _bullet(label: str, value: Any) -> str:
    if value is None or value == "":
        return ""
    return f"- **{label}**: {value}"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["_(none)_"]
    def cell(value: Any) -> str:
        return str(value).replace("\n", "<br>").replace("|", "\\|")

    lines = [
        "| " + " | ".join(cell(header) for header in headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell(item) for item in row) + " |")
    return lines


def _wide_markdown_cell(value: Any) -> str:
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", "; ")
        .replace("\t", " ")
        .replace("|", "\\|")
        .replace(" ", NBSP)
    )


def _wide_markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["_(none)_"]
    lines = [
        "| " + " | ".join(_wide_markdown_cell(header) for header in headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_wide_markdown_cell(item) for item in row) + " |")
    return lines


def _sanitize_mermaid_id(value: str) -> str:
    out = []
    for ch in str(value):
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    text = "".join(out).strip("_") or "node"
    if text[0].isdigit():
        return f"n_{text}"
    return text


def _escape_mermaid_label(value: Any) -> str:
    return str(value or "").replace('"', "'").replace("\n", "<br/>")


def _attacker_label(result: dict[str, Any], *, zh: bool) -> str:
    initial = result.get("initial_access") or {}
    resolution = result.get("attacker_ip_resolution") or {}
    profile = result.get("attacker_ip_profile") or {}
    return str(
        initial.get("attacker_ip")
        or resolution.get("attacker_ip")
        or profile.get("ip")
        or ("外网攻击者" if zh else "attacker")
    )


def _short_graph_label(value: str, limit: int = 72) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _request_details_from_text(text: Any) -> dict[str, str]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    method = ""
    for part in raw.split():
        candidate = part.strip().upper()
        if candidate in HTTP_METHODS:
            method = candidate
            break
    url = ""
    for part in raw.split():
        cleaned = part.strip().strip(" ,")
        if cleaned.lower().startswith(("http://", "https://")):
            url = cleaned
            break
    if not url:
        match = URL_IN_TEXT.search(raw)
        if match:
            url = match.group(0).strip(" ,")
    if not url:
        return {"method": method} if method else {}
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return {
        "method": method,
        "url": url,
        "gateway": parsed.netloc,
        "path": path,
    }


def _web_request_label(details: dict[str, str], *, prefix: str, fallback: str) -> str:
    method = details.get("method") or ""
    path = details.get("path") or details.get("url") or ""
    packet = " ".join(part for part in (method, path) if part)
    if not packet:
        return fallback
    return _short_graph_label(f"{prefix}{packet}")


def _web_entry_details(result: dict[str, Any], initial: dict[str, Any], *, zh: bool) -> dict[str, str]:
    first: dict[str, str] = {}
    initial_details = _request_details_from_text(initial.get("url"))
    for step in sorted(result.get("timeline") or [], key=lambda item: str(item.get("timestamp") or "")):
        if str(step.get("stage") or "") != "web_attack":
            continue
        raw = step.get("raw_behavior") or step.get("description")
        first = _request_details_from_text(raw)
        if first.get("gateway") or first.get("path") or first.get("method"):
            break
    gateway = first.get("gateway") or initial_details.get("gateway")
    if not gateway:
        return {}
    return {
        "gateway": gateway,
        "first_packet_label": _web_request_label(
            first or initial_details,
            prefix="首包 " if zh else "first ",
            fallback="首个WEB包" if zh else "first web packet",
        ),
        "initial_packet_label": _web_request_label(
            initial_details,
            prefix="命中 " if zh else "hit ",
            fallback="转发/命中" if zh else "forward/hit",
        ),
    }


def _graph_labels(result: dict[str, Any]) -> dict[str, str]:
    graph = result.get("lateral_movement_graph") or {}
    labels = {str(node.get("id") or ""): str(node.get("label") or node.get("id") or "") for node in graph.get("nodes") or []}
    if "attacker" in labels:
        labels["attacker"] = str(labels["attacker"] or "")
    return labels


def _append_unique(items: list[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in items:
        items.append(text)


def _category_graph_label(category: str, *, zh: bool) -> str:
    labels = CATEGORY_LABEL_ZH if zh else CATEGORY_LABEL_EN
    return labels.get(str(category), str(category))


def _timeline_graph_summaries(result: dict[str, Any], host: str, *, zh: bool) -> list[str]:
    patterns = GRAPH_RAW_BEHAVIOR_PATTERNS_ZH if zh else GRAPH_RAW_BEHAVIOR_PATTERNS_EN
    out: list[str] = []
    host_text = str(host or "")
    for step in result.get("timeline") or []:
        raw = str(step.get("raw_behavior") or step.get("description") or "")
        if not raw:
            continue
        if str(step.get("host") or "") != host_text and host_text not in raw:
            continue
        lower = raw.lower()
        if "sshpass" in lower and host_text in raw:
            _append_unique(out, "sshpass横向" if zh else "sshpass lateral")
        for needle, label in patterns:
            if needle.lower() in lower:
                _append_unique(out, label)
        if len(out) >= 4:
            break
    return out


def _node_high_risk_summaries(
    result: dict[str, Any],
    node_id: str,
    base_label: str,
    *,
    zh: bool,
) -> list[str] | None:
    summaries = result.get("host_high_risk_summary") or {}
    direct = summaries.get(node_id) or summaries.get(base_label)
    if direct:
        return list(direct)

    out: list[str] = []
    findings = result.get("lateral_findings") or {}
    for group in ("confirmed", "likely", "suspected"):
        for item in findings.get(group) or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("host") or item.get("target") or "") != str(node_id):
                continue
            summary = item.get("high_risk_summary") or {}
            for category in summary.get("categories") or []:
                _append_unique(out, _category_graph_label(str(category), zh=zh))

    for item in _timeline_graph_summaries(result, node_id, zh=zh):
        _append_unique(out, item)

    return out or None


def _attack_path_edge_label(edge: dict[str, Any], *, zh: bool) -> str:
    stage = str(edge.get("stage") or "")
    if stage == "initial_access":
        return "入口" if zh else "entry"
    if stage == "lateral_movement":
        klass = str(edge.get("class") or "")
        if klass == "confirmed_lateral":
            return "横向" if zh else "lateral"
        if klass == "likely_lateral":
            return "疑似横向" if zh else "likely lateral"
        if klass == "suspected_lateral":
            return "尝试横向" if zh else "attempted lateral"
        return "横向" if zh else "lateral"
    return str(edge.get("protocol") or stage or "")


def _format_graph_node(
    result: dict[str, Any],
    node_id: str,
    *,
    labels: dict[str, str],
    zh: bool,
) -> str:
    if node_id == "attacker":
        return _escape_mermaid_label(_attacker_label(result, zh=zh))
    base = labels.get(node_id, node_id)
    host_summaries = _node_high_risk_summaries(result, node_id, base, zh=zh)
    return _escape_mermaid_label(format_host_node_label(node_id, base, host_summaries, zh=zh))


def _mermaid_attack_path_graph(result: dict[str, Any], *, locale: str = "zh-CN") -> str:
    zh = locale.startswith("zh")
    initial = result.get("initial_access") or {}
    graph = result.get("lateral_movement_graph") or {}
    labels = _graph_labels(result)
    nodes: set[str] = {str(node.get("id") or "") for node in graph.get("nodes") or [] if node.get("id")}
    edges: list[tuple[str, str, str]] = []
    edge_index: dict[tuple[str, str], int] = {}

    def edge_label_priority(label: str) -> int:
        text = str(label or "").lower()
        if text in {"entry", "入口"}:
            return 5
        if "likely" in text or "疑似" in text:
            return 4
        if "attempt" in text or "尝试" in text or "suspected" in text:
            return 3
        if "lateral" in text or "横向" in text:
            return 2
        return 1

    def add_edge(src: Any, dst: Any, label: str) -> None:
        src_text = str(src or "").strip()
        dst_text = str(dst or "").strip()
        if not src_text or not dst_text or src_text == dst_text:
            return
        pair = (src_text, dst_text)
        previous_idx = edge_index.get(pair)
        if previous_idx is not None:
            old = edges[previous_idx]
            if edge_label_priority(label) > edge_label_priority(old[2]):
                edges[previous_idx] = (src_text, dst_text, label)
            return
        edge_index[pair] = len(edges)
        nodes.update({src_text, dst_text})
        edges.append((src_text, dst_text, label))

    initial_host = str(initial.get("target_ip") or initial.get("host") or "").strip()
    attacker = _attacker_label(result, zh=zh)
    web_entry = _web_entry_details(result, initial, zh=zh)
    if initial_host:
        labels.setdefault("attacker", attacker)
        if web_entry:
            gateway_node = str(
                initial.get("gateway_host") or web_entry.get("gateway") or "waf_gateway"
            ).strip()
            labels.setdefault(
                gateway_node,
                f"{'WAF网关' if zh else 'WAF/Gateway'}<br/>{web_entry.get('gateway')}",
            )
            add_edge(
                "attacker",
                gateway_node,
                web_entry.get("first_packet_label") or ("首个WEB包" if zh else "first web packet"),
            )
            add_edge(
                gateway_node,
                initial_host,
                web_entry.get("initial_packet_label") or ("转发/命中" if zh else "forward/hit"),
            )
        else:
            add_edge("attacker", initial_host, "入口" if zh else "entry")

    for edge in graph.get("edges") or []:
        if web_entry and str(edge.get("stage") or "") == "initial_access":
            dst = str(edge.get("to") or "")
            src = str(edge.get("from") or "")
            if src == "attacker" and dst == initial_host:
                continue
        label = _attack_path_edge_label(edge, zh=zh)
        add_edge(edge.get("from"), edge.get("to"), label)

    for stage in result.get("attack_chain") or []:
        if stage.get("stage") != "lateral_movement":
            continue
        src = stage.get("source_host") or initial_host
        dst = stage.get("host")
        add_edge(src, dst, "横向" if zh else "lateral")

    findings = result.get("lateral_findings") or {}
    for group in ("confirmed", "likely", "suspected"):
        for item in findings.get(group) or []:
            if not isinstance(item, dict):
                continue
            src = item.get("source_host") or item.get("source") or initial_host
            dst = item.get("host") or item.get("target")
            add_edge(src, dst, "横向" if zh else "lateral")

    for asset in result.get("impacted_assets") or []:
        host = str(asset.get("host") or "").strip()
        if host:
            nodes.add(host)

    if not nodes and not edges:
        return ""

    lines = ["```mermaid", "graph LR"]
    for node_id in sorted(nodes):
        if not node_id:
            continue
        nid = _sanitize_mermaid_id(node_id)
        lines.append(f'  {nid}["{_format_graph_node(result, node_id, labels=labels, zh=zh)}"]')
    for src, dst, label in edges:
        src_id = _sanitize_mermaid_id(src)
        dst_id = _sanitize_mermaid_id(dst)
        if label:
            lines.append(f"  {src_id} -->|{_escape_mermaid_label(label)}| {dst_id}")
        else:
            lines.append(f"  {src_id} --> {dst_id}")
    lines.append("```")
    return "\n".join(lines)


def _attack_path_graph_section(result: dict[str, Any], *, locale: str) -> list[str]:
    graph = _mermaid_attack_path_graph(result, locale=locale)
    if not graph:
        return []
    title = "### 攻击路径图" if locale.startswith("zh") else "### Attack path graph"
    return ["", title, "", graph]


def _select_timeline_steps(steps: list[dict[str, Any]], *, max_rows: int = 50) -> tuple[list[dict[str, Any]], int]:
    if not steps:
        return [], 0
    total = len(steps)
    priority = {
        "initial_access",
        "lateral_movement",
        "persistence",
        "exfiltration",
        "collection",
        "command_and_control",
        "reconnaissance",
    }
    selected: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    ordered = sorted(steps, key=lambda item: str(item.get("timestamp") or ""))
    for step in ordered:
        desc = str(step.get("description") or "")
        key = (
            step.get("timestamp"),
            step.get("stage"),
            step.get("host"),
            desc[:100],
        )
        if key in seen:
            continue
        seen.add(key)
        stage = str(step.get("stage") or "")
        if stage in priority or len(selected) < max_rows:
            selected.append(step)

    if len(selected) > max_rows:
        selected = selected[:max_rows]
    return selected, total


def _timeline_raw_behavior(step: dict[str, Any], evidence_index: dict[str, Any]) -> str:
    raw = str(step.get("raw_behavior") or "").strip()
    if raw:
        return raw
    values: list[str] = []
    for ref in step.get("evidence_refs") or []:
        ev = evidence_index.get(str(ref)) or {}
        candidate = str(ev.get("raw_behavior") or "").strip()
        if candidate and candidate not in values:
            values.append(candidate)
        if len(values) >= 2:
            break
    return " | ".join(values)


def _short_text(value: Any, limit: int = 96) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _url_path_from_text(value: Any) -> str:
    details = _request_details_from_text(value)
    return details.get("path") or details.get("url") or ""


def _timeline_description(step: dict[str, Any], evidence_index: dict[str, Any]) -> str:
    stage = str(step.get("stage") or "")
    desc = str(step.get("description") or "").strip()
    raw = _timeline_raw_behavior(step, evidence_index)
    text = raw or desc
    lower = text.lower()

    if stage == "web_attack":
        details = _request_details_from_text(text)
        method = details.get("method")
        path = details.get("path") or _url_path_from_text(desc)
        parts = ["WEB请求"]
        if method:
            parts.append(method)
        if path:
            parts.append(_short_text(path, 72))
        status = re.search(r"\bstatus=(\d{3})\b", text)
        action = re.search(r"\baction=([\w-]+)", text)
        rule = re.search(r"\brule=([^\s|]+)", text)
        if status:
            parts.append(f"status={status.group(1)}")
        if action:
            parts.append(f"action={action.group(1)}")
        if rule:
            parts.append(f"rule={rule.group(1)}")
        return " ".join(parts) if len(parts) > 1 else _short_text(desc, 96)

    if stage == "initial_access":
        path = _url_path_from_text(text)
        if path:
            vector = step.get("vector") or "webshell"
            return _short_text(f"初始入口命中 {path}（{vector}）", 96)
        return _short_text(desc, 96)

    if stage == "lateral_movement":
        attempt = step.get("attempt_timestamp")
        confirmed = step.get("confirmed_timestamp")
        if attempt and confirmed:
            return _short_text(f"SSH 横向尝试 {attempt}；登录确认 {confirmed}", 120)
        if confirmed:
            return _short_text(f"SSH 横向登录确认 {confirmed}", 120)
        return _short_text(desc or text, 96)

    if stage == "execution":
        if "mysqldump" in lower:
            return "导出数据库表到临时文件"
        if "select * from payment_cards" in lower:
            return "查询 payment_cards 表"
        if "select * from users" in lower:
            return "查询 users 表"
        if "show databases" in lower:
            return "数据库枚举"
        if "curl" in lower and "192.0.2.92:8443/drop" in lower:
            return "curl POST 疑似外传到 192.0.2.92:8443/drop"
        if "curl" in lower and "192.0.2.92:8443/dns/" in lower:
            return "curl 分片请求到 192.0.2.92:8443/dns/*"
        if "cat /etc/passwd" in lower or "cat /e??/passw" in lower:
            return "读取 passwd 账号文件"
        if "cat /etc/shadow" in lower or "cat /e??/shado" in lower:
            return "读取 shadow 凭据文件"
        if "find /var/www" in lower and "password" in lower:
            return "搜索 Web 目录密码字段"
        if "ss -tlnp" in lower or "netstat" in lower or "nmap" in lower:
            return "网络/端口侦察"
        if "uname -a" in lower or re.search(r"\bid\b", lower):
            return "身份与系统侦察"
        if "rm -f" in lower or "sed -i" in lower:
            return "清理文件或 WebShell 痕迹"
        if "ping -c" in lower and "date" in lower:
            return "命令执行探测/心跳"

    if stage == "persistence":
        if "authorized_keys" in lower:
            return "SSH authorized_keys 持久化变更"
        if "/etc/systemd/system" in lower or "systemd" in lower:
            return "systemd 服务持久化变更"
        if "/etc/cron" in lower or "/var/spool/cron" in lower or "crontab" in lower:
            return "cron 计划任务持久化变更"
        if "/etc/sudoers" in lower:
            return "sudoers 权限持久化变更"
        if "ld.so.preload" in lower:
            return "ld.so.preload 持久化/绕过变更"
        return _short_text(desc or text, 96)

    if desc:
        compact = re.sub(r"执行命令:\s*\[.*", "执行命令", desc)
        return _short_text(compact, 96)
    return _short_text(text, 96)


def _mermaid_lateral_graph(result: dict[str, Any], *, locale: str = "zh-CN") -> str:
    graph = result.get("lateral_movement_graph") or {}
    nodes = graph.get("nodes") or []
    edges = [
        edge
        for edge in (graph.get("edges") or [])
        if str(edge.get("stage") or "") == "lateral_movement" or str(edge.get("from") or "") != "attacker"
    ]
    if not edges and not nodes:
        return ""
    if not edges:
        return ""

    zh = locale.startswith("zh")
    labels = {str(node.get("id") or ""): str(node.get("label") or node.get("id") or "") for node in nodes}
    host_ids = set(labels) | {str(a.get("host") or "") for a in (result.get("impacted_assets") or [])}

    lines = ["```mermaid", "graph LR"]
    rendered_nodes: set[str] = set()

    def emit_node(node_id: str) -> None:
        if node_id in rendered_nodes:
            return
        rendered_nodes.add(node_id)
        nid = _sanitize_mermaid_id(node_id)
        base = labels.get(node_id, node_id)
        if node_id == "attacker":
            base = base or ("外网攻击者" if zh else "attacker")
            lines.append(f'  {nid}["{_escape_mermaid_label(base)}"]')
            return
        host_summaries = _node_high_risk_summaries(result, node_id, base, zh=zh)
        text = format_host_node_label(node_id, base, host_summaries, zh=zh)
        lines.append(f'  {nid}["{_escape_mermaid_label(text)}"]')

    seen_edges: set[tuple[str, str]] = set()
    for edge in edges:
        src = str(edge.get("from") or "")
        dst = str(edge.get("to") or "")
        if not src or not dst:
            continue
        key = (src, dst)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        emit_node(src)
        emit_node(dst)
        src_id = _sanitize_mermaid_id(src)
        dst_id = _sanitize_mermaid_id(dst)
        lines.append(f"  {src_id} --> {dst_id}")

    for host in sorted(host_ids):
        if host and host not in rendered_nodes and host != "attacker":
            emit_node(host)

    lines.append("```")
    return "\n".join(lines)


def _lateral_list_section(result: dict[str, Any], *, locale: str) -> list[str]:
    findings = result.get("lateral_findings") or {}
    zh = locale.startswith("zh")
    class_labels = LATERAL_CLASS_LABELS_ZH if zh else LATERAL_CLASS_LABELS
    title = "### 横向移动" if zh else "### Lateral movement"
    lines: list[str] = ["", title, ""]

    mermaid = _mermaid_lateral_graph(result, locale=locale)
    if mermaid:
        lines.extend([mermaid, ""])

    groups = [
        ("confirmed", class_labels["confirmed_lateral"]),
        ("likely", class_labels["likely_lateral"]),
        ("suspected", class_labels["suspected_lateral"]),
    ]
    has_any = False
    for key, label in groups:
        items = findings.get(key) or []
        if not items:
            continue
        has_any = True
        lines.append(f"**{label}:**")
        for item in items:
            if isinstance(item, dict):
                host = item.get("host") or item.get("target") or "-"
                desc = item.get("description") or item.get("text") or item.get("reason") or ""
                attempt = item.get("attempt_timestamp")
                confirmed = item.get("confirmed_timestamp")
                if attempt or confirmed:
                    time_parts = []
                    if attempt:
                        time_parts.append(f"首次尝试 {attempt}" if zh else f"first attempt {attempt}")
                    if confirmed:
                        time_parts.append(f"登录确认 {confirmed}" if zh else f"login confirmed {confirmed}")
                    prefix = f"{'；'.join(time_parts)} | "
                else:
                    ts = item.get("timestamp") or ""
                    prefix = f"{ts} | " if ts else ""
                lines.append(f"- {prefix}{host}: {desc}".rstrip(": "))
            else:
                lines.append(f"- {item}")
        lines.append("")

    if not has_any and not mermaid:
        lines.append("- _(none)_")
    return lines


def _mitre_section(result: dict[str, Any], *, locale: str) -> list[str]:
    mitre = result.get("mitre_attack") or {}
    by_stage = result.get("mitre_attack_by_stage") or []
    zh = locale.startswith("zh")
    title = "### MITRE ATT&CK" if not zh else "### MITRE ATT&CK"
    lines = ["", title, ""]

    techniques = result.get("top_mitre_techniques") or ", ".join(mitre.get("technique_ids") or [])
    tactics = ", ".join(mitre.get("tactic_ids") or [])
    tech_label = "技术" if zh else "Techniques"
    tac_label = "战术" if zh else "Tactics"
    lines.append(_bullet(tech_label, techniques))
    lines.append(_bullet(tac_label, tactics))

    if by_stage:
        stage_label = "按阶段" if zh else "By stage"
        deduped_rows = []
        seen_stage: set[tuple[str, str]] = set()
        for row in by_stage:
            stage = str(row.get("stage") or "")
            mitre_id = str(row.get("mitre_id") or "")
            name = str(row.get("name") or "")
            if not mitre_id and not name:
                continue
            key = (stage, mitre_id)
            if key in seen_stage:
                continue
            seen_stage.add(key)
            deduped_rows.append([stage, mitre_id, name])
        if deduped_rows:
            lines.extend(["", f"**{stage_label}:**", ""])
            headers = ["阶段", "ID", "名称"] if zh else ["Stage", "ID", "Name"]
            lines.extend(_table(headers, deduped_rows))

    return [line for line in lines if line != ""]


def _fetch_summary_section(result: dict[str, Any], *, locale: str) -> list[str]:
    summary = result.get("fetch_summary")
    if not summary:
        return []
    try:
        from fetch_summary import format_fetch_summary_markdown  # noqa: WPS433
    except ImportError:
        return []
    title = "### 证据取数" if locale.startswith("zh") else "### Evidence fetch"
    return ["", title, "", format_fetch_summary_markdown(summary), ""]


def render_traceability_report(result: dict[str, Any], *, locale: str = "en") -> str:
    """Render full traceability report per SKILL.md / SKILL.zh-CN.md template."""
    zh = locale.startswith("zh")
    verdict = str(result.get("overall_verdict") or "unknown")
    verdict_label = (VERDICT_LABELS_ZH if zh else VERDICT_LABELS).get(verdict, verdict)
    confidence = result.get("confidence")
    ceiling = result.get("confidence_ceiling")
    initial = result.get("initial_access") or {}
    primary_refs = list(initial.get("primary_evidence_refs") or initial.get("evidence_refs") or [])
    supporting_refs = list(initial.get("supporting_evidence_refs") or [])
    supporting_preview = ", ".join(supporting_refs[:8])
    if len(supporting_refs) > 8:
        supporting_preview += f" … ({len(supporting_refs)} total)"

    if zh:
        lines = [
            "## 溯源分析报告",
            "",
            f"**场景**：{_format_scenarios(result.get('scenario'))}",
            f"**结论**：{verdict_label}（置信度 {confidence}，上限 {ceiling}）",
            "",
            "### 攻击叙事",
            "",
            str(result.get("summary") or "_(无)_"),
        ]
        initial_title = "### 初始入口（第一个攻破点）"
        initial_fields = [
            _bullet("主机", initial.get("host")),
            _bullet("时间", initial.get("timestamp")),
            _bullet("URL", initial.get("url")),
            _bullet("向量", initial.get("vector")),
            _bullet("入口角色", initial.get("entry_point_role")),
            _bullet("攻破点状态", initial.get("first_compromise_point_status")),
            _bullet("最早观测控制页面", initial.get("first_observed_control_url") or "—"),
            _bullet("攻击源 IP", initial.get("attacker_ip")),
            _bullet("主证据", ", ".join(primary_refs)),
            _bullet("补充证据", supporting_preview or "—"),
        ]
        timeline_title = "### 攻击时间线"
        timeline_base_headers = ["时间", "阶段", "主机", "描述", "ATT&CK", "证据"]
        impact_title = "### 影响范围"
        impact_headers = ["主机", "角色", "优先级", "备注"]
        actions_title = "### 处置建议"
        gaps_title = "### 数据缺口影响"
        hypotheses_title = "### 未解答问题 / 假设"
    else:
        lines = [
            "## Traceability Analysis Report",
            "",
            f"**Scenario**: {_format_scenarios(result.get('scenario'))}",
            f"**Verdict**: {verdict_label} (confidence {confidence}, ceiling {ceiling})",
            "",
            "### Attack narrative",
            "",
            str(result.get("summary") or "_(none)_"),
        ]
        initial_title = "### Initial entry (first breach point)"
        initial_fields = [
            _bullet("Host", initial.get("host")),
            _bullet("Time", initial.get("timestamp")),
            _bullet("URL", initial.get("url")),
            _bullet("Vector", initial.get("vector")),
            _bullet("Entry role", initial.get("entry_point_role")),
            _bullet("Compromise point status", initial.get("first_compromise_point_status")),
            _bullet("First observed control URL", initial.get("first_observed_control_url") or "—"),
            _bullet("Attacker IP", initial.get("attacker_ip")),
            _bullet("Primary evidence", ", ".join(primary_refs)),
            _bullet("Supporting evidence", supporting_preview or "—"),
        ]
        timeline_title = "### Attack timeline"
        timeline_base_headers = ["Time", "Stage", "Host", "Description", "ATT&CK", "Evidence"]
        impact_title = "### Impact scope"
        impact_headers = ["Host", "Role", "Priority", "Notes"]
        actions_title = "### Recommended actions"
        gaps_title = "### Data gap impact"
        hypotheses_title = "### Open questions / hypotheses"

    lines.extend(["", initial_title, ""])
    lines.extend(field for field in initial_fields if field)

    profile = result.get("attacker_ip_profile") or {}
    if profile:
        ip_profile_title = "### 攻击源 IP 属性" if zh else "### Attacker IP profile"
        lines.extend(["", ip_profile_title, ""])
        lines.append(_bullet("IP", profile.get("ip")))
        lines.append(_bullet("范围" if zh else "Scope", profile.get("scope")))
        if profile.get("summary"):
            label = "属性摘要" if zh else "Summary"
            lines.append(_bullet(label, profile.get("summary")))
        ev = profile.get("evidence_geo") or {}
        if ev.get("event_count"):
            geo_label = "日志地理" if zh else "Evidence geo"
            geo_val = " / ".join(x for x in (ev.get("country"), ev.get("province"), ev.get("city")) if x)
            lines.append(_bullet(geo_label, geo_val))
            refs = ev.get("evidence_refs") or []
            if refs:
                ref_label = "证据" if zh else "Evidence"
                lines.append(_bullet(ref_label, ", ".join(str(r) for r in refs[:5])))
        online = profile.get("online_lookup") or {}
        if online.get("status") == "success":
            provider = online.get("provider")
            if provider:
                provider_label = "情报源" if zh else "Intel source"
                source = "VirusTotal" if provider == "virustotal" else provider
                lines.append(_bullet(provider_label, source))
            if online.get("provider") == "virustotal":
                stats = online.get("last_analysis_stats") or {}
                malicious = int(stats.get("malicious") or 0)
                suspicious = int(stats.get("suspicious") or 0)
                if stats:
                    label = "VT 检测" if zh else "VT detections"
                    lines.append(_bullet(label, f"malicious={malicious}, suspicious={suspicious}"))
                if online.get("reputation") not in (None, ""):
                    lines.append(_bullet("VT reputation", online.get("reputation")))
                owner = online.get("as_owner")
                if owner:
                    owner_label = "组织" if zh else "Owner"
                    lines.append(_bullet(owner_label, owner))
                if online.get("network"):
                    network_label = "网络段" if zh else "Network"
                    lines.append(_bullet(network_label, online.get("network")))
            lines.append(_bullet("ISP", online.get("isp")))
            lines.append(_bullet("ASN", online.get("asn") or online.get("as")))
            flags = []
            if online.get("mobile"):
                flags.append("移动网络" if zh else "mobile")
            if online.get("hosting"):
                flags.append("数据中心" if zh else "hosting")
            if online.get("proxy"):
                flags.append("代理/VPN" if zh else "proxy")
            if flags:
                flag_label = "网络类型" if zh else "Network type"
                lines.append(_bullet(flag_label, ", ".join(flags)))

    lines.extend(_attack_path_graph_section(result, locale=locale))

    timeline_source = result.get("timeline") or result.get("attack_chain") or []
    timeline_steps, timeline_total = _select_timeline_steps(list(timeline_source))
    source_types = result.get("timeline_source_types") or resolve_timeline_source_types(result)
    evidence_index = result.get("evidence_index") or {}
    timeline_headers = list(timeline_base_headers)
    if source_types:
        timeline_headers.extend(source_labels(source_types, zh=zh))
    timeline_rows = []
    for step in timeline_steps:
        refs = step.get("evidence_refs") or []
        coverage = step.get("source_coverage")
        if not isinstance(coverage, dict):
            coverage = build_source_coverage(refs, evidence_index, source_types)
        row = [
            str(step.get("timestamp") or ""),
            str(step.get("stage") or ""),
            str(step.get("host") or ""),
            _timeline_description(step, evidence_index),
            str(step.get("mitre_id") or ""),
            ", ".join(str(ref) for ref in refs),
        ]
        if source_types:
            row.extend(format_source_coverage_cells(coverage, source_types))
        timeline_rows.append(row)
    lines.extend(["", timeline_title, ""])
    lines.append(
        "> 攻击时间线为 Markdown 表格宽表；详细 URL/命令保留在 JSON 的 timeline[].raw_behavior，可按证据 ID 复核。"
        if zh
        else "> The attack timeline is a wide Markdown table; detailed URLs/commands remain in JSON timeline[].raw_behavior and can be reviewed by evidence ID."
    )
    if source_types:
        legend = (
            "> 数据源列：✓ = 该阶段在此数据源有对应证据；✗ = 无。"
            if zh
            else "> Source columns: ✓ = evidence present in that source; ✗ = not visible."
        )
        lines.append(legend)
    lines.extend(_wide_markdown_table(timeline_headers, timeline_rows))
    if timeline_total > len(timeline_steps):
        note = (
            f"\n> 共 {timeline_total} 条链路段落，报告展示 {len(timeline_steps)} 条（已去重/截断）。"
            if zh
            else f"\n> {timeline_total} chain stages total; showing {len(timeline_steps)} deduplicated entries."
        )
        lines.append(note)

    lines.extend(_mitre_section(result, locale=locale))
    lines.extend(_lateral_list_section(result, locale=locale))

    impact_rows = []
    for asset in result.get("impacted_assets") or []:
        impact_rows.append(
            [
                str(asset.get("host") or ""),
                str(asset.get("role") or ""),
                str(asset.get("priority") or ""),
                str(asset.get("note") or asset.get("name") or ""),
            ]
        )
    lines.extend(["", impact_title, ""])
    lines.extend(_table(impact_headers, impact_rows))

    actions = result.get("recommended_actions") or []
    if actions:
        lines.extend(["", actions_title, ""])
        for idx, action in enumerate(actions, start=1):
            lines.append(f"{idx}. {action}")

    gaps = result.get("data_gaps_impact") or []
    if gaps:
        lines.extend(["", gaps_title, ""])
        for gap in gaps:
            lines.append(f"- {gap}")

    hypotheses = result.get("hypotheses") or []
    if hypotheses:
        lines.extend(["", hypotheses_title, ""])
        for item in hypotheses:
            if isinstance(item, dict):
                text = item.get("text") or item.get("hypothesis") or str(item)
                conf = item.get("confidence")
                suffix = f" (confidence {conf})" if conf is not None else ""
                lines.append(f"- {text}{suffix}")
            else:
                lines.append(f"- {item}")

    lines.extend(_fetch_summary_section(result, locale=locale))

    if result.get("blocked"):
        reason = result.get("block_reason") or ""
        label = "**阻断原因**" if zh else "**Blocked reason**"
        lines.extend(["", label, reason])

    matched = result.get("matched_pattern")
    if matched:
        label = "匹配模式" if zh else "Matched pattern"
        lines.extend(["", _bullet(label, matched)])

    return "\n".join(line for line in lines if line is not None).rstrip() + "\n"
