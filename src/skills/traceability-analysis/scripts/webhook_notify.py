"""Webhook notifications for traceability-analysis reports (DingTalk / Feishu / WeCom)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = SKILL_ROOT / "webhook-config.json"
EXAMPLE_CONFIG_PATH = SKILL_ROOT / "webhook-config.example.json"

SUPPORTED_CHANNEL_TYPES = {"dingtalk", "feishu", "wecom"}


def load_webhook_config(
    *,
    config_path: str | Path | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Resolve webhook config from payload override, explicit path, or default file."""
    payload = payload or {}
    inline = payload.get("notification") or payload.get("webhook")
    if isinstance(inline, dict) and inline.get("channels"):
        return inline

    candidates: list[Path] = []
    if config_path:
        path = Path(config_path)
        if not path.is_absolute():
            path = SKILL_ROOT / path
        candidates.append(path)
    candidates.append(DEFAULT_CONFIG_PATH)

    for path in candidates:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
    return None


def should_notify(result: dict[str, Any], config: dict[str, Any]) -> tuple[bool, str]:
    if not config.get("enabled", True):
        return False, "notification disabled in config"

    if result.get("blocked"):
        notify_on = config.get("notify_on") or []
        if notify_on and "insufficient_evidence" not in notify_on:
            return False, "blocked result and insufficient_evidence not in notify_on"

    verdict = str(result.get("overall_verdict") or "")
    notify_on = config.get("notify_on")
    if notify_on and verdict and verdict not in notify_on:
        return False, f"verdict {verdict} not in notify_on"

    confidence = result.get("confidence")
    if confidence is not None:
        try:
            if float(confidence) < float(config.get("min_confidence") or 0.0):
                return False, "confidence below min_confidence"
        except (TypeError, ValueError):
            pass

    channels = [c for c in (config.get("channels") or []) if c.get("enabled", True)]
    if not channels:
        return False, "no enabled channels"

    return True, ""


def build_notification_text(
    result: dict[str, Any],
    *,
    config: dict[str, Any] | None = None,
    report_output_path: str | Path | None = None,
) -> str:
    config = config or {}
    prefix = str(config.get("title_prefix") or "[SecWeaver 溯源]").strip()
    verdict = result.get("overall_verdict") or "unknown"
    confidence = result.get("confidence")
    summary = str(result.get("summary") or "").strip()

    lines = [
        f"{prefix} 溯源分析报告",
        "",
        f"**判定**: {verdict}",
    ]
    if confidence is not None:
        ceiling = result.get("confidence_ceiling")
        if ceiling is not None and ceiling != confidence:
            lines.append(f"**置信度**: {confidence}（上限 {ceiling}）")
        else:
            lines.append(f"**置信度**: {confidence}")

    initial = result.get("initial_access") or {}
    if initial.get("host"):
        entry = (
            f"{initial.get('host')} @ {initial.get('timestamp') or '-'}"
            f" | {initial.get('vector') or '-'} | {initial.get('url') or '-'}"
        )
        lines.extend(["", f"**入口**: {entry}"])

    impacted = result.get("impacted_assets") or []
    if impacted:
        lines.append("")
        lines.append("**影响范围**:")
        for asset in impacted[:8]:
            host = asset.get("host") or "-"
            role = asset.get("role") or "-"
            priority = asset.get("priority") or "-"
            name = asset.get("name")
            label = f"{host} ({role}, {priority})"
            if name:
                label = f"{name} — {label}"
            lines.append(f"- {label}")

    lateral = result.get("lateral_findings") or {}
    confirmed = len(lateral.get("confirmed") or [])
    likely = len(lateral.get("likely") or [])
    suspected = len(lateral.get("suspected") or [])
    if confirmed or likely or suspected:
        lines.append("")
        lines.append(
            f"**横向**: confirmed={confirmed}, likely={likely}, suspected={suspected}"
        )

    if summary:
        lines.extend(["", f"**摘要**: {summary}"])

    actions = result.get("recommended_actions") or []
    max_actions = int(config.get("max_actions") or 5)
    if actions:
        lines.append("")
        lines.append("**建议处置**:")
        for action in actions[:max_actions]:
            lines.append(f"- {action}")

    mitre = result.get("top_mitre_techniques")
    if mitre:
        lines.extend(["", f"**ATT&CK**: {mitre}"])

    if config.get("include_markdown_excerpt", True):
        excerpt = str(result.get("markdown_report") or "").strip()
        if excerpt:
            excerpt_lines = excerpt.splitlines()[:20]
            lines.extend(["", "---", *excerpt_lines])

    if report_output_path:
        lines.extend(["", f"**完整报告**: `{report_output_path}`"])

    fetch_summary = result.get("fetch_summary") or {}
    tw = fetch_summary.get("time_window") or {}
    if tw.get("time_start") or tw.get("time_end"):
        lines.extend(
            [
                "",
                f"**时间窗**: {tw.get('time_start') or '-'} ~ {tw.get('time_end') or '-'}",
            ]
        )

    return "\n".join(lines)


def _dingtalk_signed_url(webhook_url: str, secret: str) -> str:
    if not secret:
        return webhook_url
    timestamp = str(round(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}"
    sign = urllib.parse.quote_plus(
        base64.b64encode(
            hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")
    )
    sep = "&" if "?" in webhook_url else "?"
    return f"{webhook_url}{sep}timestamp={timestamp}&sign={sign}"


def _feishu_sign_payload(payload: dict[str, Any], secret: str) -> dict[str, Any]:
    if not secret:
        return payload
    timestamp = str(int(time.time()))
    string_to_sign = f"{timestamp}\n{secret}"
    sign = base64.b64encode(
        hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    signed = dict(payload)
    signed["timestamp"] = timestamp
    signed["sign"] = sign
    return signed


def build_channel_payload(channel_type: str, text: str, *, title: str) -> dict[str, Any]:
    channel_type = channel_type.lower()
    if channel_type == "dingtalk":
        return {
            "msgtype": "markdown",
            "markdown": {"title": title, "text": text},
        }
    if channel_type == "feishu":
        return {
            "msg_type": "text",
            "content": {"text": text},
        }
    if channel_type == "wecom":
        return {
            "msgtype": "markdown",
            "markdown": {"content": text},
        }
    raise ValueError(f"unsupported channel type: {channel_type}")


def post_webhook(
    channel: dict[str, Any],
    payload: dict[str, Any],
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    channel_type = str(channel.get("type") or "").lower()
    webhook_url = str(channel.get("webhook_url") or "").strip()
    if channel_type not in SUPPORTED_CHANNEL_TYPES:
        return {"ok": False, "error": f"unsupported type: {channel_type}"}
    if not webhook_url:
        return {"ok": False, "error": "missing webhook_url"}

    secret = str(channel.get("secret") or "")
    body = dict(payload)
    url = webhook_url
    if channel_type == "dingtalk":
        url = _dingtalk_signed_url(webhook_url, secret)
    elif channel_type == "feishu":
        body = _feishu_sign_payload(body, secret)

    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            ok = _response_ok(channel_type, parsed, resp.status)
            return {"ok": ok, "status": resp.status, "response": parsed}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return {"ok": False, "status": exc.code, "response": parsed, "error": str(exc)}
    except urllib.error.URLError as exc:
        return {"ok": False, "error": str(exc.reason)}


def _response_ok(channel_type: str, response: dict[str, Any], http_status: int) -> bool:
    if http_status >= 400:
        return False
    if channel_type == "dingtalk":
        return response.get("errcode") in (0, "0", None) and http_status < 400
    if channel_type == "feishu":
        code = response.get("code")
        status = response.get("StatusCode")
        return (code in (0, None) and status in (0, None)) or response.get("msg") == "success"
    if channel_type == "wecom":
        return response.get("errcode") in (0, "0", None)
    return http_status < 400


def notify_traceability_report(
    result: dict[str, Any],
    config: dict[str, Any],
    *,
    dry_run: bool = False,
    report_output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Send report summary to configured webhook channels."""
    notify, skip_reason = should_notify(result, config)
    meta: dict[str, Any] = {
        "enabled": bool(config.get("enabled", True)),
        "attempted": False,
        "skipped": not notify,
        "skip_reason": skip_reason or None,
        "dry_run": dry_run,
        "channels": [],
    }
    if not notify:
        return meta

    text = build_notification_text(
        result,
        config=config,
        report_output_path=report_output_path,
    )
    title = str(config.get("title_prefix") or "[SecWeaver 溯源]").strip()
    meta["message_preview"] = text[:500]
    meta["attempted"] = True

    for channel in config.get("channels") or []:
        if not channel.get("enabled", True):
            continue
        channel_type = str(channel.get("type") or "").lower()
        name = channel.get("name") or channel_type
        entry: dict[str, Any] = {"name": name, "type": channel_type}
        try:
            payload = build_channel_payload(channel_type, text, title=title)
        except ValueError as exc:
            entry.update({"ok": False, "error": str(exc)})
            meta["channels"].append(entry)
            continue

        if dry_run:
            entry.update({"ok": True, "dry_run": True})
            meta["channels"].append(entry)
            continue

        delivery = post_webhook(channel, payload)
        entry.update(delivery)
        meta["channels"].append(entry)

    meta["ok"] = all(c.get("ok") for c in meta["channels"]) if meta["channels"] else False
    return meta


def maybe_notify_traceability_report(
    result: dict[str, Any],
    *,
    payload: dict[str, Any] | None = None,
    config_path: str | Path | None = None,
    force_notify: bool = False,
    skip_notify: bool = False,
    dry_run: bool = False,
    report_output_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Load config and notify unless explicitly skipped."""
    if skip_notify:
        return {"skipped": True, "skip_reason": "--no-notify"}

    config = load_webhook_config(config_path=config_path, payload=payload)
    if not config:
        if force_notify:
            return {
                "skipped": True,
                "skip_reason": "no webhook config found; copy webhook-config.example.json to webhook-config.json",
            }
        return None

    if force_notify:
        config = {**config, "enabled": True}

    inline = (payload or {}).get("notification") or (payload or {}).get("webhook") or {}
    if inline.get("enabled") is True:
        config = {**config, "enabled": True}
    if inline.get("enabled") is False:
        return {"skipped": True, "skip_reason": "notification.enabled=false in payload"}

    if inline.get("dry_run"):
        dry_run = True

    return notify_traceability_report(
        result,
        config,
        dry_run=dry_run,
        report_output_path=report_output_path,
    )
