"""Tests for traceability-analysis webhook notifications."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from webhook_notify import (  # noqa: E402
    build_channel_payload,
    build_notification_text,
    load_webhook_config,
    maybe_notify_traceability_report,
    notify_traceability_report,
    should_notify,
)


SAMPLE_RESULT = {
    "overall_verdict": "confirmed_intrusion_chain",
    "confidence": 0.86,
    "confidence_ceiling": 0.88,
    "summary": "Attacker hit web-01 via WebShell; lateral to db-01.",
    "initial_access": {
        "host": "192.0.2.91",
        "timestamp": "2026-07-01T16:46:36+08:00",
        "vector": "webshell",
        "url": "/uploads/s.phtml",
    },
    "impacted_assets": [
        {"host": "192.0.2.91", "role": "initial_compromise", "priority": "P0", "name": "web-91"},
        {"host": "192.0.2.92", "role": "lateral_target", "priority": "P0"},
    ],
    "lateral_findings": {"confirmed": [], "likely": [{"host": "192.0.2.92"}], "suspected": []},
    "recommended_actions": ["Isolate 192.0.2.91", "Reset devops password"],
    "top_mitre_techniques": "T1190; T1505.003; T1021.004",
    "markdown_report": "# Traceability Analysis Report\n\n- **Verdict**: confirmed",
    "fetch_summary": {
        "time_window": {
            "time_start": "2026-07-01T14:00:00+08:00",
            "time_end": "2026-07-01T19:00:00+08:00",
        }
    },
}


class WebhookNotifyTests(unittest.TestCase):
    def test_build_notification_text_contains_key_fields(self):
        text = build_notification_text(
            SAMPLE_RESULT,
            config={"title_prefix": "[Test]"},
            report_output_path="/tmp/report.json",
        )
        self.assertIn("[Test]", text)
        self.assertIn("confirmed_intrusion_chain", text)
        self.assertIn("192.0.2.91", text)
        self.assertIn("Isolate 192.0.2.91", text)
        self.assertIn("/tmp/report.json", text)

    def test_should_notify_respects_verdict_filter(self):
        config = {
            "enabled": True,
            "notify_on": ["likely_intrusion_chain"],
            "channels": [{"type": "wecom", "enabled": True, "webhook_url": "http://x"}],
        }
        ok, reason = should_notify(SAMPLE_RESULT, config)
        self.assertFalse(ok)
        self.assertIn("notify_on", reason)

    def test_build_channel_payload_formats(self):
        ding = build_channel_payload("dingtalk", "hello", title="t")
        self.assertEqual(ding["msgtype"], "markdown")
        feishu = build_channel_payload("feishu", "hello", title="t")
        self.assertEqual(feishu["msg_type"], "text")
        wecom = build_channel_payload("wecom", "hello", title="t")
        self.assertEqual(wecom["msgtype"], "markdown")

    def test_notify_dry_run(self):
        config = {
            "enabled": True,
            "channels": [
                {
                    "type": "wecom",
                    "enabled": True,
                    "name": "test",
                    "webhook_url": "https://example.com/hook",
                }
            ],
        }
        meta = notify_traceability_report(SAMPLE_RESULT, config, dry_run=True)
        self.assertTrue(meta["attempted"])
        self.assertTrue(meta["ok"])
        self.assertTrue(meta["channels"][0]["dry_run"])

    @patch("webhook_notify.urllib.request.urlopen")
    def test_post_wecom_success(self, mock_urlopen):
        from webhook_notify import post_webhook

        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b'{"errcode":0,"errmsg":"ok"}'
        resp.__enter__.return_value = resp
        mock_urlopen.return_value = resp

        result = post_webhook(
            {"type": "wecom", "webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x"},
            {"msgtype": "markdown", "markdown": {"content": "hi"}},
        )
        self.assertTrue(result["ok"])

    def test_load_config_from_payload_inline(self):
        payload = {
            "notification": {
                "enabled": True,
                "channels": [{"type": "feishu", "webhook_url": "https://x", "enabled": True}],
            }
        }
        cfg = load_webhook_config(payload=payload)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg["channels"][0]["type"], "feishu")

    def test_maybe_notify_skipped_with_no_notify(self):
        meta = maybe_notify_traceability_report(SAMPLE_RESULT, skip_notify=True)
        self.assertTrue(meta["skipped"])


if __name__ == "__main__":
    unittest.main()
