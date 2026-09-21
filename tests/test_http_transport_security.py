"""Security regressions for credential-bearing connector HTTP transport."""

from __future__ import annotations

import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DATA_ACCESS = ROOT / "src" / "skills" / "_shared" / "data-access"
sys.path.insert(0, str(DATA_ACCESS))

from http_fetch import fetch_http_api  # noqa: E402
from http_transport import NoRedirect, ssl_context, validate_secure_endpoint  # noqa: E402
from splunk_fetch import fetch as fetch_splunk  # noqa: E402


class HttpTransportSecurityTests(unittest.TestCase):
    def test_remote_http_is_rejected_before_network_access(self) -> None:
        with patch("http_transport.urllib.request.build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "must use HTTPS"):
                fetch_http_api(
                    {"config": {"base_url": "http://api.example.com"}},
                    {"type": "http_api", "token": "synthetic"},
                    {"method": "GET", "path": "/events"},
                    {},
                )
            with self.assertRaisesRegex(ValueError, "must use HTTPS"):
                fetch_splunk(
                    {"config": {"base_url": "http://splunk.example.com", "index": "security"}},
                    {"token": "synthetic"},
                    "src_ip=203.0.113.10",
                    {},
                )
            opener.assert_not_called()

    def test_only_explicit_loopback_http_is_allowed(self) -> None:
        for url in (
            "http://localhost:8788/fetch",
            "http://127.0.0.1:8788/fetch",
            "http://[::1]:8788/fetch",
            "https://api.example.com",
        ):
            with self.subTest(url=url):
                self.assertEqual(validate_secure_endpoint(url), url)
        for url in (
            "http://api.example.com",
            "http://localhost.:8788/fetch",
            "http://user:secret@localhost:8788/fetch",
            "ftp://localhost/events",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_secure_endpoint(url)

    def test_redirect_handler_rejects_same_origin_and_downgrade(self) -> None:
        request = urllib.request.Request("https://api.example.com/events")
        handler = NoRedirect()
        for target in (
            "https://api.example.com/v2/events",
            "https://other.example.com/events",
            "http://api.example.com/events",
        ):
            with self.subTest(target=target), self.assertRaisesRegex(RuntimeError, "redirects are not allowed"):
                handler.redirect_request(request, None, 302, "Found", {}, target)

    def test_tls_verification_flags_cannot_disable_live_fetch(self) -> None:
        with patch("http_transport.urllib.request.build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "tls_verify=false is not allowed"):
                fetch_http_api(
                    {"config": {"base_url": "https://api.example.com", "tls_verify": False}},
                    {},
                    {"method": "GET", "path": "/events"},
                    {},
                )
            with self.assertRaisesRegex(ValueError, "verify_tls=false is not allowed"):
                fetch_splunk(
                    {
                        "config": {
                            "base_url": "https://splunk.example.com:8089",
                            "index": "security",
                            "verify_tls": False,
                        }
                    },
                    {},
                    "src_ip=203.0.113.10",
                    {},
                )
            opener.assert_not_called()

    def test_relative_ca_file_cannot_escape_dataasset_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "dataasset"
            root.mkdir()
            outside = parent / "outside.pem"
            outside.write_text("synthetic", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must stay inside DATAASSET_ROOT"):
                ssl_context(
                    {"ca_file": "../outside.pem"},
                    "https://api.example.com",
                    dataasset_root=root,
                )
            link = root / "linked.pem"
            link.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "must stay inside DATAASSET_ROOT"):
                ssl_context(
                    {"ca_file": "linked.pem"},
                    "https://api.example.com",
                    dataasset_root=root,
                )


if __name__ == "__main__":
    unittest.main()
