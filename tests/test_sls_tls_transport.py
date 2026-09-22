"""Exercise Proxy probes and signed SDK queries against an ephemeral TLS peer."""

import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/skills/_shared/data-access"))
from sls_proxy_fetch import _endpoint_available, fetch
from sls_tls import tls_policy


class SLSTLSTransportTests(unittest.TestCase):
    def test_trust_configuration_rejects_missing_ca_and_ambiguous_flags(self):
        with tempfile.TemporaryDirectory() as directory, patch("sls_tls.DATAASSET_ROOT", Path(directory)):
            with self.assertRaises(FileNotFoundError):
                tls_policy({"ca_file": "missing.pem"})
            with self.assertRaisesRegex(ValueError, "requires"):
                tls_policy({"ca_file": "missing.pem", "tls_verify": False})
            for value in (None, 0, 1, "false", "true", []):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    tls_policy({"tls_verify": value})
        self.assertIs(tls_policy({}), True)
        self.assertIs(tls_policy({"tls_verify": False}), False)

    def test_tls_policy_defers_annotation_evaluation_for_direct_imports(self):
        """Keep the shared helper importable before any Skill code executes.

        Direct Skill-script imports must not evaluate PEP 604 annotations while the
        module loads; older launch environments otherwise fail before TLS policy
        validation can report a useful configuration error.
        """
        self.assertEqual(tls_policy.__annotations__["return"], "bool | str")

    @unittest.skipUnless(shutil.which("openssl"), "openssl required for ephemeral TLS fixture")
    def test_probe_and_real_sdk_enforce_same_trust_policy(self):
        # Generate disposable key material outside the repository. Loopback
        # requests contain synthetic credentials only; always close the server.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, capture_output=True)
            requests = []

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    """Record completed handshakes; return a minimal SLS logs response."""
                    requests.append((self.path, bool(self.headers.get("Authorization"))))
                    body = b'{"meta":{"progress":"Complete","count":0},"data":[]}' if self.command == "POST" else b"[]"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Content-Type", "application/json")
                    self.send_header("x-log-count", "0")
                    self.send_header("x-log-progress", "Complete")
                    self.end_headers()
                    self.wfile.write(body)

                def do_POST(self):
                    """SDK v2 uses POST; consume its body before the same TLS assertion."""
                    self.rfile.read(int(self.headers.get("Content-Length", 0)))
                    self.do_GET()

                def log_message(self, *_args):
                    pass

            server = HTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            endpoint = f"https://127.0.0.1:{server.server_port}"
            credentials = {"type": "aliyun_ram", "access_key_id": "SWAK_TEST", "access_key_secret": "synthetic"}
            config = {"endpoint": endpoint, "project": "test-project", "logstore": "events"}
            params = {"time_start": "2026-09-17T00:00:00+08:00", "time_end": "2026-09-17T00:01:00+08:00", "limit": 1}
            try:
                with self.assertRaises(Exception) as failure:
                    fetch({}, {"connector_type": "sls_proxy", "config": config}, credentials, "*", params)
                self.assertIn("certificate", str(failure.exception).lower())
                self.assertEqual(requests, [])
                with self.assertRaises(Exception):
                    _endpoint_available(endpoint, tls_verify=True, timeout=2)
                self.assertEqual(requests, [])
                # Relative CA paths are rooted at DATAASSET_ROOT for both paths.
                with patch("sls_tls.DATAASSET_ROOT", root):
                    policy = tls_policy({"ca_file": cert.name})
                    self.assertTrue(_endpoint_available(endpoint, tls_verify=policy, timeout=2))
                    events, _ = fetch({}, {"connector_type": "sls_proxy", "config": {**config, "ca_file": cert.name}}, credentials, "*", params)
                self.assertEqual(events, [])
                self.assertEqual(len(requests), 2)
                self.assertFalse(requests[0][1])
                self.assertTrue(requests[1][1])
                self.assertIn("project=test-project", requests[1][0])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
