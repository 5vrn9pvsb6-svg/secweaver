"""Real loopback TLS regression: reject unknown peers before sending credentials."""

import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/dataasset"))
sys.path.insert(0, str(ROOT / "src/skills/_shared/data-access"))
sys.path.insert(0, str(ROOT / "dataasset-ui"))
from es_fetch import fetch_es
from es_onboarding import ElasticsearchDiscoveryClient, ElasticsearchOnboardingError
from dataasset_ui_services.es_onboarding import probe_customer_es


class ESTLSTransportTests(unittest.TestCase):
    def test_studio_forwards_default_and_explicit_policy(self):
        for values in ({}, {"tls_verify": True}, {"tls_verify": False}, {"tls_verify": "false"}):
            with self.subTest(values=values), patch("dataasset_ui_services.es_onboarding.discover_elasticsearch") as discover:
                probe_customer_es({"endpoint": "https://es.example.com", "ca_file": "ca.pem", **values})
                self.assertIs(discover.call_args.kwargs["tls_verify"], values.get("tls_verify", True))
                self.assertEqual(discover.call_args.kwargs["ca_file"], "ca.pem")

    @unittest.skipUnless(shutil.which("openssl"), "openssl required for ephemeral TLS fixture")
    def test_untrusted_peer_rejected_and_private_ca_accepted(self):
        # Generate a short-lived test key instead of committing private key bytes.
        # The server is loopback-only and always closed, including failed assertions.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, capture_output=True)
            requests = []
            redirect = []

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    """Record only requests that completed the TLS handshake."""
                    requests.append(self.headers.get("Authorization"))
                    if redirect:
                        self.send_response(302)
                        self.send_header("Location", "http://127.0.0.1:9/downgrade")
                        self.end_headers()
                        return
                    body = json.dumps({"version": {"number": "8.0.0"}, "hits": {"total": 0, "hits": []}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def do_POST(self):
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
            credentials = {"type": "es", "username": "test", "password": "synthetic"}
            connector = {"config": {"url": endpoint, "index": "logs-test"}}
            try:
                with self.assertRaises(urllib.error.URLError):
                    fetch_es(connector, credentials, {"size": 10}, {})
                with self.assertRaises(ElasticsearchOnboardingError):
                    ElasticsearchDiscoveryClient(endpoint, credentials).request("GET", "/")
                self.assertEqual(requests, [])
                # CA-only setup must enable verification without needing an extra flag.
                with patch("es_fetch.DATAASSET_ROOT", root):
                    _, meta = fetch_es({"config": {**connector["config"], "ca_file": cert.name}}, credentials, {}, {})
                self.assertTrue(meta["tls_verified"])
                client = ElasticsearchDiscoveryClient(endpoint, credentials, ca_file=cert.name, dataasset_root=root)
                self.assertIn("version", client.request("GET", "/"))
                self.assertEqual(len(requests), 2)
                self.assertTrue(all(item.startswith("Basic ") for item in requests))
                # Explicit diagnostic opt-out remains compatible, never an automatic retry.
                client = ElasticsearchDiscoveryClient(endpoint, credentials, tls_verify=False)
                client.request("GET", "/")
                self.assertEqual(len(requests), 3)
                redirect.append(True)
                with self.assertRaisesRegex(RuntimeError, "redirects are not allowed"):
                    fetch_es({"config": {**connector["config"], "ca_file": str(cert)}}, credentials, {}, {})
                self.assertEqual(len(requests), 4)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
