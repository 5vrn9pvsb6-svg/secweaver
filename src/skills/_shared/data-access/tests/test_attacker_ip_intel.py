"""Tests for attacker IP network profile enrichment."""

from __future__ import annotations

import sys
import json
import urllib.error
import unittest
from pathlib import Path
from unittest.mock import patch

DATA_ACCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DATA_ACCESS))

from attacker_ip_intel import (  # noqa: E402
    build_attacker_ip_profile,
    classify_network_attributes,
    collect_geo_from_evidence,
    lookup_ip_online,
)


class AttackerIpIntelTests(unittest.TestCase):
    def test_collect_geo_from_waf_and_web(self) -> None:
        bundles = {
            "waf_alert": [
                {
                    "evidence_id": "waf-1",
                    "src_ip": "115.193.81.185",
                    "country": "中国",
                    "province": "浙江省",
                    "city": "杭州市",
                    "geo_info": "30.28,120.15",
                }
            ],
            "web_access_log": [
                {
                    "evidence_id": "web-1",
                    "remote_addr": "115.193.81.185",
                    "country": "中国",
                    "province": "浙江省",
                    "city": "杭州市",
                }
            ],
        }
        geo = collect_geo_from_evidence("115.193.81.185", bundles)
        self.assertEqual(geo["event_count"], 2)
        self.assertEqual(geo["country"], "中国")
        self.assertEqual(geo["city"], "杭州市")
        self.assertIn("waf-1", geo["evidence_refs"])

    @patch("attacker_ip_intel.urllib.request.urlopen")
    def test_lookup_ip_online_success(self, mock_urlopen) -> None:
        payload = {
            "status": "success",
            "query": "115.193.81.185",
            "country": "China",
            "regionName": "Zhejiang",
            "city": "Hangzhou",
            "isp": "China Mobile",
            "org": "CMCC",
            "as": "AS9808 CMCC",
            "mobile": True,
            "proxy": False,
            "hosting": False,
        }

        class Resp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_urlopen.return_value = Resp()
        result = lookup_ip_online("115.193.81.185", provider="ip-api")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["mobile"])
        self.assertEqual(result["asn"], "AS9808")

    @patch("attacker_ip_intel.urllib.request.urlopen")
    def test_lookup_ip_online_ip_api_failure_keeps_provider(self, mock_urlopen) -> None:
        mock_urlopen.side_effect = urllib.error.URLError("timed out")

        result = lookup_ip_online("115.193.81.185", provider="ip-api")

        self.assertEqual(result["status"], "lookup_failed")
        self.assertEqual(result["provider"], "ip-api.com")
        self.assertIn("timed out", result["error"])

    @patch("attacker_ip_intel.urllib.request.urlopen")
    def test_lookup_ip_online_ipwhois_success(self, mock_urlopen) -> None:
        payload = {
            "success": True,
            "ip": "115.193.81.185",
            "country": "China",
            "region": "Zhejiang",
            "city": "Hangzhou",
            "connection": {
                "asn": 4134,
                "org": "Chinanet",
                "isp": "Chinanet",
                "domain": "chinatelecom.com.cn",
            },
            "security": {
                "anonymous": False,
                "proxy": False,
                "vpn": True,
                "tor": False,
                "hosting": False,
            },
        }

        class Resp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_urlopen.return_value = Resp()
        result = lookup_ip_online("115.193.81.185", provider="ipwhois")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["provider"], "ipwho.is")
        self.assertEqual(result["asn"], "AS4134")
        self.assertEqual(result["isp"], "Chinanet")
        self.assertTrue(result["proxy"])
        self.assertIn("vpn", result["tags"])

    @patch("attacker_ip_intel.urllib.request.urlopen")
    def test_lookup_ip_online_virustotal_success(self, mock_urlopen) -> None:
        payload = {
            "data": {
                "id": "115.193.81.185",
                "attributes": {
                    "country": "CN",
                    "asn": 56041,
                    "as_owner": "China Mobile communications corporation",
                    "network": "115.192.0.0/11",
                    "regional_internet_registry": "APNIC",
                    "reputation": -3,
                    "last_analysis_stats": {
                        "harmless": 71,
                        "malicious": 2,
                        "suspicious": 1,
                        "timeout": 0,
                        "undetected": 21,
                    },
                    "total_votes": {"harmless": 0, "malicious": 1},
                    "tags": ["dynamic-ip"],
                    "last_analysis_date": 1783321200,
                },
            }
        }

        class Resp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_urlopen.return_value = Resp()
        result = lookup_ip_online(
            "115.193.81.185",
            provider="virustotal",
            virustotal_api_key="token",
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["provider"], "virustotal")
        self.assertEqual(result["asn"], "AS56041")
        self.assertEqual(result["as_owner"], "China Mobile communications corporation")
        self.assertEqual(result["network"], "115.192.0.0/11")
        self.assertEqual(result["last_analysis_stats"]["malicious"], 2)
        self.assertEqual(result["total_votes"]["malicious"], 1)

    def test_lookup_ip_online_virustotal_missing_key_tells_user_to_configure(self) -> None:
        with patch.dict("attacker_ip_intel.os.environ", {}, clear=True):
            result = lookup_ip_online(
                "115.193.81.185",
                provider="virustotal",
                config={
                    "enabled": True,
                    "providers": {
                        "virustotal": {
                            "enabled": True,
                        }
                    },
                },
            )

        self.assertEqual(result["status"], "config_missing")
        self.assertEqual(result["provider"], "virustotal")
        self.assertEqual(result["action_required"], "configure_virustotal_api_key")
        self.assertIn("请配置 VirusTotal API Key", result["action_required_label"])
        self.assertIn("VIRUSTOTAL_API_KEY", result["config_hint"])
        self.assertEqual(result["credential_source"], "none")

    @patch("attacker_ip_intel.urllib.request.urlopen")
    @patch("attacker_ip_intel._resolve_credentials_ref")
    def test_lookup_ip_online_virustotal_uses_configured_vault_ref(
        self,
        mock_resolve,
        mock_urlopen,
    ) -> None:
        payload = {
            "data": {
                "id": "115.193.81.185",
                "attributes": {
                    "asn": 56041,
                    "as_owner": "China Mobile communications corporation",
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                },
            }
        }

        class Resp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_resolve.return_value = ({"type": "virustotal", "token": "vault-token"}, None)
        mock_urlopen.return_value = Resp()
        result = lookup_ip_online(
            "115.193.81.185",
            config={
                "enabled": True,
                "default_provider": "virustotal",
                "providers": {
                    "virustotal": {
                        "credentials_ref": "vault://threat-intel/virustotal",
                    }
                },
            },
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["provider"], "virustotal")
        mock_resolve.assert_called_once_with("vault://threat-intel/virustotal")

        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.headers.get("X-apikey"), "vault-token")

    @patch("attacker_ip_intel.urllib.request.urlopen")
    @patch("attacker_ip_intel._resolve_credentials_ref")
    def test_auto_provider_prefers_ipwhois_when_configured_vt_key_missing(
        self,
        mock_resolve,
        mock_urlopen,
    ) -> None:
        payload = {
            "success": True,
            "ip": "115.193.81.185",
            "country": "China",
            "region": "Zhejiang",
            "city": "Hangzhou",
            "connection": {"asn": 4134, "org": "Chinanet", "isp": "Chinanet"},
            "security": {"proxy": False, "vpn": False, "tor": False, "hosting": False},
        }

        class Resp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_resolve.return_value = (None, "secret not found")
        mock_urlopen.return_value = Resp()
        result = lookup_ip_online(
            "115.193.81.185",
            config={
                "enabled": True,
                "default_provider": "auto",
                "providers": {
                    "virustotal": {
                        "credentials_ref": "vault://threat-intel/virustotal",
                    },
                    "ipwhois": {},
                    "ip-api": {},
                },
            },
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["provider"], "ipwho.is")
        self.assertEqual(result["asn"], "AS4134")

    @patch("attacker_ip_intel.urllib.request.urlopen")
    @patch("attacker_ip_intel._resolve_credentials_ref")
    def test_auto_provider_falls_back_to_ip_api_when_ipwhois_fails(
        self,
        mock_resolve,
        mock_urlopen,
    ) -> None:
        ip_api_payload = {
            "status": "success",
            "query": "115.193.81.185",
            "country": "China",
            "regionName": "Zhejiang",
            "city": "Hangzhou",
            "isp": "China Mobile",
            "org": "CMCC",
            "as": "AS9808 CMCC",
        }

        class Resp:
            def __init__(self, payload):
                self.payload = payload

            def read(self):
                return json.dumps(self.payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_resolve.return_value = (None, "secret not found")
        mock_urlopen.side_effect = [
            urllib.error.URLError("ipwhois timeout"),
            Resp(ip_api_payload),
        ]
        result = lookup_ip_online(
            "115.193.81.185",
            config={
                "enabled": True,
                "default_provider": "auto",
                "providers": {
                    "virustotal": {
                        "credentials_ref": "vault://threat-intel/virustotal",
                    },
                    "ipwhois": {},
                    "ip-api": {},
                },
            },
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["provider"], "ip-api.com")
        self.assertEqual(result["asn"], "AS9808")
        self.assertEqual(result["fallback_from"]["provider"], "ipwho.is")

    def test_build_profile_merges_evidence_and_tags(self) -> None:
        bundles = {
            "web_access_log": [
                {
                    "evidence_id": "web-1",
                    "remote_addr": "115.193.81.185",
                    "country": "中国",
                    "province": "浙江省",
                    "city": "杭州市",
                }
            ]
        }
        with patch(
            "attacker_ip_intel.lookup_ip_online",
            return_value={
                "status": "success",
                "isp": "China Mobile",
                "asn": "AS9808",
                "mobile": True,
                "proxy": False,
                "hosting": False,
            },
        ):
            profile = build_attacker_ip_profile("115.193.81.185", bundles, online_lookup=True)
        assert profile is not None
        self.assertEqual(profile["ip"], "115.193.81.185")
        self.assertIn("公网地址", profile["attributes"])
        self.assertTrue(any("ISP" in tag for tag in profile["attributes"]))

    def test_build_profile_adds_virustotal_context_with_ipwhois_primary(self) -> None:
        with (
            patch(
                "attacker_ip_intel.lookup_ip_online",
                return_value={
                    "status": "success",
                    "provider": "ipwho.is",
                    "isp": "Chinanet",
                    "org": "Chinanet-zj Hangzhou Node Network",
                    "asn": "AS4134",
                    "mobile": None,
                    "proxy": None,
                    "hosting": None,
                },
            ),
            patch(
                "attacker_ip_intel._lookup_virustotal",
                return_value={
                    "status": "success",
                    "provider": "virustotal",
                    "query": "115.193.81.185",
                    "asn": "AS4134",
                    "as_owner": "Chinanet",
                    "network": "115.192.0.0/13",
                    "reputation": -1,
                    "last_analysis_stats": {"malicious": 1, "suspicious": 2},
                    "tags": ["scanner"],
                },
            ),
        ):
            profile = build_attacker_ip_profile(
                "115.193.81.185",
                {},
                {"ip_intel_provider": "ipwhois"},
                online_lookup=True,
            )

        assert profile is not None
        self.assertEqual(profile["online_lookup"]["provider"], "ipwho.is")
        vt = profile["threat_intel"]["virustotal"]
        self.assertEqual(vt["provider"], "virustotal")
        self.assertEqual(vt["last_analysis_stats"]["malicious"], 1)
        self.assertIn("情报源: ipwho.is", profile["attributes"])
        self.assertIn("情报源: VirusTotal", profile["attributes"])
        self.assertIn("VT 检测: malicious=1, suspicious=2", profile["attributes"])

    @patch("attacker_ip_intel.urllib.request.urlopen")
    def test_build_profile_with_virustotal_tags(self, mock_urlopen) -> None:
        payload = {
            "data": {
                "id": "115.193.81.185",
                "attributes": {
                    "country": "CN",
                    "asn": 56041,
                    "as_owner": "China Mobile communications corporation",
                    "network": "115.192.0.0/11",
                    "reputation": -3,
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1},
                    "total_votes": {"malicious": 1},
                },
            }
        }

        class Resp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        mock_urlopen.return_value = Resp()
        profile = build_attacker_ip_profile(
            "115.193.81.185",
            {},
            {"ip_intel_provider": "virustotal", "virustotal_api_key": "token"},
            online_lookup=True,
        )
        assert profile is not None
        self.assertIn("情报源: VirusTotal", profile["attributes"])
        self.assertIn("VT 检测: malicious=2, suspicious=1", profile["attributes"])
        self.assertIn("ASN: AS56041", profile["attributes"])
        self.assertIn("组织: China Mobile communications corporation", profile["attributes"])

    def test_opt_out_via_params(self) -> None:
        profile = build_attacker_ip_profile(
            "115.193.81.185",
            {},
            {"resolve_attacker_ip_profile": False},
        )
        self.assertIsNone(profile)

    def test_private_ip_skips_online(self) -> None:
        profile = build_attacker_ip_profile("10.0.0.1", {}, online_lookup=True)
        assert profile is not None
        self.assertEqual(profile["scope"], "private")
        self.assertEqual((profile.get("online_lookup") or {}).get("status"), "private_or_reserved")

    def test_classify_network_attributes(self) -> None:
        tags = classify_network_attributes(
            "115.193.81.185",
            evidence_geo={"country": "中国", "province": "浙江省", "city": "杭州市"},
            online={"status": "success", "mobile": True, "isp": "China Mobile", "asn": "AS9808"},
        )
        self.assertTrue(any("移动网络" in t for t in tags))


if __name__ == "__main__":
    unittest.main()
