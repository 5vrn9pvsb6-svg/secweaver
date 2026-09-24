"""Keep public entry guides aligned with executable offline and query contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def documented_json(path: Path) -> list[dict]:
    """Validate the actual fenced examples, not a separate copy that can drift.

    These guides use standalone JSON fences. Parse their bodies with the JSON
    parser so invalid syntax fails before Schema and cross-reference checks.
    """
    return [json.loads(body) for body in re.findall(
        r"^```json\s*\n(.*?)^```\s*$", path.read_text(), re.MULTILINE | re.DOTALL,
    )]


def run_public_command(*args: str) -> dict:
    """Force the sanitized registry; these tests must never resolve live secrets.

    Callers use an explicit sample or --dry-run. Captured output stays inside the
    test so a failure does not accidentally print private terminal environment.
    """
    result = subprocess.run(
        [sys.executable, *args], cwd=ROOT,
        env={**os.environ, "DATAASSET_ROOT": str(ROOT / "dataasset")},
        text=True, capture_output=True, timeout=30, check=True,
    )
    return json.loads(result.stdout)


class PublicOnboardingDocsTests(unittest.TestCase):
    def test_runtime_configuration_files_match_their_schemas(self):
        pairs = (
            ("query-templates/templates.json", "query-templates.schema.json"),
            ("configure/connector-catalog.json", "connector-catalog.schema.json"),
            ("configure/external-connectors.json", "external-connectors.schema.json"),
        )
        for config_name, schema_name in pairs:
            with self.subTest(config=config_name):
                document = json.loads((ROOT / "dataasset" / config_name).read_text())
                schema = json.loads((ROOT / "dataasset/schema" / schema_name).read_text())
                Draft202012Validator(schema).validate(document)

        profile_schema = json.loads(
            (ROOT / "dataasset/schema/connector-onboarding-profile.schema.json").read_text()
        )
        manifests = [
            json.loads((ROOT / "dataasset/configure/connector-catalog.json").read_text()),
            json.loads((ROOT / "dataasset/configure/external-connectors.json").read_text()),
        ]
        for manifest in manifests:
            for connector_type, spec in manifest["connectors"].items():
                with self.subTest(profile=connector_type):
                    Draft202012Validator(profile_schema).validate(spec["onboarding_profile"])

    def test_public_sls_placeholders_are_not_active(self):
        for path in (ROOT / "dataasset/connectors").glob("*.json"):
            connector = json.loads(path.read_text())
            if (connector.get("config") or {}).get("project") == "YOUR_SLS_PROJECT":
                with self.subTest(connector=connector["connector_id"]):
                    self.assertEqual(connector["status"], "draft")

    def test_source_guide_examples_match_schema_and_each_other(self):
        """Both translations must ship valid, identical machine-readable examples."""
        schemas = {
            key: json.loads((ROOT / "dataasset/schema" / filename).read_text())
            for key, filename in (("asset_id", "data-asset.schema.json"),
                                  ("connector_id", "data-connector.schema.json"))
        }
        examples = []
        templates = json.loads((ROOT / "dataasset/query-templates/templates.json").read_text())["templates"]
        for suffix in (".md", ".zh-CN.md"):
            objects = documented_json(ROOT / "docs_user" / ("03-configure-data-sources" + suffix))
            self.assertEqual(len(objects), 3)
            connectors = {obj["connector_id"]: obj for obj in objects if "asset_id" not in obj}
            for obj in objects:
                key = "asset_id" if "asset_id" in obj else "connector_id"
                with self.subTest(language=suffix, object=obj[key]):
                    Draft202012Validator(schemas[key]).validate(obj)
                    self.assertEqual(obj["status"], "draft")
                    if key == "asset_id":
                        connector = connectors[obj["connector_id"]]
                        for template_id in obj["query_template_ids"]:
                            template = templates[template_id]
                            self.assertIn(connector["connector_type"], template["connector_types"])
                            self.assertIn(obj["asset_type"], template["asset_types"])
                        self.assertEqual(obj["field_aliases"]["client_ip"], "src_ip")
                        self.assertEqual(obj["field_aliases"]["request_uri"], "url")
            examples.append(objects)
        self.assertEqual(*examples)

    def test_documented_sls_and_es_query_previews_resolve(self):
        for asset_id in ("asset-waf-prod-01", "asset-es-waf-prod"):
            result = run_public_command(
                "src/dataasset/test_connector.py", asset_id, "--by-asset", "--dry-run",
                "--params", json.dumps({"src_ip": "203.0.113.10", "limit": 10,
                                        "time_start": "2026-09-08T00:00:00Z",
                                        "time_end": "2026-09-08T00:05:00Z"}),
            )
            self.assertEqual(result["query_meta"]["mode"], "dry_run")
            self.assertEqual(result["events"], [])

    def test_agent_es_example_generates_draft_verified_tls_objects(self):
        """Inspect generated overrides: deep merging must not retain a WAF IP filter.

        Explicit dry-run and the sanitized registry prevent writes and credential
        access; the configuration file is the same artifact linked by both guides.
        """
        result = run_public_command(
            "src/secweaver.py", "asset", "apply", "-f",
            "src/tools/secweaver-agent/elasticsearch/dataasset-source.example.json", "--dry-run",
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "dry-run")
        source, = result["sources"]
        for kind in ("connector", "asset"):
            obj = source[kind]["data"]
            schema = json.loads((ROOT / f"dataasset/schema/data-{kind}.schema.json").read_text())
            Draft202012Validator(schema).validate(obj)
            self.assertEqual(obj["status"], "draft")
        self.assertIs(source["connector"]["data"]["config"]["tls_verify"], True)
        self.assertEqual(source["connector"]["data"]["config"]["index"], "secweaver-public-agent-exec-*")
        template = source["template"]["data"]
        self.assertEqual(template["params"], ["time_start", "time_end", "limit"])
        self.assertEqual(template["es_query"]["query"], {
            "bool": {"must": [{"range": {"@timestamp": {
                "gte": "{time_start}", "lte": "{time_end}",
            }}}]},
        })

    def test_real_onboarding_guides_select_private_root(self):
        for suffix in (".md", ".zh-CN.md"):
            for base in ("dataasset/README", "dataasset/credentials/README",
                         "src/tools/secweaver-agent/elasticsearch/README",
                         "docs_user/03-configure-data-sources", "docs_user/30-sls-proxy-onboarding"):
                text = (ROOT / (base + suffix)).read_text()
                self.assertIn("export DATAASSET_ROOT=dataasset_my", text)
                self.assertNotRegex(text, r"(?m)^DATAASSET_ROOT=dataasset\s+.*sops-vault")

    def test_generated_agent_es_source_can_preview_queries_without_credentials(self):
        """Exercise generation and retrieval together in a disposable public copy.

        No real overlay is read or changed. Retrieval stays dry-run, so this verifies
        parameter rendering and registry references without a live ES or Vault.
        """
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "dataasset"
            shutil.copytree(ROOT / "dataasset", registry,
                            ignore=shutil.ignore_patterns("secrets", ".age", "__pycache__"))
            env = {**os.environ, "DATAASSET_ROOT": str(registry)}
            generated = subprocess.run(
                [sys.executable, "src/secweaver.py", "asset", "apply", "-f",
                 "src/tools/secweaver-agent/elasticsearch/dataasset-source.example.json"],
                cwd=ROOT, env=env, text=True, capture_output=True, timeout=30, check=True,
            )
            self.assertTrue(json.loads(generated.stdout)["ok"])
            result = subprocess.run(
                [sys.executable, "src/dataasset/test_connector.py", "asset-local-agent-exec",
                 "--by-asset", "--dry-run", "--params",
                 json.dumps({"time_start": "2026-09-08T00:00:00Z",
                             "time_end": "2026-09-08T00:05:00Z", "limit": 10})],
                cwd=ROOT, env=env, text=True, capture_output=True, timeout=30, check=True,
            )
            preview = json.loads(result.stdout)
            self.assertEqual(preview["template_id"], "local_agent_exec_by_time")
            self.assertEqual(preview["query_meta"]["mode"], "dry_run")
            self.assertEqual(preview["events"], [])
            self.assertNotIn("{src_ip}", result.stdout)
            self.assertNotIn("{time_start}", result.stdout)

    def test_root_readmes_disclose_client_limits_and_output_locations(self):
        for suffix in (".md", ".zh-CN.md"):
            text = (ROOT / ("README" + suffix)).read_text()
            self.assertIn("POSIX", text)
            self.assertIn("WSL2", text)
            self.assertIn("wsl --install", text)
            self.assertIn("wsl --set-version Ubuntu 2", text)
            self.assertNotIn("quickstart.ps1", text)
            self.assertNotIn(r".venv\Scripts\python.exe", text)
            self.assertIn("`outputs/ai-showcase/`", text)
            self.assertIn("`examples/reports/`", text)
            self.assertIn("DATAASSET_ROOT", text)

    def test_quickstart_keeps_optional_onboarding_after_first_result(self):
        for suffix in (".md", ".zh-CN.md"):
            text = (ROOT / "docs_user" / ("00-security-operator-quickstart" + suffix)).read_text()
            self.assertIn("make quickstart", text)
            self.assertIn("wsl --install", text)
            self.assertIn("wsl --set-version Ubuntu 2", text)
            self.assertNotIn("quickstart.ps1", text)
            self.assertNotIn(r".venv\Scripts\python.exe", text)
            self.assertIn("outputs/ai-showcase/webshell-to-ssh-lateral.json", text)
            self.assertNotIn("python3 src/", text)
            self.assertNotIn("asset apply", text)

    def test_wsl_client_support_and_agent_boundary_stay_explicit(self):
        """Keep WSL onboarding usable without presenting it as a Windows sensor."""
        for suffix in (".md", ".zh-CN.md"):
            paths = (
                ROOT / ("README" + suffix),
                ROOT / "docs_user" / ("00-security-operator-quickstart" + suffix),
                ROOT / "docs_dev" / ("01-new-contributor-quickstart" + suffix),
                ROOT / "docs_user" / ("30-sls-proxy-onboarding" + suffix),
                ROOT / "src/tools/secweaver-agent" / ("README" + suffix),
            )
            texts = [path.read_text() for path in paths]
            for path, text in zip(paths, texts):
                with self.subTest(language=suffix, path=path.relative_to(ROOT)):
                    self.assertIn("WSL2", text)

            combined = "\n".join(texts)
            self.assertIn("make quickstart", combined)
            self.assertIn(".venv/bin/python", combined)
            self.assertIn("wsl --install", combined)
            self.assertIn("wsl --set-version Ubuntu 2", combined)
            self.assertIn("Security 4688", combined)
            self.assertIn("Sysmon", combined)
            self.assertIn("Ubuntu", combined)

            client_text = "\n".join(texts[:-1])
            self.assertNotIn("quickstart.ps1", client_text)
            self.assertNotIn(r".venv\Scripts\python.exe", client_text)

    def test_guide_case_ids_resolve_to_the_expected_skill(self):
        catalog = json.loads((ROOT / "examples/ai-showcase/cases.json").read_text())
        by_case = {item["case_id"]: item for item in catalog["cases"]}
        for number, name in (("15", "data-source-completeness"), ("17", "alert-confirmation"),
                             ("18", "traceability-analysis"), ("19", "risk-identification")):
            for suffix in (".md", ".zh-CN.md"):
                text = (ROOT / "docs_user" / f"{number}-{name}{suffix}").read_text()
                cases = re.findall(r"make ai-showcase CASE=([a-z0-9-]+)", text)
                self.assertTrue(cases)
                for case_id in cases:
                    self.assertEqual(by_case[case_id]["skill"], name)
                self.assertNotIn("brain Page", text)
                self.assertNotIn("brain 第", text)

    def test_saas_dry_run_matches_documented_output(self):
        result = run_public_command(
            "src/dataasset/test_connector.py", "conn-sls-proxy-demo", "--dry-run",
            "--params", json.dumps({"time_start": "2026-09-07T00:00:00Z",
                                    "time_end": "2026-09-07T00:05:00Z", "limit": 10}),
        )
        self.assertEqual(result["connector_type"], "sls_proxy")
        self.assertEqual(result["template_id"], "host_exec_by_time")
        self.assertEqual(result["query_meta"]["mode"], "dry_run")
        self.assertEqual(result["events"], [])
        self.assertEqual(result["credentials_ref"], "vault://sls/sls-proxy-query")

    def test_discovery_preview_is_read_only_and_matches_guide(self):
        asset = ROOT / "dataasset/assets/asset-waf-api-prod.json"
        before = asset.read_bytes()
        result = run_public_command(
            "src/secweaver.py", "asset", "discover-format", "asset-waf-api-prod",
            "-i", "examples/log-format-discovery/waf-jsonl.sample",
        )
        self.assertEqual(result["detected_format"], "json_lines")
        self.assertEqual(result["sample_count"], 2)
        self.assertIn("normalized_preview", result)
        self.assertEqual(before, asset.read_bytes())

    def test_lab_guide_uses_unified_agent_and_preserves_evidence(self):
        text = (ROOT / "attack_test/environmentDeployment/README.md").read_text()
        self.assertIn("systemctl start secweaver-agent", text)
        self.assertIn("/opt/secweaver-agent/logs", text)
        self.assertNotIn("systemctl start audit-port-execmon", text)
        self.assertNotIn("truncate -s0", text)
        self.assertIn("umask 077", text)
        for path in (ROOT / "attack_test/environmentDeployment").glob("case*/README.md"):
            self.assertNotIn("/var/log/audit-port-execmon.log", path.read_text())
            self.assertNotIn("/var/log/syslog-risk-json.log", path.read_text())

    def test_saas_client_guide_does_not_require_private_platform_setup(self):
        for suffix in (".md", ".zh-CN.md"):
            text = (ROOT / "docs_user" / ("30-sls-proxy-onboarding" + suffix)).read_text()
            self.assertIn("sops-vault.sh edit vault://sls/sls-proxy-query", text)
            self.assertIn("--dry-run", text)
            self.assertIn("--params", text)
            self.assertNotIn("SLS_PROXY_MASTER_KEY", text)
            self.assertNotIn("server.sls_proxy", text)


if __name__ == "__main__":
    unittest.main()
