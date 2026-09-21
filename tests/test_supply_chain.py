"""Regression tests for deterministic source supply-chain artifacts."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = REPO_ROOT / "src" / "scripts" / "generate_supply_chain.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_supply_chain", GENERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {GENERATOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestSupplyChainArtifacts(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = load_generator()

    def test_every_declared_dependency_has_reviewed_license_metadata(self) -> None:
        dependencies = self.generator.all_dependencies()
        self.assertTrue(dependencies)
        self.assertTrue(all(dependency.license_id for dependency in dependencies))

    def test_committed_artifacts_match_dependency_declarations(self) -> None:
        dependencies = self.generator.all_dependencies()
        self.assertEqual(
            self.generator.SBOM_PATH.read_text(encoding="utf-8"),
            self.generator.render_sbom(dependencies),
        )
        self.assertEqual(
            self.generator.NOTICES_PATH.read_text(encoding="utf-8"),
            self.generator.render_notices(dependencies),
        )


if __name__ == "__main__":
    unittest.main()
