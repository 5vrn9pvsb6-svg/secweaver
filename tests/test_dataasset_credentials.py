"""Regression tests for local SOPS executable discovery."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
RESOLVER = REPO_ROOT / "src" / "dataasset" / "credentials" / "resolve.py"


def load_resolver_module():
    spec = importlib.util.spec_from_file_location("dataasset_credential_resolver", RESOLVER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {RESOLVER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestSopsExecutableDiscovery(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = load_resolver_module()

    def test_finds_sops_from_path(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            executable = Path(temp_dir) / "sops"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)

            with patch.dict(os.environ, {"PATH": temp_dir, "SOPS_BIN": ""}, clear=False):
                self.assertEqual(self.resolver.find_executable("sops"), str(executable))

    def test_finds_sops_from_fallback_directory_when_path_is_incomplete(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            executable = Path(temp_dir) / "sops"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)

            with patch.dict(os.environ, {"PATH": "/usr/bin", "SOPS_BIN": ""}, clear=False), patch.object(
                self.resolver,
                "DEFAULT_EXECUTABLE_DIRS",
                (Path(temp_dir),),
            ):
                self.assertEqual(self.resolver.find_executable("sops"), str(executable))

    def test_explicit_sops_bin_has_priority(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            executable = Path(temp_dir) / "custom-sops"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)

            with patch.dict(os.environ, {"PATH": "/usr/bin", "SOPS_BIN": str(executable)}, clear=False):
                self.assertEqual(self.resolver.find_executable("sops"), str(executable))


if __name__ == "__main__":
    unittest.main()
