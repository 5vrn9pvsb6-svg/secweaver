#!/usr/bin/env python3
"""Generate deterministic third-party notices and a CycloneDX source SBOM."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_REQUIREMENTS = REPO_ROOT / "requirements-data-access.txt"
# Keep the public SBOM limited to modules present in the Community archive. The
# Agent Gateway/server is an internal deliverable and is intentionally excluded
# from both the archive and this generated dependency inventory.
GO_MODS = (REPO_ROOT / "src" / "tools" / "secweaver-agent" / "go.mod",)
PROJECT_METADATA = REPO_ROOT / "pyproject.toml"
SBOM_PATH = REPO_ROOT / "sbom" / "secweaver-source.cdx.json"
NOTICES_PATH = REPO_ROOT / "THIRD_PARTY_NOTICES.md"

# Licenses are reviewed metadata rather than guesses made by the generator. Any new
# dependency deliberately fails generation until its upstream license is classified.
LICENSES = {
    "pypi:aliyun-log-python-sdk": "MIT",
    "pypi:jsonschema": "MIT",
    "pypi:paramiko": "LGPL-2.1-or-later",
    "pypi:psycopg": "LGPL-3.0-only",
    "pypi:pymysql": "MIT",
    "golang:github.com/beorn7/perks": "MIT",
    "golang:github.com/cespare/xxhash/v2": "MIT",
    "golang:github.com/cilium/ebpf": "MIT",
    "golang:github.com/prometheus/client_golang": "Apache-2.0",
    "golang:github.com/prometheus/client_model": "Apache-2.0",
    "golang:github.com/prometheus/common": "Apache-2.0",
    "golang:github.com/prometheus/procfs": "Apache-2.0",
    "golang:github.com/lib/pq": "MIT",
    "golang:go.uber.org/goleak": "MIT",
    "golang:golang.org/x/exp": "BSD-3-Clause",
    "golang:golang.org/x/mod": "BSD-3-Clause",
    "golang:golang.org/x/sys": "BSD-3-Clause",
    "golang:google.golang.org/protobuf": "BSD-3-Clause",
}


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str | None
    constraint: str | None
    indirect: bool = False

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name.lower()}"

    @property
    def license_id(self) -> str:
        try:
            return LICENSES[self.key]
        except KeyError as exc:
            raise ValueError(f"license classification missing for {self.key}") from exc

    @property
    def bom_ref(self) -> str:
        base = f"pkg:{self.ecosystem}/{self.name.lower()}"
        return f"{base}@{self.version}" if self.version else base


def project_version() -> str:
    """Read the application identity used as the SBOM root component."""
    match = re.search(r'^version\s*=\s*"([^"]+)"', PROJECT_METADATA.read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise ValueError(f"project version missing from {PROJECT_METADATA}")
    return match.group(1)


def python_dependencies() -> list[Dependency]:
    """Parse only source-declared Python requirements and preserve constraints."""
    dependencies: list[Dependency] = []
    pattern = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[([^]]+)])?\s*(.*)$")
    for raw_line in PYTHON_REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = pattern.match(line)
        if not match:
            raise ValueError(f"unsupported Python requirement: {line}")
        name, extras, constraint = match.groups()
        normalized = name.lower().replace("_", "-")
        suffix = f"; extras={extras}" if extras else ""
        dependencies.append(Dependency("pypi", normalized, None, f"{constraint}{suffix}"))
    return dependencies


def go_dependencies() -> list[Dependency]:
    """Parse direct and indirect modules from every Community Go module."""
    dependencies: list[Dependency] = []
    for go_mod in GO_MODS:
        in_require_block = False
        for raw_line in go_mod.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line == "require (":
                in_require_block = True
                continue
            if in_require_block and line == ")":
                in_require_block = False
                continue
            if not in_require_block or not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                raise ValueError(f"unsupported Go requirement in {go_mod}: {line}")
            dependencies.append(
                Dependency("golang", parts[0], parts[1], None, "// indirect" in line)
            )
    return dependencies


def all_dependencies() -> list[Dependency]:
    """Combine ecosystems in stable order for reproducible generated artifacts."""
    dependencies = python_dependencies() + go_dependencies()
    # Sorting makes both artifacts byte-for-byte reproducible across platforms.
    return sorted(dependencies, key=lambda item: (item.ecosystem, item.name.lower()))


def component(dependency: Dependency) -> dict[str, object]:
    """Convert reviewed dependency metadata into one CycloneDX component."""
    properties = [
        {"name": "secweaver:ecosystem", "value": dependency.ecosystem},
        {
            "name": "secweaver:dependency-scope",
            "value": "indirect" if dependency.indirect else "direct",
        },
    ]
    if dependency.constraint:
        properties.append({"name": "secweaver:version-constraint", "value": dependency.constraint})
    result: dict[str, object] = {
        "bom-ref": dependency.bom_ref,
        "type": "library",
        "name": dependency.name,
        "purl": dependency.bom_ref,
        "licenses": [{"license": {"id": dependency.license_id}}],
        "properties": properties,
    }
    if dependency.version:
        result["version"] = dependency.version
    return result


def render_sbom(dependencies: list[Dependency]) -> str:
    """Render the deterministic CycloneDX 1.6 source inventory."""
    version = project_version()
    root_ref = f"pkg:pypi/secweaver@{version}"
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": "secweaver",
                "version": version,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            "properties": [
                {
                    "name": "secweaver:inventory-completeness",
                    "value": "source-declared-dependencies",
                }
            ],
        },
        "components": [component(dependency) for dependency in dependencies],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [dependency.bom_ref for dependency in dependencies]},
            *({"ref": dependency.bom_ref, "dependsOn": []} for dependency in dependencies),
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_notices(dependencies: list[Dependency]) -> str:
    """Render the human-readable SPDX summary from the same dependency objects."""
    rows = []
    for dependency in dependencies:
        declared = dependency.version or dependency.constraint or "unspecified"
        scope = "indirect" if dependency.indirect else "direct"
        rows.append(
            f"| `{dependency.ecosystem}` | `{dependency.name}` | `{declared}` | `{scope}` | `{dependency.license_id}` |"
        )
    return "\n".join(
        [
            "# Third-Party Notices",
            "",
            "SecWeaver Community is licensed under Apache-2.0. The source tree declares the",
            "third-party dependencies below. Copyright remains with their respective owners.",
            "License identifiers use SPDX syntax; consult each upstream distribution for its",
            "complete license text and notices.",
            "",
            "This inventory is generated from `requirements-data-access.txt`,",
            "`src/tools/secweaver-agent/go.mod`.",
            "Python entries are declared direct dependencies",
            "with version constraints, not a complete environment-specific transitive lock.",
            "The CycloneDX source SBOM records the same limitation explicitly.",
            "",
            "| Ecosystem | Package | Declared version | Scope | SPDX license |",
            "|---|---|---|---|---|",
            *rows,
            "",
        ]
    )


def check_or_write(path: Path, expected: str, *, check: bool) -> bool:
    """Either write an artifact or fail when its committed form is stale."""
    if check:
        actual = path.read_text(encoding="utf-8") if path.is_file() else None
        if actual != expected:
            print(f"ERROR: generated supply-chain artifact is stale: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected, encoding="utf-8")
    print(path.relative_to(REPO_ROOT))
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SecWeaver source dependency notices and SBOM.")
    parser.add_argument("--check", action="store_true", help="Fail when committed artifacts are stale.")
    args = parser.parse_args()

    try:
        dependencies = all_dependencies()
        ok = check_or_write(SBOM_PATH, render_sbom(dependencies), check=args.check)
        ok = check_or_write(NOTICES_PATH, render_notices(dependencies), check=args.check) and ok
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
