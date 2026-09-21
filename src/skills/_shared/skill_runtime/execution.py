"""The only shared owner of invoking canonical Skill assessments."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from . import SKILLS_ROOT
from .contracts import ensure_skill_envelope

MANIFEST_PATH = SKILLS_ROOT / "manifest.json"


def _load_assessment_scripts() -> dict[str, Path]:
    """Load canonical assessment entrypoints from the repository Skill catalog.

    The manifest is the release-facing source of truth for names, aliases and
    visibility. Keep this shared runtime limited to assessment entries so
    fetch, prompt and operational workflows retain their own invocation
    contracts. Fail closed when an assessment is missing a trusted script or
    points outside the repository's source tree.
    """
    catalog = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    scripts: dict[str, Path] = {}
    repository_root = SKILLS_ROOT.parents[1]
    for entry in catalog.get("skills", []):
        if entry.get("kind") != "assessment":
            continue
        key = entry.get("key")
        relative_script = entry.get("script")
        if not isinstance(key, str) or not isinstance(relative_script, str):
            raise RuntimeError("assessment catalog entries require key and script")
        script = (repository_root / relative_script).resolve()
        if repository_root not in script.parents or not script.is_file():
            raise RuntimeError(f"assessment script is not a repository file: {relative_script}")
        scripts[key] = script
    if not scripts:
        raise RuntimeError(f"no assessment scripts declared in {MANIFEST_PATH}")
    return scripts


# Keep the runtime's historical short keys for callers while sourcing paths
# from the same catalog used by the CLI and documentation checks.
SKILL_SCRIPTS = _load_assessment_scripts()


def load_skill_module(name: str, path: Path) -> Any:
    """Load trusted repository code, not a path or module supplied by evidence.

    Reload the entrypoint and assessment catalogs on each invocation; ordinary
    imported dependencies still follow Python's module cache. Register while
    loading for Python introspection; restore a prior module on failure instead
    of leaving a partially initialized module. Callers execute synchronously;
    this loader does not provide concurrent sys.modules mutation isolation.
    """
    scripts = str(path.parent)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def assess_payload(skill: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Assess an already-built payload without CLI output, webhook or report side effects.

    Each Skill remains the authority for its rules, verdicts and optional
    enrichment. Inputs/prechecks are supplied by the caller; this function does
    not fetch evidence or rebuild payloads. Unsupported names fail explicitly.
    """
    if skill not in SKILL_SCRIPTS:
        raise ValueError(f"unsupported Skill: {skill}")
    ensure_skill_envelope(payload, skill)
    module = load_skill_module(f"secweaver_runtime_{skill}", SKILL_SCRIPTS[skill])
    if skill == "completeness":
        result = module.assess(
            payload,
            module.load_scenarios(SKILLS_ROOT / "data-source-completeness/scenarios.json"),
        )
    elif skill == "traceability":
        result = module.analyze(payload, module.load_trace_patterns())
    elif skill == "alert":
        attack = module.load_json(SKILLS_ROOT / "alert-confirmation/attack-types.json")
        fp = module.load_json(SKILLS_ROOT / "alert-confirmation/fp-patterns.json")
        result = module.analyze(payload, attack, fp)
    else:
        result = module.assess(
            payload,
            module.load_scenarios(SKILLS_ROOT / "risk-identification/scenarios.json"),
        )
    constraints = (payload.get("fetch_summary") or {}).get("analysis_constraints")
    if constraints:
        # Keep domain verdicts intact while making the shared evidence boundary
        # visible to API/CLI consumers and any later narrative generation.
        result["analysis_constraints"] = dict(constraints)
    return ensure_skill_envelope(result, skill)


def run_completeness_assess(payload: dict[str, Any]) -> dict[str, Any]:
    """Run the canonical metadata precheck shared by all input adapters."""
    return assess_payload("completeness", payload)
