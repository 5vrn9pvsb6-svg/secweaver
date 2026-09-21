"""Versioned envelope contract shared by deterministic SecWeaver Skills."""

from __future__ import annotations

from typing import Any

SKILL_CONTRACT_VERSION = "1.0"

SKILL_ID_ALIASES = {
    "completeness": "data-source-completeness",
    "data-source-completeness": "data-source-completeness",
    "traceability": "traceability-analysis",
    "traceability-analysis": "traceability-analysis",
    "alert": "alert-confirmation",
    "alert-confirmation": "alert-confirmation",
    "risk": "risk-identification",
    "risk-identification": "risk-identification",
    "fetch": "evidence-fetch",
    "evidence-fetch": "evidence-fetch",
}


class SkillContractError(ValueError):
    """Report an incompatible Skill envelope before fetch or assessment."""


def canonical_skill_id(skill: str) -> str:
    """Resolve runtime aliases to the stable public Skill identifier."""
    canonical = SKILL_ID_ALIASES.get(str(skill or "").strip())
    if not canonical:
        raise SkillContractError(f"unsupported Skill contract id: {skill!r}")
    return canonical


def _validate_mapping_field(envelope: dict[str, Any], field: str) -> None:
    value = envelope.get(field)
    if value is not None and not isinstance(value, dict):
        raise SkillContractError(f"{field} must be a JSON object")


def _validate_evidence_bundles(envelope: dict[str, Any]) -> None:
    """Protect Skill engines from ambiguous or scalar evidence containers."""
    bundles = envelope.get("evidence_bundles")
    if bundles is None:
        return
    if not isinstance(bundles, dict):
        raise SkillContractError("evidence_bundles must be a JSON object")
    for asset_type, events in bundles.items():
        if not isinstance(asset_type, str) or not isinstance(events, list):
            raise SkillContractError("evidence_bundles must map asset types to arrays")
        if any(not isinstance(event, dict) for event in events):
            raise SkillContractError(
                f"evidence_bundles.{asset_type} must contain JSON objects"
            )


def ensure_skill_envelope(envelope: dict[str, Any], skill: str) -> dict[str, Any]:
    """Validate and stamp a backward-compatible Skill input or output envelope.

    Version-less v1 payloads remain accepted so existing examples and callers do
    not require a flag day. An explicit unknown version or conflicting Skill id
    fails before the runtime can silently reinterpret the payload.
    """
    if not isinstance(envelope, dict):
        raise SkillContractError("Skill payload/result must be a JSON object")
    canonical = canonical_skill_id(skill)
    version = envelope.get("contract_version")
    if version not in (None, SKILL_CONTRACT_VERSION):
        raise SkillContractError(
            f"unsupported contract_version={version!r}; expected {SKILL_CONTRACT_VERSION!r}"
        )
    declared_skill = envelope.get("skill")
    if declared_skill is not None and canonical_skill_id(str(declared_skill)) != canonical:
        raise SkillContractError(
            f"payload skill {declared_skill!r} does not match requested Skill {canonical!r}"
        )

    _validate_mapping_field(envelope, "params")
    _validate_mapping_field(envelope, "fetch_summary")
    _validate_mapping_field(envelope, "completeness_precheck")
    _validate_evidence_bundles(envelope)
    envelope["contract_version"] = SKILL_CONTRACT_VERSION
    envelope["skill"] = canonical
    return envelope
