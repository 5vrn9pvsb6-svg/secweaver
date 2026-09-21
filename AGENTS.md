# SecWeaver Repository Engineering Rules

These rules apply to the entire repository and are merge requirements.

## Mandatory Code Comments

Code changes must add or update comments at the same time as the implementation. A change is incomplete when its non-obvious behavior is undocumented.

- Add comments to every new or materially changed function whose intent, constraints, or failure behavior is not obvious from its signature and structure.
- Document design intent and the reason behind the implementation, not a line-by-line translation of the code.
- Explicitly comment concurrency and lock ownership, lifecycle transitions, ordering assumptions, bounded-resource behavior, performance tradeoffs, compatibility handling, security boundaries, retries, rollback, and degraded-mode behavior.
- Document exported APIs according to the language's standard conventions.
- Keep comments synchronized with behavior. Update or remove stale comments in the same change that modifies the code.
- Tests do not replace comments for design invariants or operational assumptions.
- Trivial accessors and direct assignments do not need narration. Comments that merely repeat syntax are not considered compliance.

Reviewers must treat missing or misleading comments on non-obvious code as a merge blocker.

## Mandatory Documentation Updates

Every completed code change must create or update the documentation that describes the
changed behavior. Documentation is part of the implementation, not a follow-up task.

- Update the nearest user guide, developer/design document, README, configuration example,
  API contract, or release note affected by the change. Add a new document when no suitable
  document exists.
- Document new defaults, configuration fields, command-line flags, compatibility limits,
  operational procedures, failure and fallback behavior, migration steps, and observable
  log or data-format changes.
- Keep English and Chinese documentation siblings synchronized when both exist. Update
  packaged examples and installation or upgrade instructions when release behavior changes.
- Do not claim a feature is supported until the documentation states its supported platforms,
  prerequisites, limitations, and verification method.
- Before declaring the work complete, search for stale version numbers, configuration examples,
  command snippets, and behavior descriptions; run the repository's documentation checks when
  available and mention any unavailable check in the final report.

Reviewers must treat a code change without its corresponding documentation update as incomplete.

## Mandatory Release Versioning

Agent release versions are immutable identities, not reusable build labels.

- Any source, configuration, packaged documentation, installer, or release-policy change under
  `src/tools/secweaver-agent` must increment its canonical `VERSION` before a new package is built.
- Never publish different bytes under an existing Agent version, even when the previous archive was
  not deployed. Rebuilding the same source and version is allowed only for reproducibility checks.
- Release scripts must reject environment-only version overrides and must not let dirty-build
  overrides bypass the version-bump requirement.
- Operator Bundle and Server versions remain independent, but an Operator that embeds a new Agent
  release must use a new Bundle version instead of overwriting an existing delivery archive.
- Parser/schema versions change only when their data contract changes; they must not be used as the
  Agent package version.

Reviewers must treat release artifacts that reuse a published version for changed content as invalid.
