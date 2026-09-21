#!/usr/bin/env python3
"""SecWeaver traceability analysis command and compatibility exports."""

from __future__ import annotations

import sys

from traceability_analysis.cli import main
from traceability_analysis.common import (
    build_host_ip_map,
    cmd_text,
    event_on_host,
    in_window,
    index_evidence,
    load_json,
    near,
    parse_ts,
)
from traceability_analysis.engine import analyze
from traceability_analysis.execution import dedupe_execution_stages, find_execution_chain
from traceability_analysis.initial_access import (
    _exec_inferred_confidence,
    _initial_access_description,
    d1_reverse_lookup_gap,
    find_initial_access,
    find_initial_access_from_exec,
    find_initial_access_from_victim,
    match_webshell,
    resolve_execution_hosts,
)
from traceability_analysis.lateral import (
    ACCEPTED_SSH,
    FAILED_SSH,
    bfs_lateral,
    find_lateral_from_exec,
    ssh_result,
)
from traceability_analysis.paths import (
    CHAIN_PATTERNS_PATH,
    DATA_ACCESS_PATH,
    LEGACY_PATTERNS_PATH,
    PATTERNS_PATH,
    SCRIPTS_PATH,
)
from traceability_analysis.result import (
    _blocked_result,
    compute_confidence,
    determine_verdict,
    gate_precheck,
    recommended_actions,
    trace_markdown_report,
)

# Compatibility imports that existed in the original single-file module namespace.
from attck_trace import build_trace_mitre_attack, format_mitre_attack_short  # noqa: E402,F401
from correlation_trace import (  # noqa: E402,F401
    attach_join_ids_to_stages,
    build_stages_from_join_edges,
    correlate_for_trace,
    dedupe_lateral_stages,
    matrix_supports_exec,
    matrix_supports_lateral,
    merge_attack_stages,
    merge_initial_access,
    resolve_trace_contract,
)
from heuristic_rules import (  # noqa: E402,F401
    format_template,
    heuristic_time_window_deltas,
    matrix_window_deltas,
    policy_block,
    resolve_verdict_from_policy,
    section,
    ssh_result_from_rules,
)
from host_normalize import (  # noqa: E402,F401
    build_trace_host_ip_map,
    enrich_impacted_with_registry,
    extract_ssh_lateral_targets,
    inject_registered_hosts,
    investigation_host_set,
    is_web_listener_exec,
    merge_registry_host_ips,
    normalize_bundles_for_trace,
    victim_host_from_event,
)
from risk_rules_bridge import load_trace_patterns, resolve_matched_pattern  # noqa: E402,F401
from source_adapters.tigersec import (  # noqa: E402,F401
    exec_session_signals,
    initial_access_inference_note,
    is_non_interactive_exec,
)
from source_adapters.tigersec_syslog import (  # noqa: E402,F401
    find_lateral_confirmations_from_syslog,
    upgrade_suspected_lateral_with_syslog,
)
from source_adapters.tigersec_target_impact import (  # noqa: E402,F401
    find_post_lateral_target_exec_signals,
    impacted_note_for_likely_lateral,
    upgrade_suspected_lateral_with_target_exec,
)
from timeline_source_coverage import build_source_coverage, resolve_timeline_source_types  # noqa: E402,F401
from trace_d1_bootstrap import build_attacker_ip_resolution, victim_field_matches  # noqa: E402,F401


if __name__ == "__main__":
    sys.exit(main())
