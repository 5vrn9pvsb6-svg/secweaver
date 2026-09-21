#!/usr/bin/env python3
"""SecWeaver alert confirmation command and compatibility exports."""

from __future__ import annotations

import sys

from alert_confirmation.cli import main
from alert_confirmation.common import (
    _ts_epoch,
    alert_timestamp,
    attack_success_window,
    cmd_text,
    event_host_keys,
    event_in_investigation_window,
    event_timestamp,
    host_matches_victim,
    in_correlation_window,
    investigation_time_bounds,
    load_json,
    match_patterns,
    parse_ts,
    text_blob,
    victim_host_keys,
)
from alert_confirmation.engine import analyze, confirm_alert
from alert_confirmation.gateway import (
    _block_success_keys,
    _block_success_statuses,
    classify_gateway_miss_reason,
    find_gateway_access_coverage,
    find_gateway_success_hint,
    gateway_hint_recommended_action,
    scan_gateway_misses,
    web_request_has_waf_alert,
)
from alert_confirmation.layer1 import (
    VERDICT_RANK,
    _gateway_miss_severity,
    _layer1_upgrade_config,
    check_fp,
    detect_attack_type,
    infer_attack_type_from_correlated,
    layer1_verdict,
    upgrade_layer1_verdict,
)
from alert_confirmation.paths import ATTACK_TYPES_PATH, DATA_ACCESS_PATH, FP_PATTERNS_PATH
from alert_confirmation.report import batch_summary, count_repeats, markdown_report
from alert_confirmation.success import (
    apply_ip_block_guard,
    build_analyst_questions,
    build_summary,
    compute_confidence,
    confidence_ceiling,
    confirmation_mode,
    effective_confidence_ceiling,
    evaluate_ip_block_guard,
    find_campaign_success,
    find_d2_success,
    has_d2_data,
    layer2_outcome,
    recommended_action,
)
from alert_confirmation.url_match import (
    _alert_path_matches_web,
    _alert_request_method,
    _match_attack_url_patterns,
    _normalize_http_status,
    _same_src_ip,
    _url_text,
    _web_request_method,
    _within_tight_seconds,
    alert_path_query,
    urls_correlate,
    waf_alert_matches_request,
)


if __name__ == "__main__":
    sys.exit(main())
