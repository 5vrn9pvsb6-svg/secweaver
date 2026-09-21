"""数据源 → 可识别风险映射与缺口提醒。"""

from __future__ import annotations

from typing import Any

# evidence_bundles 键 → 元数据
DATA_SOURCES: dict[str, dict[str, Any]] = {
    "host_exec": {
        "label": "进程命令执行",
        "asset_type": "host_exec",
        "module": "exec",
        "required_for_modules": ["exec"],
        "description": "对外监听进程及其子进程的命令执行事件（audit-port-execmon 等）",
    },
    "host_connect": {
        "label": "进程主动外连",
        "asset_type": "host_connect",
        "module": "connect",
        "required_for_modules": ["connect"],
        "description": "对外监听进程发起的主动 TCP/UDP 连接事件",
    },
    "host_file_op": {
        "label": "进程文件操作",
        "asset_type": "host_file_op",
        "module": None,
        "required_for_modules": [],
        "auxiliary_for_modules": ["exec"],
        "description": "监听进程上下文内的文件读写/创建/删除（辅助 exec 上下文加权与攻击链）",
    },
    "host_persistence": {
        "label": "主机持久化变更",
        "asset_type": "host_persistence",
        "module": "persistence",
        "required_for_modules": ["persistence"],
        "description": "cron、systemd、authorized_keys、sudoers、profile、内核模块等持久化位置变更",
    },
    "host_process": {
        "label": "主机进程快照",
        "asset_type": "host_process",
        "module": None,
        "required_for_modules": [],
        "auxiliary_for_modules": ["exec", "connect", "persistence"],
        "description": "每 10 分钟采集的全量当前进程，用于补充进程存活、父子关系、用户和资源占用上下文",
    },
    "host_socket": {
        "label": "主机监听端口快照", "asset_type": "host_socket", "module": None,
        "required_for_modules": [], "auxiliary_for_modules": ["exec", "connect"],
        "description": "每分钟监听端口快照，用于确认异常服务暴露和进程归属",
    },
    "host_identity": {
        "label": "主机登录与身份变化", "asset_type": "host_identity", "module": None,
        "required_for_modules": [], "auxiliary_for_modules": ["exec", "persistence", "ssh"],
        "description": "账户属性变化和登录会话开始/结束，用于身份影响面确认",
    },
    "host_service": {
        "label": "主机服务与计划任务变化", "asset_type": "host_service", "module": None,
        "required_for_modules": [], "auxiliary_for_modules": ["exec", "persistence"],
        "description": "服务、timer、cron 和计划任务基线及变化",
    },
    "host_kernel_context": {
        "label": "主机内核与容器上下文", "asset_type": "host_kernel_context", "module": None,
        "required_for_modules": [], "auxiliary_for_modules": ["exec", "connect", "persistence"],
        "description": "内核模块、驱动、命名空间、cgroup 容器和容器运行时上下文",
    },
    "waf_alert": {
        "label": "WAF 告警",
        "asset_type": "waf_alert",
        "module": None,
        "required_for_modules": [],
        "auxiliary_for_modules": ["exec", "connect"],
        "description": "WAF 命中告警（用于主机风险与 WAF 互证建议，不独立判风险）",
    },
    "ssh_auth": {
        "label": "SSH 认证日志",
        "asset_type": "ssh_auth",
        "module": "ssh",
        "required_for_modules": ["ssh"],
        "implemented": True,
        "description": "SSH 登录/失败/暴力破解（tigersec-sys-auth / syslog-risk-json 认证子集）",
    },
    "syslog_risk_alert": {
        "label": "syslog 结构化风险报警",
        "asset_type": "syslog_risk_alert",
        "module": "syslog",
        "required_for_modules": ["syslog"],
        "implemented": True,
        "description": "syslog-risk-json 全量风险事件（asset-secweaver-sys-risk-alert）；SSH 暴破 raw 由 ssh 模块处理",
    },
    "dns_log": {
        "label": "DNS 查询日志",
        "asset_type": "dns_log",
        "module": "dns",
        "required_for_modules": ["dns"],
        "auxiliary_for_modules": ["connect"],
        "implemented": True,
        "description": "用于将主机外连关联到 C2 域名，识别 NXDOMAIN、DGA、DNS 隧道和非常见 TLD",
    },
    "network_traffic_audit": {
        "label": "全流量会话",
        "asset_type": "network_traffic_audit",
        "module": None,
        "required_for_modules": [],
        "auxiliary_for_modules": ["connect"],
        "description": "用于分析 C2 beacon 周期、流量体量和会话持续时间",
    },
}

# 规则 ID → 主数据源 + 辅助数据源 + 缺失时的用户提醒
RULE_SOURCE_REQUIREMENTS: dict[str, dict[str, Any]] = {
    # exec 模块 — 主依赖 host_exec
    "external_listener_shell_exec": {
        "primary": ["host_exec"],
        "auxiliary": ["host_connect", "host_file_op"],
        "label": "Web 进程 Shell 执行",
    },
    "download_and_execute": {
        "primary": ["host_exec"],
        "auxiliary": ["host_connect", "host_file_op"],
        "label": "下载并执行",
    },
    "reverse_shell": {
        "primary": ["host_exec"],
        "auxiliary": ["host_connect"],
        "label": "反弹 Shell",
    },
    "persistence_modify": {
        "primary": ["host_exec"],
        "auxiliary": ["host_file_op", "host_persistence"],
        "label": "持久化/后门",
    },
    "security_control_tampering": {
        "primary": ["host_exec"],
        "auxiliary": [],
        "label": "关闭审计/防火墙",
    },
    "sensitive_file_read": {
        "primary": ["host_exec"],
        "auxiliary": [],
        "label": "敏感文件读取",
    },
    "internal_recon": {
        "primary": ["host_exec"],
        "auxiliary": [],
        "label": "内网侦察",
    },
    "webshell_write": {
        "primary": ["host_exec"],
        "auxiliary": ["host_file_op"],
        "label": "WebShell 写入（命令特征）",
        "missing_aux_note": "无 host_file_op 时仅依赖命令行 echo/tee 特征，无法覆盖纯文件 API 落地",
    },
    "network_exfil_tools": {
        "primary": ["host_exec"],
        "auxiliary": ["host_connect"],
        "label": "外传工具/隧道",
    },
    "obfuscated_exec": {
        "primary": ["host_exec"],
        "auxiliary": [],
        "label": "混淆执行",
    },
    "data_staging": {
        "primary": ["host_exec"],
        "auxiliary": ["host_file_op", "host_connect"],
        "label": "数据打包外传准备",
    },
    "database_dump": {
        "primary": ["host_exec"],
        "auxiliary": [],
        "label": "数据库导出",
    },
    "noise_command": {
        "primary": ["host_exec"],
        "auxiliary": [],
        "label": "运维噪声命令",
    },
    # connect 模块 — 主依赖 host_connect
    "external_c2_connect": {
        "primary": ["host_connect"],
        "auxiliary": ["host_exec"],
        "label": "公网 C2 外连",
    },
    "suspicious_port_connect": {
        "primary": ["host_connect"],
        "auxiliary": ["host_exec"],
        "label": "可疑端口外连",
    },
    "exec_correlated_egress": {
        "primary": ["host_connect"],
        "auxiliary": ["host_exec"],
        "label": "exec 关联外连",
        "missing_aux_note": "无 host_exec 时无法关联同窗 curl/wget 命令，该规则不会命中",
    },
    "non_whitelist_egress": {
        "primary": ["host_connect"],
        "auxiliary": [],
        "label": "非公网白名单外连",
    },
    "business_whitelist_connect": {
        "primary": ["host_connect"],
        "auxiliary": [],
        "label": "内网业务依赖连接",
    },
    "high_nxdomain_burst": {
        "primary": ["dns_log"],
        "auxiliary": [],
        "label": "高频 NXDOMAIN",
        "implemented": True,
    },
    "suspected_dga_domain": {
        "primary": ["dns_log"],
        "auxiliary": ["host_connect"],
        "label": "疑似 DGA 域名",
        "implemented": True,
    },
    "uncommon_tld_query": {
        "primary": ["dns_log"],
        "auxiliary": [],
        "label": "非常见 TLD 查询",
        "implemented": True,
    },
    "dns_tunnel_suspected": {
        "primary": ["dns_log"],
        "auxiliary": ["network_traffic_audit"],
        "label": "疑似 DNS 隧道",
        "implemented": True,
        "missing_aux_note": "无 network_traffic_audit 时只能基于查询长度/类型画像，无法验证实际隧道流量体量",
    },
    "doh_egress": {
        "primary": ["host_connect"],
        "auxiliary": ["dns_log", "proxy_log"],
        "label": "DoH 外连",
        "implemented": True,
        "missing_aux_note": "无 dns_log/proxy_log 时仅能基于目的 IP/端口判断 DoH，无法看到 HTTP path/SNI",
    },
    "dot_egress": {
        "primary": ["host_connect"],
        "auxiliary": ["dns_log"],
        "label": "DoT 外连",
        "implemented": True,
    },
    "scan_burst_connect": {
        "primary": ["host_connect"],
        "auxiliary": [],
        "label": "扫描式短连接_burst",
        "implemented": False,
    },
    # 规划中
    "ssh_bruteforce": {
        "primary": ["ssh_auth"],
        "auxiliary": ["syslog_risk_alert"],
        "label": "SSH 暴力破解",
        "implemented": True,
    },
    "account_created": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "本地账号创建",
        "implemented": True,
    },
    "account_modified": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "账号/密码变更",
        "implemented": True,
    },
    "sudo_high_risk": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "高危 sudo",
        "implemented": True,
    },
    "sudo_command": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "sudo 命令",
        "implemented": True,
    },
    "root_ssh_login": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "root SSH 登录成功",
        "implemented": True,
    },
    "security_policy_denied": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "SELinux/AppArmor 拒绝",
        "implemented": True,
    },
    "firewall_event": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "防火墙变更",
        "implemented": True,
    },
    "suspicious_cron": {
        "primary": ["syslog_risk_alert"],
        "auxiliary": [],
        "label": "可疑 cron",
        "implemented": True,
    },
    "persistence_cron_modify": {
        "primary": ["host_persistence"],
        "auxiliary": ["host_exec", "syslog_risk_alert"],
        "label": "cron 持久化变更",
        "implemented": True,
    },
    "persistence_systemd_modify": {
        "primary": ["host_persistence"],
        "auxiliary": ["host_exec", "syslog_risk_alert"],
        "label": "systemd 持久化变更",
        "implemented": True,
    },
    "persistence_ssh_key_modify": {
        "primary": ["host_persistence"],
        "auxiliary": ["ssh_auth", "host_exec"],
        "label": "SSH authorized_keys 变更",
        "implemented": True,
    },
    "persistence_profile_modify": {
        "primary": ["host_persistence"],
        "auxiliary": ["host_exec"],
        "label": "profile/bashrc/rc.local 变更",
        "implemented": True,
    },
    "persistence_sudoers_modify": {
        "primary": ["host_persistence"],
        "auxiliary": ["syslog_risk_alert"],
        "label": "sudoers 权限持久化变更",
        "implemented": True,
    },
    "persistence_kernel_module_modify": {
        "primary": ["host_persistence"],
        "auxiliary": [],
        "label": "内核模块持久化变更",
        "implemented": True,
    },
    "persistence_ld_preload_modify": {
        "primary": ["host_persistence"],
        "auxiliary": [],
        "label": "ld.so.preload 持久化/绕过变更",
        "implemented": True,
    },
    "persistence_generic_change": {
        "primary": ["host_persistence"],
        "auxiliary": [],
        "label": "持久化路径变更",
        "implemented": True,
    },
}

# 按数据源聚合可识别的规则（仅 v1 已实现）
SOURCE_TO_RULES: dict[str, list[str]] = {}
for rule_id, meta in RULE_SOURCE_REQUIREMENTS.items():
    if meta.get("implemented") is False:
        continue
    for src in meta.get("primary") or []:
        SOURCE_TO_RULES.setdefault(src, []).append(rule_id)

MODULE_PRIMARY_SOURCE = {
    "exec": "host_exec",
    "connect": "host_connect",
    "dns": "dns_log",
    "persistence": "host_persistence",
    "ssh": "ssh_auth",
    "syslog": "syslog_risk_alert",
}

SCENARIO_SOURCE_REQUIREMENTS: dict[str, dict[str, list[str]]] = {
    "S5": {
        "required": ["host_exec"],
        "recommended": ["host_connect", "host_file_op", "host_persistence", "ssh_auth", "syslog_risk_alert"],
        "optional": ["waf_alert"],
    },
    "S5-EXEC": {
        "required": ["host_exec"],
        "recommended": ["host_file_op", "host_persistence"],
        "optional": ["host_connect"],
    },
    "S5-CONNECT": {
        "required": ["host_connect"],
        "recommended": ["host_exec"],
        "optional": [],
    },
    "S5-PERSISTENCE": {
        "required": ["host_persistence"],
        "recommended": ["host_exec", "syslog_risk_alert"],
        "optional": [],
    },
    "S5-HOST": {
        "required": ["host_exec"],
        "recommended": ["host_connect", "host_file_op", "host_persistence", "ssh_auth", "syslog_risk_alert"],
        "optional": ["waf_alert"],
    },
    "S5+WAF": {
        "required": ["host_exec"],
        "recommended": ["host_connect", "host_file_op", "host_persistence", "waf_alert"],
        "optional": [],
    },
    "S8": {
        "required": ["host_connect"],
        "recommended": ["host_exec", "dns_log", "network_traffic_audit", "syslog_risk_alert"],
        "optional": [],
    },
}


def _bundle_has_events(bundles: dict[str, list], key: str) -> bool:
    return bool(bundles.get(key))


def _source_status(
    key: str,
    *,
    present: bool,
    in_window: bool,
    event_count: int,
    modules: list[str],
) -> str:
    meta = DATA_SOURCES.get(key, {})
    if not present:
        return "missing"
    if not in_window or event_count == 0:
        return "empty_in_window"
    req_mods = meta.get("required_for_modules") or []
    if req_mods and not any(m in modules for m in req_mods):
        return "present_not_used"
    return "present"


def evaluate_source_coverage(
    bundles: dict[str, list],
    *,
    scenario: str,
    modules: list[str],
    raw_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    """评估各数据源可用性、可识别/不可用风险与用户提醒。"""
    raw_counts = raw_counts or {}
    scenario_req = SCENARIO_SOURCE_REQUIREMENTS.get(scenario, SCENARIO_SOURCE_REQUIREMENTS["S5"])

    source_status: dict[str, dict[str, Any]] = {}
    for key, meta in DATA_SOURCES.items():
        present = key in bundles
        count = raw_counts.get(key, len(bundles.get(key) or []) if present else 0)
        in_window = count > 0
        status = _source_status(
            key,
            present=present,
            in_window=in_window,
            event_count=count,
            modules=modules,
        )
        enables = list(SOURCE_TO_RULES.get(key, []))
        if meta.get("implemented") is False:
            enables = []
        source_status[key] = {
            "label": meta.get("label", key),
            "asset_type": meta.get("asset_type", key),
            "status": status,
            "event_count": count,
            "implemented": meta.get("implemented", True),
            "enables_modules": list(meta.get("required_for_modules") or []),
            "enables_risk_rules": enables,
            "description": meta.get("description", ""),
        }

    available: list[str] = []
    degraded: list[dict[str, str]] = []
    unavailable: list[dict[str, str]] = []

    for rule_id, meta in RULE_SOURCE_REQUIREMENTS.items():
        if meta.get("implemented") is False:
            unavailable.append(
                {
                    "rule_id": rule_id,
                    "label": meta.get("label", rule_id),
                    "reason": "规则尚未实现",
                    "missing_sources": meta.get("primary") or [],
                }
            )
            continue
        primary = meta.get("primary") or []
        auxiliary = meta.get("auxiliary") or []
        primary_ok = all(_source_available(source_status, s) for s in primary)
        if not primary_ok:
            missing = [s for s in primary if not _source_available(source_status, s)]
            unavailable.append(
                {
                    "rule_id": rule_id,
                    "label": meta.get("label", rule_id),
                    "reason": f"缺少主数据源：{', '.join(_label(s) for s in missing)}",
                    "missing_sources": missing,
                }
            )
            continue
        available.append(rule_id)
        missing_aux = [s for s in auxiliary if not _source_available(source_status, s)]
        if missing_aux:
            note = meta.get("missing_aux_note") or (
                f"缺少辅助数据源 {', '.join(_label(s) for s in missing_aux)}，"
                "置信度/关联能力可能降级"
            )
            degraded.append({"rule_id": rule_id, "label": meta.get("label", rule_id), "note": note})

    user_reminders: list[str] = []
    data_gaps: list[str] = []

    for src_key in scenario_req.get("required") or []:
        st = source_status.get(src_key, {}).get("status")
        if st == "missing":
            msg = (
                f"【必需】缺少 {_label(src_key)}（{src_key}），"
                f"无法运行 {', '.join(DATA_SOURCES[src_key].get('required_for_modules') or ['相关'])} 模块。"
                f"可识别风险：{_rules_summary(SOURCE_TO_RULES.get(src_key, []))}"
            )
            user_reminders.append(msg)
            data_gaps.append(f"{src_key}: missing — required for scenario {scenario}")
        elif st == "empty_in_window":
            msg = (
                f"【必需】{_label(src_key)}（{src_key}）在当前 host/时间窗内无事件，"
                f"无法识别：{_rules_summary(SOURCE_TO_RULES.get(src_key, []))}"
            )
            user_reminders.append(msg)
            data_gaps.append(f"{src_key}: no events in window")

    for src_key in scenario_req.get("recommended") or []:
        st = source_status.get(src_key, {}).get("status")
        if st in ("missing", "empty_in_window"):
            if src_key == "host_connect" and "connect" in modules:
                user_reminders.append(
                    f"【建议】缺少 {_label(src_key)}，无法识别外连类风险："
                    f"{_rules_summary(SOURCE_TO_RULES.get('host_connect', []))}；"
                    "exec 上下文加权将降级（跨源攻击链请用 traceability-analysis）"
                )
                data_gaps.append(f"{src_key}: missing — connect risks degraded")
            elif src_key == "host_file_op":
                user_reminders.append(
                    f"【建议】缺少 {_label(src_key)}，exec 规则的上下文加权（同窗 file 事件）不可用，"
                    "WebShell 落地若未体现在 command 中将漏检"
                )
                data_gaps.append(f"{src_key}: missing — exec context boost degraded")
            elif src_key == "host_persistence":
                user_reminders.append(
                    f"【建议】缺少 {_label(src_key)}，无法独立识别 cron/systemd/authorized_keys 等持久化留驻；"
                    "exec 持久化规则只能依赖命令行特征"
                )
                data_gaps.append(f"{src_key}: missing — persistence risks degraded")
            elif src_key == "waf_alert":
                user_reminders.append(
                    "【建议】缺少 WAF 告警（waf_alert），无法给出主机风险与 WAF 互证建议"
                )
                data_gaps.append("waf_alert: missing — no WAF cross-check recommendation")
            elif src_key == "dns_log":
                user_reminders.append(
                    "【建议】缺少 DNS 查询日志（dns_log），无法识别高频 NXDOMAIN、DGA、非常见 TLD、"
                    "DNS 隧道等域名画像；host_connect 只能保留 IP/端口侧外连证据"
                )
                data_gaps.append("dns_log: missing — DNS profile and domain attribution degraded")
            elif src_key == "network_traffic_audit":
                user_reminders.append(
                    "【建议】缺少全流量会话（network_traffic_audit），DNS 不能替代流量体量、"
                    "beacon 周期和真实会话路径验证"
                )
                data_gaps.append("network_traffic_audit: missing — DNS cannot replace session/volume evidence")

    # 模块级提醒（避免与上方重复）
    for mod in modules:
        src = MODULE_PRIMARY_SOURCE.get(mod)
        if not src:
            continue
        st = source_status.get(src, {}).get("status")
        if st == "present":
            continue
        prefix = f"{mod} 模块未运行"
        if any(prefix in r for r in user_reminders):
            continue
        if mod == "exec":
            user_reminders.append(
                f"{prefix}：缺少 {_label(src)} 数据。"
                f"漏检命令类风险（Shell/下载执行/反弹Shell/持久化等 {_len_exec_rules()} 条规则）"
            )
        elif mod == "connect":
            user_reminders.append(
                f"{prefix}：缺少 {_label(src)} 数据。"
                f"漏检外连类风险（C2/可疑端口/exec关联外连等 {_len_connect_rules()} 条规则）"
            )
        elif mod == "dns":
            user_reminders.append(
                f"{prefix}：缺少 {_label(src)} 数据。"
                "漏检 DNS 画像风险（NXDOMAIN/DGA/非常见 TLD/DNS 隧道）；"
                "DoH/DoT 仍需 host_connect 或 proxy 辅助识别"
            )
        elif mod == "persistence":
            user_reminders.append(
                f"{prefix}：缺少 {_label(src)} 数据。"
                f"漏检持久化变更风险（cron/systemd/authorized_keys/sudoers 等 {_len_persistence_rules()} 条规则）"
            )

    if (
        source_status.get("host_exec", {}).get("status") == "present"
        and source_status.get("host_connect", {}).get("status") != "present"
        and "exec" in modules
        and "connect" in modules
    ):
        user_reminders.append(
            "【关联降级】仅有 host_exec 无 host_connect：无法识别外连类风险；跨源攻击链请用 traceability-analysis"
        )

    coverage_level = _coverage_level(source_status, scenario_req, modules)

    return {
        "coverage_level": coverage_level,
        "data_source_status": source_status,
        "risk_coverage": {
            "available_rule_ids": available,
            "degraded_rules": degraded,
            "unavailable_rules": unavailable,
        },
        "user_reminders": user_reminders,
        "data_gaps": data_gaps,
        "scenario_requirements": scenario_req,
    }


def _label(key: str) -> str:
    return DATA_SOURCES.get(key, {}).get("label", key)


def _rules_summary(rule_ids: list[str]) -> str:
    if not rule_ids:
        return "（无）"
    labels = []
    for rid in rule_ids[:6]:
        labels.append(RULE_SOURCE_REQUIREMENTS.get(rid, {}).get("label", rid))
    suffix = "…" if len(rule_ids) > 6 else ""
    return "、".join(labels) + suffix


def _len_exec_rules() -> int:
    return len(SOURCE_TO_RULES.get("host_exec", []))


def _len_connect_rules() -> int:
    return len(SOURCE_TO_RULES.get("host_connect", []))


def _len_persistence_rules() -> int:
    return len(SOURCE_TO_RULES.get("host_persistence", []))


def _source_available(source_status: dict[str, dict[str, Any]], key: str) -> bool:
    st = source_status.get(key, {}).get("status")
    return st in ("present", "present_not_used")


def _coverage_level(
    source_status: dict[str, dict[str, Any]],
    scenario_req: dict[str, list[str]],
    modules: list[str],
) -> str:
    required = scenario_req.get("required") or []
    recommended = scenario_req.get("recommended") or []
    req_ok = all(_source_available(source_status, k) for k in required)
    if not req_ok:
        return "insufficient"
    rec_ok = all(_source_available(source_status, k) for k in recommended)
    if rec_ok:
        return "full"
    # Required sources decide insufficient. Recommended module sources only degrade to partial.
    mod_ok = True
    required_set = set(required)
    for mod in modules:
        src = MODULE_PRIMARY_SOURCE.get(mod)
        if src and src in required_set and not _source_available(source_status, src):
            mod_ok = False
    if mod_ok:
        return "partial"
    return "insufficient"
