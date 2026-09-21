"""Operator-facing validation diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_OWNER = "高阶运营"
DEFAULT_IMPACT = "可能影响上线、fetch 或 Skill 研判可信度。"
DEFAULT_FIX = "按对象查看对应 JSON，确认引用、状态和字段声明是否符合 dataasset 设计契约。"


@dataclass
class Issue:
    severity: str
    message: str
    code: str = "validation"
    object_type: str = "unknown"
    object_id: str = ""
    path: str = ""
    field: str = ""
    priority: str = ""
    owner: str = DEFAULT_OWNER
    impact: str = DEFAULT_IMPACT
    suggested_fix: str = DEFAULT_FIX

    def to_dict(self) -> dict[str, Any]:
        diagnosis = diagnose_issue(self)
        priority = self.priority or diagnosis.get("priority") or ("P0" if self.severity == "error" else "P1")
        owner = self.owner if self.owner != DEFAULT_OWNER else diagnosis.get("owner", self.owner)
        impact = self.impact if self.impact != DEFAULT_IMPACT else diagnosis.get("impact", self.impact)
        suggested_fix = self.suggested_fix if self.suggested_fix != DEFAULT_FIX else diagnosis.get("suggested_fix", self.suggested_fix)
        diagnosis = {
            **diagnosis,
            "priority": priority,
            "owner": owner,
            "impact": impact,
            "suggested_fix": suggested_fix,
        }
        return {
            "severity": self.severity,
            "priority": priority,
            "code": self.code,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "path": self.path,
            "field": self.field,
            "message": self.message,
            "category": diagnosis["category"],
            "root_cause": diagnosis["root_cause"],
            "impact": impact,
            "suggested_fix": suggested_fix,
            "fix_steps": diagnosis["fix_steps"],
            "example": diagnosis["example"],
            "docs": diagnosis["docs"],
            "owner": owner,
            "diagnosis": diagnosis,
        }


def _diag(
    *,
    category: str,
    root_cause: str,
    fix_steps: list[str],
    impact: str = DEFAULT_IMPACT,
    suggested_fix: str = DEFAULT_FIX,
    owner: str = DEFAULT_OWNER,
    priority: str = "",
    example: str = "",
    docs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "category": category,
        "root_cause": root_cause,
        "impact": impact,
        "suggested_fix": suggested_fix,
        "fix_steps": fix_steps,
        "owner": owner,
        "priority": priority,
        "example": example,
        "docs": docs or [],
    }


def diagnose_issue(issue: Issue) -> dict[str, Any]:
    """Classify a validation issue into operator-facing diagnostics."""

    text = f"{issue.code} {issue.object_type} {issue.field} {issue.message}".lower()

    if issue.code.startswith("runtime-"):
        return _diag(
            category="runtime-readiness",
            root_cause="Bundle 的静态执行链仍包含未激活对象、占位配置、缺失引用或不可用凭证密文。",
            impact="配置可以通过基础结构校验，但对应 Skill 仍无法可靠执行真实取数。",
            suggested_fix="按 blocker 修复 Bundle -> Asset -> Connector -> Credential 链路，再执行真实连通性检查。",
            fix_steps=[
                "根据 issue.object_type 和 issue.object_id 定位未就绪对象。",
                "将确认可用的对象提升为 active，并替换 YOUR_* 等接入占位值。",
                "确认 credentials_ref 对应的密文存在且未被禁用。",
                "重新运行 `python3 src/secweaver.py validate --runtime-ready --bundle <bundle_id> --json`。",
                "静态门禁通过后，运行 dataasset-connectivity-check 验证真实连通性和数据存在性。",
            ],
            owner="运营 / 开发",
            priority="P0",
            docs=["docs_user/13-SecWeaver-CLI.zh-CN.md", "docs_user/03-configure-data-sources.zh-CN.md"],
        )

    if "jsonschema" in text:
        return _diag(
            category="validator-runtime",
            root_cause="当前 Python 环境缺少 JSON Schema 校验依赖，或 schema 契约校验失败。",
            impact="结构约束可能未完整执行；开源发布或上线前需要确认 schema 校验可用。",
            suggested_fix="优先使用项目 .venv 运行；若仍缺依赖，执行 `python3 -m pip install -r requirements-data-access.txt` 后重跑。",
            fix_steps=[
                "确认使用仓库虚拟环境：`.venv/bin/python src/dataasset/validate.py --json`。",
                "安装依赖：`python3 -m pip install -r requirements-data-access.txt`。",
                "若是 schema 字段错误，按 dataasset/schema/*.schema.json 修正对象字段。",
            ],
            owner="开发 / 高阶运营",
            priority="P0",
            docs=["dataasset/README.zh-CN.md", "docs_user/09-operations-troubleshooting.zh-CN.md"],
        )

    if "schema [" in text or "is not one of" in text:
        return _diag(
            category="schema-contract",
            root_cause="JSON 字段结构、类型或枚举值不符合 dataasset/schema 中定义的契约。",
            impact="配置文件可能无法被 UI、validate、fetch 或 Skill 稳定解析，通常会阻塞发布。",
            suggested_fix="按对应 dataasset/schema/*.schema.json 修正字段类型、枚举值或必填项。",
            fix_steps=[
                "查看 issue.message 中的 schema 路径，例如 `schema [connector_type]`。",
                "打开对应的 dataasset/schema/*.schema.json。",
                "按 schema 要求修正字段类型、枚举值、数组/对象结构。",
                "重新运行 `python3 src/secweaver.py validate --json`。",
            ],
            owner="运营 / 开发",
            priority="P0" if issue.severity == "error" else "P1",
            docs=["dataasset/schema/data-asset.schema.json", "dataasset/schema/data-connector.schema.json"],
        )

    if "credentials_ref" in text or "vault://" in text:
        return _diag(
            category="credential",
            root_cause="active connector 需要凭证引用，但当前 credentials_ref 缺失、格式不对，或找不到对应密文。",
            impact="live fetch 无法解密凭证，数据源连通测试和 Skill 调查会失败。",
            suggested_fix="使用 `vault://namespace/name` 引用凭证，真实密钥只放在 credentials vault，不写入 connector JSON。",
            fix_steps=[
                "在 connector JSON 中填写 `credentials_ref: vault://<type>/<name>`。",
                "在 dataasset/credentials/ 下创建或同步对应密文。",
                "用 `python3 src/secweaver.py connector test <asset_id> --by-asset --dry-run` 先确认模板渲染。",
            ],
            owner="运营",
            priority="P0" if issue.severity == "error" else "P1",
            example='{"credentials_ref": "vault://aws/secops-readonly"}',
            docs=["dataasset/credentials/README.zh-CN.md", "docs_user/03-configure-data-sources.zh-CN.md"],
        )

    if "config 缺少" in text or "connector" in text and ("缺少" in text or "missing" in text):
        return _diag(
            category="connector-config",
            root_cause="connector_type 已选择，但该类型要求的连接参数没有填完整。",
            impact="asset apply 可能能生成文件，但 fetch/test-connector 无法构造有效请求。",
            suggested_fix="打开对应 connector JSON，按 connector_type 补齐 endpoint、region、log_group、host、database 等必填 config。",
            fix_steps=[
                "确认 connector.connector_type 是否选对。",
                "对照 dataasset/configure/connector-catalog.json 或 onboarding 页面提示补齐必填字段。",
                "重新运行 `python3 src/secweaver.py validate --json --only-active`。",
            ],
            owner="运营",
            priority="P0",
            docs=["dataasset/onboarding/README.zh-CN.md", "docs_user/16-data-source-onboarding-faq.zh-CN.md"],
        )

    if "query_template" in text or "default_template" in text or "模板" in text or "template" in text:
        return _diag(
            category="query-template",
            root_cause="资产声明的 query_template 与 asset_type 或 connector_type 不匹配，或默认模板缺失。",
            impact="fetch 时无法选择查询模板，导致数据源即使可连接也无法被 Skill 使用。",
            suggested_fix="确认 asset.query_template_ids 存在于 templates.json，且模板 asset_types / connector_types 覆盖当前资产和连接器。",
            fix_steps=[
                "打开 dataasset/query-templates/templates.json 找到对应 template_id。",
                "检查模板中的 `asset_types` 是否包含 asset.asset_type。",
                "检查模板中的 `connector_types` 是否包含 connector.connector_type。",
                "如不想手写 query_template_ids，可在 `default_templates` 中登记默认模板。",
            ],
            owner="高阶运营 / 开发",
            priority="P0" if issue.severity == "error" else "P1",
            docs=["docs_dev/09-data-asset-design.zh-CN.md", "docs_user/03-configure-data-sources.zh-CN.md"],
        )

    if "evidence 必需字段" in text or "schema.fields" in text or "time_field" in text or "retention_days" in text:
        return _diag(
            category="field-contract",
            root_cause="资产字段契约不完整，Skill 无法稳定读取 canonical evidence 字段。",
            impact="完整性、告警确认、溯源和风险识别会缺关键字段，active 资产可能阻塞发布。",
            suggested_fix="在 asset.schema.fields 中声明源字段，并用 asset.field_aliases 将源字段映射到 canonical 字段。",
            fix_steps=[
                "补齐 `schema.fields`、`schema.time_field`、`schema.retention_days`。",
                "若源字段名不同，在 `field_aliases` 中声明 `源字段: canonical字段`。",
                "对照 dataasset/configure/evidence-minimum-fields.json 检查该 asset_type 的 required 字段。",
            ],
            owner="高阶运营",
            priority="P0" if issue.severity == "error" else "P1",
            docs=["dataasset/configure/evidence-minimum-fields.json", "docs_dev/12-agent-collection-and-evidence-spec.zh-CN.md"],
        )

    if "join_keys" in text or "recommended_chain" in text or "correlation" in text or "anchor" in text or "不可达" in text:
        return _diag(
            category="correlation",
            root_cause="关联矩阵或场景编排引用了当前资产字段无法提供的 Join 字段、Join id 或 asset_type。",
            impact="跨源关联、攻击链拼接或场景补数可能失效，影响溯源结论可信度。",
            suggested_fix="补 schema.fields / field_aliases / join variants，或调整 correlation-matrix 与 anchor-patterns 的引用。",
            fix_steps=[
                "定位 issue 中的 join id、pattern id 或字段名。",
                "确认相关 asset_type 至少有一个 active/draft 资产声明该字段。",
                "源字段名不同则补 `join_keys.*_variants` 或 `asset.field_aliases`。",
                "场景链引用不存在 Join 时，修正 `recommended_chain`。",
            ],
            owner="安全专家 / 开发",
            priority="P0" if issue.severity == "error" else "P1",
            docs=["docs_user/21-cross-source-field-correlation.zh-CN.md", "docs_dev/22-correlation-matrix-design-evaluation.zh-CN.md"],
        )

    if "network_id" in text or "cidr" in text or "coverage.hosts" in text or "host_ip" in text:
        return _diag(
            category="topology",
            root_cause="主机、网段或资产覆盖范围声明不一致。",
            impact="拓扑展示、host 过滤、跨源关联和运营归属可能不准确。",
            suggested_fix="修正 network_id/CIDR/coverage.hosts；coverage.hosts 只写日志来源 IP，主机别名写 host.aliases。",
            fix_steps=[
                "确认 dataasset/networks/*.json 中存在被引用的 network_id。",
                "确认 host_ip 或 interfaces[].ip 落在对应 CIDR 内。",
                "确认 asset.coverage.hosts 使用 IP，不使用 hostname/FQDN。",
            ],
            owner="运营",
            priority="P0" if issue.severity == "error" else "P1",
            docs=["docs_user/02-core-concepts.zh-CN.md", "docs_user/04-correlation-matrix.zh-CN.md"],
        )

    if "active 资产包" in text or "非 active" in text or "discovery" in text or "status" in text:
        return _diag(
            category="lifecycle",
            root_cause="对象状态不符合发布链路：active bundle/asset 引用了 draft、discovery 或未完成对象。",
            impact="发布门禁会阻塞；运营侧可能误以为数据源已上线但实际不可用。",
            suggested_fix="接入期保持 draft/discovery；连通测试通过且字段确认后再提升为 active。",
            fix_steps=[
                "新数据源先使用 `status: draft` 或 `status: discovery`。",
                "通过 validate、test-connector、必要的格式发现后，再改为 `active`。",
                "active bundle 只能引用 active asset。",
            ],
            owner="运营",
            priority="P0" if issue.severity == "error" else "P1",
            docs=["docs_user/00-security-operator-quickstart.zh-CN.md", "docs_user/09-operations-troubleshooting.zh-CN.md"],
        )

    if "不存在" in text or "引用未知" in text:
        return _diag(
            category="reference",
            root_cause="配置引用了不存在的 asset、connector、host、network、bundle 或 scenario。",
            impact="validate 或运行时装配会失败，被引用对象无法参与 fetch 或调查。",
            suggested_fix="修正引用 id，或先创建被引用对象；对象 id 应与文件名保持一致。",
            fix_steps=[
                "用 issue.path 打开出错文件。",
                "检查 issue.field 中的 id 是否拼写正确。",
                "确认目标文件存在，且内部 *_id 与文件名一致。",
            ],
            owner="运营 / 开发",
            priority="P0" if issue.severity == "error" else "P1",
            docs=["dataasset/README.zh-CN.md", "docs_user/03-configure-data-sources.zh-CN.md"],
        )

    if "catalog.json" in text:
        return _diag(
            category="catalog",
            root_cause="catalog.json 与 assets/connectors/bundles 当前文件状态不一致。",
            impact="UI 和工具读取 registry 时可能看不到最新对象。",
            suggested_fix="运行 `python3 src/secweaver.py validate --sync-catalog` 同步 catalog。",
            fix_steps=[
                "确认新增或删除的 DataAsset 文件是否符合命名规则。",
                "运行 `python3 src/secweaver.py validate --sync-catalog`。",
                "重新运行 `make docs-check` 和 validate。",
            ],
            owner="开发 / 高阶运营",
            priority="P1",
            docs=["dataasset/README.zh-CN.md"],
        )

    return _diag(
        category="generic-config",
        root_cause="配置不满足 DataAsset 契约，具体原因见 message/path/field。",
        suggested_fix=issue.suggested_fix,
        impact=issue.impact,
        owner=issue.owner,
        priority="P0" if issue.severity == "error" else "P1",
        fix_steps=[
            "打开 issue.path 指向的 JSON/YAML 文件。",
            "定位 issue.field 或 message 中提到的字段。",
            "按 suggested_fix 修改后重新运行 validate。",
        ],
        docs=["docs_user/09-operations-troubleshooting.zh-CN.md", "dataasset/README.zh-CN.md"],
    )


def summarize_diagnostics(issues: list[dict[str, Any]], *, strict: bool = False) -> dict[str, Any]:
    categories: dict[str, dict[str, Any]] = {}
    for issue in issues:
        category = str(issue.get("category") or "generic-config")
        item = categories.setdefault(category, {"category": category, "error_count": 0, "warning_count": 0, "blocking_count": 0})
        if issue.get("severity") == "error":
            item["error_count"] += 1
            item["blocking_count"] += 1
        else:
            item["warning_count"] += 1
            if strict:
                item["blocking_count"] += 1
    ordered = sorted(
        categories.values(),
        key=lambda item: (-int(item["blocking_count"]), -int(item["error_count"]), item["category"]),
    )
    return {
        "category_count": len(ordered),
        "categories": ordered,
    }


@dataclass
class Report:
    issues: list[Issue] = field(default_factory=list)
    runtime_readiness: dict[str, Any] | None = None
    _seen_issue_keys: set[tuple[str, str, str, str, str, str, str]] = field(default_factory=set, init=False, repr=False)

    def add(
        self,
        severity: str,
        msg: str,
        *,
        code: str = "validation",
        object_type: str = "unknown",
        object_id: str = "",
        path: str | Path = "",
        field: str = "",
        priority: str = "",
        owner: str = DEFAULT_OWNER,
        impact: str = DEFAULT_IMPACT,
        suggested_fix: str = DEFAULT_FIX,
    ) -> None:
        issue_path = str(path) if path else ""
        issue_key = (severity, code, object_type, object_id, issue_path, field, msg)
        if issue_key in self._seen_issue_keys:
            return
        self._seen_issue_keys.add(issue_key)
        self.issues.append(
            Issue(
                severity=severity,
                message=msg,
                code=code,
                object_type=object_type,
                object_id=object_id,
                path=issue_path,
                field=field,
                priority=priority,
                owner=owner,
                impact=impact,
                suggested_fix=suggested_fix,
            )
        )

    def error(self, msg: str, **kwargs: Any) -> None:
        self.add("error", msg, **kwargs)

    def warn(self, msg: str, **kwargs: Any) -> None:
        self.add("warning", msg, **kwargs)

    @property
    def errors(self) -> list[str]:
        return [issue.message for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[str]:
        return [issue.message for issue in self.issues if issue.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_json(self, *, strict: bool = False) -> dict[str, Any]:
        blocking = [issue for issue in self.issues if issue.severity == "error" or (strict and issue.severity == "warning")]
        issues = [issue.to_dict() for issue in self.issues]
        payload = {
            "ok": not blocking,
            "strict": strict,
            "summary": {
                "error_count": len(self.errors),
                "warning_count": len(self.warnings),
                "blocking_count": len(blocking),
            },
            "diagnostics": summarize_diagnostics(issues, strict=strict),
            "issues": issues,
        }
        if self.runtime_readiness is not None:
            payload["runtime_readiness"] = self.runtime_readiness
        return payload
