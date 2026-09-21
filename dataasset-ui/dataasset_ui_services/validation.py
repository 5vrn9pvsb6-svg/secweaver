"""Validation runner and advice mapping for the local DataAsset UI."""

from __future__ import annotations

import json
import subprocess
from typing import Any

from .common import ROOT, VALIDATE_SCRIPT, subprocess_env, validation_python


def validation_advice(output: str) -> list[dict]:
    cards: list[dict] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith(("ERROR:", "WARN:")):
            continue
        severity = "P0" if line.startswith("ERROR:") else "P1"
        text = line.split(":", 1)[1].strip()
        lower = text.lower()
        advice = "按对象查看对应 JSON，确认引用、状态和字段声明是否符合 dataasset 设计契约。"
        owner = "高阶运营"
        impact = "可能影响 validate、fetch 或 Skill 调查可信度。"

        if "未安装 jsonschema" in text or "jsonschema" in lower:
            severity = "P0"
            advice = "UI 会优先使用项目 .venv/bin/python 运行 validate.py；如果仍出现该提示，请执行 .venv/bin/python -m pip install jsonschema 后重跑校验。"
            owner = "开发 / 高阶运营"
            impact = "JSON Schema 校验被跳过，配置契约没有被完整检查；发布前必须解决。"
        elif "active" in lower and "draft" in lower:
            advice = "接入期将 bundle.status 改为 draft，或先完成成员资产连通测试并晋升为 active。"
            owner = "运营"
            impact = "阻塞发布；active 资产包不应引用未发布资产。"
        elif "credentials_ref" in lower or "vault://" in lower:
            advice = "为 active connector 填写 vault://namespace/name，不要把明文密钥写入 JSON。"
            owner = "运营"
            impact = "live fetch 无法解密凭证，连接会失败。"
        elif "evidence 必需字段" in text:
            advice = "在 asset.schema.fields 中声明 canonical 字段，或在 asset.field_aliases 中补充 源字段→canonical；active 前必须让 Skill 能读到最小 evidence 字段。"
            owner = "高阶运营"
            impact = "阻塞发布；完整性、告警确认、溯源等 Skill 会缺关键字段。"
        elif "不可达" in text and ("join_keys" in lower or "correlation-matrix" in lower):
            advice = "检查对应 asset_type 的资产是否声明该字段；若日志里是源字段，请补 schema.fields、asset.field_aliases 或 join_keys.*_variants。optional Join 可作为 P1 排期。"
            owner = "高阶运营 / 安全专家"
            impact = "Join 字段无法解析，跨源关联或攻击链补全可能失效。"
        elif "host_id" in lower or "host_field" in lower:
            advice = "资产侧不再使用主机绑定字段；主机覆盖关系以 asset.coverage.hosts 的日志来源 IP 为准，单主机采集可在 connector.config.host_id 标注物理目标。"
            owner = "高阶运营"
            impact = "主机或字段引用不一致时，拓扑展示和跨源关联可能不准确。"
        elif "query_template" in lower or "template" in lower:
            advice = "确认 asset.query_template_ids 存在于 templates.json，且模板 connector_types 与 connector.connector_type 匹配。"
            owner = "高阶运营 / 开发"
            impact = "fetch/test-connector 可能无法选择查询模板。"
        elif "schema" in lower or "is not one of" in lower:
            advice = "按 dataasset/schema/*.schema.json 修正字段值；不要绕过 schema。"
            owner = "运营 / 开发"
            impact = "配置契约不通过，通常阻塞发布。"
        elif "correlation" in lower or "join" in lower:
            advice = "确认 Join 字段来自 schema.fields、field_aliases 或 evidence-minimum-fields；复杂 Join 需安全专家评审。"
            owner = "安全专家 / 开发"
            impact = "跨源关联可能不可达，影响溯源结论。"

        cards.append(
            {
                "priority": severity,
                "raw": line,
                "meaning": text,
                "impact": impact,
                "advice": advice,
                "owner": owner,
            }
        )
    return cards


def run_validation(
    *,
    sync_catalog: bool = False,
    strict: bool = False,
    only_active: bool = False,
    runtime_ready: bool = False,
    bundle_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Run the canonical validator with UI-selected scope and readiness mode."""
    python_bin = validation_python()
    cmd = [python_bin, str(VALIDATE_SCRIPT), "--json"]
    if strict:
        cmd.append("--strict")
    if only_active:
        cmd.append("--only-active")
    if sync_catalog:
        cmd.append("--sync-catalog")
    if runtime_ready:
        cmd.append("--runtime-ready")
        for bundle_id in bundle_ids or []:
            cmd.extend(["--bundle", bundle_id])
    try:
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            env=subprocess_env(),
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("validate.py 执行超时") from exc
    output = (result.stdout or "") + (result.stderr or "")
    structured: dict[str, Any] = {}
    try:
        structured = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        structured = {}
    issues = structured.get("issues") or []
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "python": python_bin,
        "output": output,
        "structured": structured,
        "diagnostics": structured.get("diagnostics") or {},
        "advice": issues or validation_advice(output),
    }
