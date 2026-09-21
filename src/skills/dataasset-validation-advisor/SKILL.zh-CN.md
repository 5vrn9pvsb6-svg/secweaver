---
name: dataasset-validation-advisor
description: >-
  Validate SecWeaver dataasset registry and explain actionable fixes. Use when
  the user asks to 校验数据源资产, validate dataasset, check data assets, analyze
  validate.py output, explain validation errors, or give suggestions for assets,
  connectors, bundles, credentials, hosts, schemas, or query templates.
---

# 数据资产校验与建议

对 `dataasset/` 做「可运行校验 + 人类可读建议」：运行确定性脚本，归类 errors/warnings，说明影响，并给出最小修复路径。

## 适用时机

- 用户说「校验数据」「检查 dataasset」「validate 报错怎么看」「给出修复建议」
- 修改了 `assets/`、`connectors/`、`bundles/`、`hosts/`、`query-templates/`、`schema/` 后需要体检
- 发布资产 / bundle 前确认是否可进入 `active`
- 根据当前 Schema 和代码复核 `docs_dev/history/10-data-asset-design-evaluation.md` 中的历史问题

## 必跑命令

从仓库根目录执行：

```bash
# 首选：项目虚拟环境，确保 jsonschema 生效
.venv/bin/python src/dataasset/validate.py 2>&1

# catalog 变更时再跑
.venv/bin/python src/dataasset/validate.py --sync-catalog 2>&1
```

如果 `.venv` 不存在或缺 `jsonschema`，先创建/安装：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install jsonschema
```

不要用系统 Python 强装包；macOS/Homebrew Python 可能受 PEP 668 保护。

## 分析流程

1. 运行 validate，保留完整 stdout/stderr。
2. 按前缀拆分：`ERROR:` 为阻塞，`WARN:` 为建议。
3. 按对象归类：asset / connector / bundle / host / schema / catalog / template。
4. 对每类输出：
   - **现象**：原始错误摘要
   - **原因**：违反了哪条契约
   - **影响**：是否阻塞 active / fetch / Skill
   - **建议处理**：给出保守、最小改动
5. 明确区分：
   - **设计问题**：脚本或 schema 需要改
   - **运营数据问题**：示例 draft、占位符、未晋升、未填真实连接参数
   - **可接受 warning**：接入期 draft、示例目录说明、catalog 备注类提示等；未被 asset 引用的 connector 不再作为 warning
6. 不要为了让 validate 变绿而随意把 draft 资产改 active；active 只在连通测试和字段确认后设置。

## 常见错误与建议

| validate 输出 | 原因 | 建议 |
|---|---|---|
| `environment: 'lab' is not one of ...` | asset schema 只允许 `production/staging/development` | POC/lab 资产改 `development`，或团队明确后扩 schema |
| `correlation-matrix.json: asset_id=None` | 旧版 validate 将 matrix 当 asset 扫描 | 已由 validate 跳过普通 asset 扫描，并执行 matrix 专用校验；若复现说明脚本回退 |
| `active 资产包引用了非 active 资产` | active bundle 发布契约被破坏 | 接入期 bundle 改 `draft`；或先测试并晋升成员资产 |
| `query_template_id ... 不在 templates.json` | asset 引用了不存在模板 | 补模板或移除引用 |
| `connector ... 无匹配的 query_template` | connector_type 与模板不匹配 | 给该 connector_type 增模板，或调整 asset `query_template_ids` |
| `credentials_ref 格式无效/缺少` | active connector 缺 vault 引用 | 填 `vault://namespace/name`；local_file 可例外 |
| `asset-coverage-host-not-ip` | `coverage.hosts` 中出现 hostname/别名/文字 | 改为实际日志来源 IP；别名写入 `host.aliases` |
| `connector ... config.host_id 引用未知主机` | 单主机 connector 指向不存在的 host | 新增 host 或修正 connector.config.host_id |
| `text_parser valid under each of ...` | oneOf 分支重叠 | 自定义 parser 字符串分支加 `not enum` 排除内置 id |

## 输出格式

必须给用户一个「运营可执行」短报告。不要只贴 validate 原文；每个问题都要说明谁处理、是否阻塞、怎么改、是否需要开发介入。

### 总览

```markdown
## 校验结果

- Errors: N
- Warnings: M
- 是否阻塞发布：是/否
- 建议处理人：运营 / 高阶运营 / 开发 / 安全专家
- 建议处理顺序：P0 → P1 → P2
```

### 问题明细表

```markdown
| 优先级 | 对象 | 问题 | 原因 | 影响 | 修复建议 | 处理人 | 是否需要开发 |
|---|---|---|---|---|---|---|---|
| P0 | asset / connector / bundle / matrix | 原始错误摘要 | 违反的契约 | 阻塞 active / fetch / Skill | 最小改动方案 | 运营 | 否 |
```

优先级定义：

| 优先级 | 含义 | 发布影响 |
|---|---|---|
| P0 | `ERROR` 或会导致 active/fetch/Skill 失败 | 必须修复 |
| P1 | `WARN` 但会降低调查可信度或造成数据缺口 | 建议本轮修复 |
| P2 | 文档、示例、冗余、可接受 warning | 可排期 |

### 单项解释卡片

对每个 P0/P1 问题，至少输出一张卡片：

```markdown
### [P0] <对象>: <问题标题>

- **原始输出**：`ERROR/WARN: ...`
- **这是什么意思**：用运营能理解的话解释。
- **为什么会这样**：引用具体契约，如 schema、coverage.hosts、connector、template、bundle、matrix。
- **影响范围**：是否影响 validate、test-connector、fetch、完整性、告警确认、溯源。
- **最小修复**：只改必须改的 JSON 字段。
- **示例修改**：给出 JSON 片段或文件路径。
- **处理人**：运营 / 高阶运营 / 开发 / 安全专家。
- **复验命令**：`validate.py` / `test_connector.py` / 对应 Skill 命令。
```

### 运营可直接复制的修复示例

当修复明确且低风险时，给出可复制 JSON 片段：

```json
"field_aliases": {
  "host_name": "host",
  "time": "timestamp"
}
```

但不要自动修改文件，除非用户明确说“帮我修复”。

### 不确定时的输出

如果缺少上下文，不要猜测，应输出：

```markdown
需要确认：
1. 生产日志 raw 字段是否确实包含 `<field>`？
2. 该 connector 是否应该被某个 asset 引用，还是保留为跳板/备用？
3. 该 bundle 是否准备发布为 active，还是接入期 draft？
```

## 可选修复动作

只有用户明确要求“修复”时才编辑文件。修复前说明将改哪些文件。常见安全修复：

- `asset-local-lab-auth.environment: lab → development`
- 接入期 `bundle.status: active → draft`
- 修正 `coverage.hosts` 中的非 IP 值，别名写入 `host.aliases`
- `validate.py` 已跳过 `assets/correlation-matrix.json` 的普通 asset 校验，并执行 matrix 专用校验
- schema 增补字段（如 `pii_fields`）时同步设计文档和评估文档

## 参考文件

- `src/dataasset/validate.py`
- `dataasset/schema/*.schema.json`
- `dataasset/README.md`
- `docs_dev/09-data-asset-design.md`
- `docs_dev/history/10-data-asset-design-evaluation.md`（仅作历史背景）
- `src/skills/_shared/data-access/README.md`
