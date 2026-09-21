---
name: dataasset-connectivity-check
description: >-
  Checks SecWeaver active data assets for real connectivity and usability. Use
  when the user asks to 探测/检查 active 资产连接性, test connectors, check whether
  dataasset assets can fetch data, verify SLS/SSH/ES/database/API connectors,
  or distinguish config validation from live fetch availability.
---

# Active 数据资产连接性巡检

用于回答：当前 `active` 数据资产是否真的可连接、可取数、可用于 Skill。

本 Skill 补充 `src/dataasset/validate.py`：

- `validate.py`：静态配置、schema、引用、矩阵字段契约。
- 本 Skill：真实凭证解析、connector 连通、query template 渲染、live fetch、是否有可用 evidence。

## 必跑前置

从仓库根目录优先使用虚拟环境：

```bash
.venv/bin/python src/dataasset/validate.py --json --strict --only-active
```

如果用户只要求快速连通性，可以继续运行巡检，即使 validate 有既有 warning；报告中说明这些是静态门禁问题。

## 巡检脚本

主脚本：

```bash
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py
```

常用模式：

```bash
# 快速巡检：active assets，最近 5 分钟，limit=1
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --format markdown

# 标准巡检：最近 24 小时，适合判断是否有数据
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --window-minutes 1440 --limit 10 --format markdown

# 单资产巡检
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --asset-id asset-waf-prod-01 --window-minutes 60

# 只做配置/凭证/模板检查，不 live fetch
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --dry-run

# active asset 引用了 draft connector 时，默认跳过；如需强制探测
.venv/bin/python src/skills/dataasset-connectivity-check/scripts/check.py --include-draft-connectors
```

对于需要主机参数的模板，巡检默认使用资产 `coverage.hosts` 中第一个有效主机；
可通过 `--host` 或 `--host-name` 显式覆盖。每条结果会输出 `probe_host` 和
`probe_host_source`，没有声明主机覆盖范围的资产不再自动注入虚构的 `web-01`。

## 状态语义

连接成功、有数据、足够执行某个技能必须分开判断。live 成功时 `connectable=true`，
`has_data` 根据返回事件设置。空结果的 `usable_for_requested_skill=false`；有事件但未
评估场景覆盖时为 `null`。dry-run 三项均为 `null`，失败时连接性仍未证实。
兼容字段 `usable_for_skill` 现在只表示返回了候选事件，不能作为技能证据充足的结论。
汇总用 `connected_assets_total`、`assets_with_data_total` 分别统计连接和数据，
`skill_readiness=not_evaluated`。成功的空查询不计为连接失败。

| 状态 | 含义 | 是否可用于 Skill |
|---|---|---|
| `OK_CONNECTED_WITH_DATA` | 连接成功且取回数据 | 有候选证据，未评估场景覆盖 |
| `OK_CONNECTED_NO_DATA` | 连接和模板成功，但探测窗口无数据 | 当前无证据，可扩大窗口或修正范围 |
| `FAILED_CONFIG` | 配置错误，如占位符、connector 不存在 | 否 |
| `FAILED_CREDENTIAL` | Vault/SOPS/凭证格式/密钥解析失败 | 否 |
| `FAILED_CONNECTOR` | connector 本身不可达，如 ProjectNotExist、SSH banner | 否 |
| `FAILED_TEMPLATE` | connector 可达但模板语法或查询执行失败 | 否 |
| `FAILED_SCHEMA` | 取回数据无法归一或字段不满足 schema | 否 |
| `FAILED_TEMPLATE_NO_MATCH` | 没有可匹配模板 | 否 |
| `SKIPPED_DRAFT_CONNECTOR` | active asset 引用 draft connector，默认不探测 | 否 |

## 报告要求

对用户输出运营可执行报告：

1. 总览：active 资产数、connector 路径数、连接成功数、有数据资产数、失败数，以及未评估的场景覆盖。
2. 明细：每个 asset/connector 的状态、目标、失败原因。
3. 分层归因：
   - 配置问题：占位符、draft connector、缺 connector。
   - 凭证问题：Vault 解析失败、私钥解析失败、类型不匹配。
   - 连接问题：SLS ProjectNotExist、LogStoreNotExist、SSH banner、网络超时。
   - 模板问题：ParameterInvalid、parse_datetime、语法错误。
   - 数据问题：连接成功但窗口无数据。
4. 给出最小修复建议，不要自动修改文件，除非用户明确要求修复。

## 安全要求

- 永远不要把解密后的 secret 打印给用户。
- 可以输出 `credentials_ref`，不要输出 `access_key_secret`、SSH private key、password、token。
- 对 SLS/ES/DB/API 默认使用小窗口和小 limit，避免重查询。
- SSH 只允许通过现有 connector constraints 执行安全的 grep/tail。

## 推荐判断

- `OK_CONNECTED_NO_DATA` 不是失败；如果用户问“有没有数据”，再扩大窗口。
- active asset 引用 draft connector 应作为运营风险报告。
- 如果 live fetch 失败但 connector ping 成功，优先归因为模板问题。
- 如果 connector 配置里有 `YOUR_*` 或 `REPLACE_ME`，直接判 `FAILED_CONFIG`，无需 live fetch。

## 典型下一步

- `FAILED_CONFIG`：修 connector JSON，占位符替换为真实 project/logstore/host。
- `FAILED_TEMPLATE`：修 `dataasset/query-templates/templates.json`。
- `FAILED_CREDENTIAL`：用 `src/dataasset/credentials/sops-vault.sh get <ref>` 脱敏验证，再编辑 Vault。
- `FAILED_CONNECTOR`：排查云服务、网络、安全组、SSH 服务或 endpoint。
- `OK_CONNECTED_NO_DATA`：用 `--window-minutes 1440` 或业务参数重跑。
