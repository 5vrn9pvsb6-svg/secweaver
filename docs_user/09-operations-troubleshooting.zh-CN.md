# 09. 日常运营检查与排错

**语言：** [English](09-operations-troubleshooting.md) | 简体中文（本文）

本文说明日常维护 `dataasset/` 时应该检查什么，以及遇到常见问题如何排查。

---

## 每次改完配置后先做什么？

建议第一步运行校验：

```bash
.venv/bin/python src/dataasset/validate.py
```

如果项目没有虚拟环境，可以尝试：

```bash
python3 src/dataasset/validate.py
```

如果输出 JSON 更方便处理：

```bash
.venv/bin/python src/dataasset/validate.py --json
```

如果希望直接看到原因、修复步骤和关联文档：

```bash
.venv/bin/python src/dataasset/validate.py --diagnose
```

也可以从统一 CLI 调用：

```bash
python3 src/secweaver.py validate --diagnose
```

---

## 如何切换到私有资产目录？

如果你把真实资产放在 `dataasset_my/`，不要直接覆盖发布目录 `dataasset/`。运营同学可以用 `DATAASSET_ROOT` 临时指定资产根目录：

```bash
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --diagnose
```

启动 DataAsset Studio 时同样适用：

```bash
DATAASSET_ROOT=dataasset_my DATAASSET_UI_PORT=8765 python3 dataasset-ui/server.py
```

做连通性或 dry-run 时也要带上同一个环境变量，避免误测到默认 `dataasset/`：

```bash
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py asset test YOUR_ASSET_ID --dry-run
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py asset apply -f dataasset_my/onboarding/examples/data-sources.sample.json --dry-run
```

判断当前用的是哪个目录，可以看 UI 启动参数，或在命令前显式加 `DATAASSET_ROOT=...`。团队约定上建议：

- `dataasset/`：默认本地配置目录；只有脱敏的公共示例可提交到开源仓库。
- `dataasset_my/`：本地或私有真实资产目录，不提交到开源仓库。

---

## validate 会检查什么？

通常会检查：

- JSON 文件格式是否正确。
- 文件名和 ID 是否一致。
- Asset 引用的 Connector 是否存在。
- Connector 引用的凭证格式是否合理。
- Asset 引用的 Query Template 是否存在。
- 字段是否满足最小 evidence 要求。
- Host / Network / `coverage.hosts` 是否一致。
- Host IP 是否落在 Network CIDR 内。
- Scenario Pattern 引用的 Bundle 是否存在。
- Correlation Matrix 的 Join 字段是否可达。
- Correlation Matrix 的 `fetch_plan` 是否能解析到模板和参数。
- catalog 是否和目录内容一致。

---

## 如何理解 error、warning、blocking？

| 类型 | 含义 | 建议动作 |
|---|---|---|
| `blocking` | 会阻断正式使用的问题 | 必须修 |
| `error` | 明确错误，可能导致取数或关联失败 | 必须修 |
| `warning` | 风险或不推荐配置 | 评估后修或记录原因 |

一般建议：

```text
blocking = 0
error = 0
warning 尽量少，且每条都知道原因
```

---

## 如何使用配置错误诊断？

`--diagnose` 会把每个问题补充为运营可读的诊断卡片，通常包含：

- `category`：问题类型，例如 `credential`、`connector_config`、`field_contract`、`correlation_matrix`、`status_lifecycle`。
- `root_cause`：为什么会出现这个问题。
- `suggested_fix`：最直接的修复建议。
- `fix_steps`：建议按顺序执行的操作。
- `docs`：相关文档路径。

如果使用 dataasset-ui，打开校验页面也能看到同样的诊断卡片。接入页面预览或应用失败时，UI 会优先展示 JSON 语法、字段拼写、覆盖冲突、缺模板、未知 connector 类型等建议。

---

## 把校验结果转成处理计划

不要只看到一行 `ERROR` 或 `WARN` 就盲目修改 JSON。保留完整输出，确认受影响对象和
运行路径，指定责任人，做最小修改，再重新执行能够证明该问题已解决的检查。

```text
1. 运行 validate 并保留完整输出
2. 按 blocking / error / warning 和受影响对象分组
3. 使用 --diagnose 确认根因
4. 指定运营、高级运营、开发或安全审阅责任人
5. 执行最小配置或代码修改
6. 重新运行目录校验和受影响的 Connector/查询检查
7. 只有验收查询通过后才晋升 active
```

按以下优先级处理：

| 优先级 | 常见问题 | 责任人 | 对发布的影响 |
|---|---|---|---|
| P0 | Schema 失败、active 对象引用缺失或 draft 依赖、active Connector 缺少凭证引用 | 运营先处理；validator 或 Schema 错误时转开发 | 阻断启用或发布 |
| P1 | 别名缺失、Join 字段不可达、coverage host 不是 IP、模板与 Connector 不匹配 | 高级运营或安全工程师 | 通常阻断可信调查 |
| P2 | draft 元数据不完整或文档 warning | 运营待办 | 不一定阻断 |

运营通常可以直接修复接入期对象状态、ID 和引用、经样本验证的 Asset 级别名、
`coverage.hosts` 和 Vault 引用。以下情况需要升级处理：

| 需要升级的情况 | 原因 |
|---|---|
| 需要新增 Connector 运行时或内置 parser | 会改变可执行取数或解析行为 |
| 需要增加复杂 Correlation Matrix Join | 可能改变调查结论 |
| `validate.py` 疑似误报 | 校验逻辑或 Schema 可能需要改代码 |
| 生产 SQL、ES DSL 或 SLS 查询需要结构性调整 | 需要审阅安全性、性能和索引字段行为 |

修复后执行能够证明受影响行为的检查，并完成最终目录校验。典型接入复验流程：

```bash
.venv/bin/python src/dataasset/validate.py --sync-catalog
.venv/bin/python src/dataasset/test_connector.py YOUR_ASSET_ID --by-asset --dry-run
.venv/bin/python src/dataasset/test_connector.py YOUR_ASSET_ID --by-asset \
  --params '{"time_start":"2026-09-08T00:00:00Z","time_end":"2026-09-08T00:05:00Z","src_ip":"203.0.113.10"}'
```

真实查询必须使用授权范围内的已知事件和真实时间窗；空结果不能证明数据源可用。
字段类问题统一见[日志格式发现](20-log-format-discovery.zh-CN.md#字段发现与归一化模型)，
完整状态生命周期统一见[如何配置数据源](03-configure-data-sources.zh-CN.md#完整接入流程)。

---

## 常见问题一：Asset 引用的 Connector 不存在

现象：

```text
asset xxx 引用了不存在的 connector_id
```

排查：

1. 检查 `dataasset/assets/asset-xxx.json` 的 `connector_id`。
2. 检查 `dataasset/connectors/` 下是否有对应文件。
3. 如果只是参考模板，应放在 `dataasset/examples/connectors/`，不要放在正式 `connectors/`。
4. 如果 connector 是正式取数路径，应放回 `dataasset/connectors/` 并确保 `connector_id` 一致。

说明：未被任何 asset 引用的 connector 不再作为 warning。它可能是备用 connector、跳板 connector、接入中 connector 或运营库存；validate 只阻断“asset 引用不存在的 connector”。

---

## 常见问题二：Query Template 不存在或不匹配

现象：

```text
query_template_id 不存在
```

或取数时查不到数据。

排查：

1. Asset 中的 `query_template_ids` 是否存在。
2. Template 是否支持该 `connector_type`。
3. Template 所需参数是否都能提供。
4. 查询语句中的字段名是否和日志源一致。

---

## 常见问题三：字段关联不上

现象：

```text
Join 没有命中
data_gaps 出现 no_match
```

可能原因：

1. 两个数据源字段名不同，但没有配置 `field_aliases`。
2. 某个 Asset 的 `schema.fields` 缺少关键字段。
3. 时间窗太小。
4. 查询结果本身没有相关事件。
5. Host 名和 IP 没有通过资产清单或 Host 注册表关联起来。

处理建议：

- 检查 `schema.fields` 是否包含 Join 所需字段。
- 检查 `field_aliases` 是否覆盖源字段。
- 检查 `correlation-matrix.json` 中 Join 字段。
- 适当扩大时间范围。
- 补充 `asset_inventory` 或 Host 配置。

---

## 常见问题四：Host 和 Network 不一致

现象：

```text
host_ip 不在 network.cidr 中
host.zone 与 network.zone 不一致
```

排查：

1. Host 的 `host_ip` 是否正确。
2. Host 的 `network_id` 是否正确。
3. Network 的 `cidr` 是否正确。
4. Host 和 Network 的 `zone` 是否应该一致。

修复原则：

- 如果 IP 填错，改 Host。
- 如果网段填错，改 Network。
- 如果主机确实跨多个网段，补充 `interfaces`。

---

## 常见问题五：AI 输出“证据不足”

这不一定是智能体的问题。

可能原因：

1. 数据源没有接入。
2. 数据源是 `draft`，未正式启用。
3. 查询模板没查到数据。
4. 时间窗不对。
5. 字段映射不对。
6. Join 规则没有命中。
7. 真实环境确实没有相关行为。

建议按这个顺序排查：

```text
Bundle 是否包含相关 Asset？
Asset 是否 active？
Connector 是否可用？
Query Template 是否能查到原始数据？
字段是否归一？
Join 是否命中？
时间窗是否合理？
```

---

## 常见问题六：大模型结论不稳定

如果同一个问题多次输出差异较大，通常说明约束不足。

建议检查：

1. 是否有明确 Scenario Pattern。
2. Scenario Pattern 是否指定了推荐链路。
3. Correlation Matrix 是否定义了 Join 规则。
4. 输出是否基于 `join_edges`。
5. 是否把数据缺口明确传给模型。

原则：

```text
调查路径越配置化，模型输出越稳定。
```

---

## 日常健康检查建议

建议定期检查：

- validate 是否通过。
- active 资产数量是否符合预期。
- draft 资产是否长期未上线。
- discovery 资产是否需要继续格式发现。
- connector 是否有未引用或废弃项。
- Bundle 是否覆盖关键场景。
- S1-S8 每个场景是否至少有最小数据源。
- 查询模板是否还能正常返回数据。

---

## 数据源上线前检查清单

- [ ] Connector 不含明文密钥。
- [ ] Credentials 已正确配置。
- [ ] Connector dry-run 通过。
- [ ] Asset 字段完整。
- [ ] Query Template 可用。
- [ ] 加入正确 Bundle。
- [ ] validate 通过。
- [ ] 状态从 `draft` 改为 `active`。
- [ ] 至少完成一次真实或样例调查验证。

---

## 下一步

继续阅读：[10. 常见问题 FAQ](10-faq.zh-CN.md)
