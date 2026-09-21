# 数据源接入 FAQ

**语言：** [English](16-data-source-onboarding-faq.md) | 简体中文（本文）

本页只提供短答案。具体操作按任务查阅：

- 完整接入与启用：[如何配置数据源](03-configure-data-sources.zh-CN.md)
- 字段发现、parser 选择与别名：[日志格式发现](20-log-format-discovery.zh-CN.md)
- 校验与故障排查：[日常运营检查与排错](09-operations-troubleshooting.zh-CN.md)

## 新接一个数据源从哪里开始？

从[完整接入流程](03-configure-data-sources.zh-CN.md#完整接入流程)开始。该流程覆盖资产目录、
凭证、Connector 和 Asset 登记、查询验收、启用及加入 Bundle。未知格式使用 `discovery`，
格式已知但尚未验证时使用 `draft`。

## 应该直接修改 `dataasset/`，还是复制 `dataasset_my/`？

默认直接修改 `dataasset/`。需要本地隔离时才复制为 `dataasset_my/`，并让 CLI、Studio
和智能体统一使用 `DATAASSET_ROOT=dataasset_my`。不要覆盖已有 `dataasset_my/`，也不要
提交客户配置、凭证、私钥或加密凭证文件。

## syslog、auth.log 或 Nginx 需要修改 Python 吗？

不需要。在 Asset 的 `text_parser` 中选择 `syslog_auth` 或 `nginx_combined`。
新文本格式在 `dataasset/parsers/` 增加经过审阅的 JSON parser，再引用其 ID。
普通格式接入不修改 `ssh_fetch.py` 或其他 Skill 运行时代码。

## SLS Asset 是否一定需要 `text_parser`？

不一定。先检查几条真实返回结果：

- 业务字段已经位于顶层：不设置 `text_parser`。
- 一个原始字段中包含完整 JSON：使用 `json_lines` 或 `json_lines2`。
- 返回值仍是一行 syslog 或 Nginx 文本：使用对应 parser。

parser 取决于 Connector 返回形态，而不是生产端最初是否输出 JSON。

## 有没有可复制的厂商样例？

有。`dataasset/onboarding/examples/` 包含基础 SLS/ES/SSH、CloudWatch、云审计/SIEM、
EDR/身份、数仓和通用外部 Connector 示例。写入前先预览：

```bash
.venv/bin/python src/secweaver.py asset apply --output-dir "$DATAASSET_ROOT" \
  -f dataasset/onboarding/examples/vendor-quickstart-cloudwatch.json --dry-run
```

Studio 接入页为 `http://127.0.0.1:8765/onboarding.html`，操作说明见
[UI 图文教程](11-onboarding-ui-walkthrough.zh-CN.md)。

## 如何审阅或回退生成的配置？

按[完整流程](03-configure-data-sources.zh-CN.md#5-预览应用并审阅生成配置)依次使用
`asset apply --dry-run`、`asset diff` 和 `asset apply`。回退前先运行
`asset rollback ... --dry-run`。回退只处理该接入文件生成的对象，不要手工删除生产 active 对象。

## Studio 中没有我的 `connector_type` 怎么办？

可以先在 `dataasset/configure/external-connectors.json` 登记配置型类型并使用通用外部
Connector，或实现并校验 Connector plugin。必须明确运行时支持、query key 和 executor
行为；下拉框出现选项不代表已经具备取数能力。协议见[外部 Connector 执行器](../docs_dev/05-external-connector-executors.zh-CN.md)。

## 源字段和规范字段不一致怎么办？

查询模板继续使用真实源字段，取回后通过 Asset 级 `field_aliases` 映射为规范字段；
不要让 Skill 直接读取厂商私有字段。按[字段发现与归一化模型](20-log-format-discovery.zh-CN.md#字段发现与归一化模型)
完成诊断、parser 选择、审阅后写回和验证。

## 校验失败后怎么处理？

运行 `python3 src/secweaver.py validate --diagnose`，保留完整输出，再按
[校验处理计划](09-operations-troubleshooting.zh-CN.md#把校验结果转成处理计划)处理。
启用前必须修复 P0/P1，并重新执行目录校验和受影响的 Connector/查询测试；空结果不算验收成功。
