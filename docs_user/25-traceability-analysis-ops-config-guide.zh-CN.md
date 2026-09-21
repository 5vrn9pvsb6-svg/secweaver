# 溯源分析运营配置指南

**语言：** [English](25-traceability-analysis-ops-config-guide.md) | 简体中文（本文）

本文说明如何在不修改调查引擎的前提下，通过 Community 版公开配置适配新的安全数据环境。范围仅包括 DataAsset、trace profile、关联矩阵、启发式规则和调查场景；本文不展开厂商适配代码；公开实现见 [`source_adapters/`](../src/skills/traceability-analysis/scripts/source_adapters/)。私有部署 overlay 不属于 Community 归档。

## 配置边界

当新数据源属于已有证据类型，只是字段名、查询模板、阈值或关联关系不同，应优先修改配置。

| 变更内容 | 公开配置入口 | 是否需要改代码 |
|---|---|---|
| Connector endpoint 与鉴权引用 | `dataasset/connectors/*.json` | 否 |
| 资产字段与查询模板 | `dataasset/assets/*.json` | 否 |
| 厂商字段映射到标准字段 | `dataasset/trace-profiles/*.json` 和资产 `field_aliases` | 否 |
| Join 键与时间窗口 | `dataasset/assets/correlation-matrix.json` | 否 |
| 调查阈值与叙事规则 | `src/skills/traceability-analysis/heuristic-rules.json` | 否 |
| 新证据类型或新关联算子 | 引擎与 Schema 实现 | 是 |

`dataasset/` 是数据契约的权威来源。Skill 配置不应重复保存 Connector 凭证或物理数据源路由。

## 推荐操作流程

1. 从 `dataasset/` 中复制语义最接近的 Connector 和资产示例。
2. 为每个对象分配新的全局唯一 ID，不要把示例 ID 直接用于生产资产。
3. 使用 `field_aliases` 或 trace profile 将源字段映射成 SecWeaver 标准字段。
4. 为资产选择或增加支持调查参数的查询模板。
5. 只配置现有证据能够支撑的关联规则和启发式规则。
6. 字段、索引和样例查询未验证前，将资产保持为 `draft`。
7. 运行 `make validate` 和相关 Skill 测试。
8. 真实查询能够返回时间、主机和身份字段正确的标准化证据后，再将资产改为 `active`。

## Trace profile 示例

从证据语义相同的 profile 开始，只调整字段别名和数据源特有解析，保持标准输出字段稳定。

```json
{
  "asset_id": "asset-example-host-exec",
  "asset_type": "host_exec",
  "trace_profile_id": "secweaver-host-exec",
  "field_aliases": {
    "source_host": "host",
    "source_ip": "host_ip",
    "process_command": "command"
  }
}
```

不要在资产文件中复制真实凭证。Connector 只引用 credential ID，Secret 应保存在配置的凭证存储中。

## 验证方法

在仓库根目录运行配置校验和回归测试（`make validate` 会先准备 Python 依赖）：

```bash
make validate
make test
```

接入新数据源时，还应对资产使用的每个查询模板执行一次有范围限制的真实查询，并确认：

- 时间戳按预期时区和格式解析；
- 主机、IP、用户、进程和事件标识能够稳定归一化；
- 关联键不会连接无关实体；
- 无数据或数据不可用会报告为数据缺口，而不是直接判定安全；
- 查询不能访问 Connector 预期范围之外的数据。

## 相关文档

- [配置数据源](03-configure-data-sources.zh-CN.md)
- [溯源分析](18-traceability-analysis.zh-CN.md)
- [跨源字段关联](21-cross-source-field-correlation.zh-CN.md)
- [Trace Profile 设计](../docs_dev/21-trace-profile-design.zh-CN.md)
- [Community 资产与 Connector 贡献指南](../docs_dev/03-community-add-asset-connector.zh-CN.md)
