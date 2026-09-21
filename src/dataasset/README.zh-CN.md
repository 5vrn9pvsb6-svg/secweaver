# DataAsset 运行程序

本目录统一保存 DataAsset 运行程序。`dataasset/` 和运营侧自有的
`dataasset_my/` 只保存配置、Schema、文档与样本数据，不再复制程序。

| 程序 | 职责 |
|---|---|
| `validate.py` | 校验目录结构、Schema、引用关系和“资产目录无程序”边界 |
| `validate_roots.py` | 校验所有已检入资产根目录，并检查共享契约漂移 |
| `sync_shared_contracts.py` | 预览或同步公开根定义的共享契约，不处理凭证和环境清单 |
| `config_migration.py` | 预览或原子写入 Connector Catalog 格式迁移 |
| `catalog_sync.py` | 生成并比对 `catalog.json` |
| `test_connector.py` | 渲染查询计划并测试 Connector |
| `promote_after_connectivity.py` | 连通性通过后提升 draft 资产 |
| `build_field_reference.py` | 生成字段参考样例 |
| `credentials/` | 解析和管理 SOPS 加密的 `vault://` 凭证 |
| `plugins/connectors/` | 内置 Connector 插件代码和契约示例 |
| `plugin_contract.py` | 插件发现、CLI 校验和运行时共用的 manifest、路径、超时及 stdio-json 响应契约；不依赖 Skill 或厂商 SDK |
| `validate_lib/connector_contracts.py` | Connector 归属、onboarding 三件套和 UI profile 的跨文件约束 |
| `validate_lib/inventory_contracts.py` | Host/Network 的 CIDR、引用与暴露面语义校验 |
| `validate_lib/runtime_readiness.py` | 不解密凭证、不联网的 Bundle 到凭证静态执行就绪检查 |

切换资产目录时不需要复制程序：

```bash
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --json
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --runtime-ready --bundle <bundle_id> --json
DATAASSET_ROOT=dataasset_my python3 src/dataasset/test_connector.py <asset_id> --by-asset --plan
DATAASSET_ROOT=dataasset_my src/dataasset/credentials/sops-vault.sh list

# 同时校验公开目录和本地 overlay。
.venv/bin/python src/dataasset/validate_roots.py --strict

# 先检查共享契约漂移；确认计划后再使用 --write。
.venv/bin/python src/dataasset/sync_shared_contracts.py --check
.venv/bin/python src/dataasset/sync_shared_contracts.py --write

# 先预览；人工复核 JSON 计划后再添加 --write。
python3 src/secweaver.py dataasset migrate --root dataasset_my --json
```

Connector 插件代码使用独立根目录。仓库内示例放在本目录；运营侧自有插件可
独立指定：

```bash
SECWEAVER_PLUGIN_ROOT=/opt/secweaver/connectors python3 src/secweaver.py connector catalog --json
```

`src/dataasset/validate.py` 会拒绝出现在目标资产目录中的 Python、Shell、
JavaScript、编译程序和带可执行权限的文件。
`validate(dataasset_root)` 从本次传入目录派生 Schema 与凭证路径，不会改写模块级
`DATAASSET_ROOT`；同一进程中的运行时模块仍使用启动时解析的全局目录。
Connector Catalog 使用格式版本 `2.0`；运行时遇到不支持的格式会直接失败，必须先迁移。
`validate_roots.py` 执行 `dataasset/configure/shared-contracts.json` 的归属分类，只对
`shared` 文件做逐字节比较；`override` 和 `root_owned` 必须显式分类，凭证文件不在比较范围。
Connector 结构和必填组合以共享的 `schema/data-connector.schema.json` 为唯一校验契约；
Catalog 保存运行能力、依赖与接入 UI 元数据。凭证状态只允许 `active` 或 `disabled`，
未知状态会被校验器、Studio 和运行时拒绝。

## 真实数据与发布边界

ES 默认校验证书，支持私有 CA；查询不完整状态会进入取数摘要和报告。
自动证据 ID 已升级为 v2；源日志敏感字段仍需显式配置 masking。
发布检查、兼容性、迁移参数与脱敏示例见[使用说明](../../docs_user/community-release-and-data-safety.zh-CN.md)。
