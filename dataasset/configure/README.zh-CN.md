# 平台运行配置（configure）

本目录存放 **运营可编辑、运行时直接加载** 的平台配置 JSON（非 JSON Schema 校验文件）。

| 文件 | 说明 |
|------|------|
| [evidence-minimum-fields.json](evidence-minimum-fields.json) | 各 `asset_type` 最小 Evidence 字段、全局 `field_aliases` |
| [connector-catalog.json](connector-catalog.json) | 内置 connector 单一事实来源：query key、runtime、依赖策略、onboarding 模板和 UI profile |
| [external-connectors.json](external-connectors.json) | 配置型 connector 单一事实来源；用于只改配置新增外部 connector |
| [ip-intel.json](ip-intel.json) | 攻击源 IP 在线属性源配置；`auto` 会先尝试已配置的 VirusTotal，再回退 ipwho.is，最后回退 legacy ip-api.com |
| [text-log-parsers.json](text-log-parsers.json) | 内置 `text_parser` 清单（资产通过 `text_parser` 字段选用） |
| [shared-contracts.json](shared-contracts.json) | 多资产根 JSON 文件的规范归属分类 |

Connector 不再单独维护 UI profile 文件。每个条目的 `onboarding_template` 指向
`dataasset/onboarding/<name>/` 三件套，`onboarding_profile` 同时供 Studio 和 CLI 使用；
插件在自己的 `plugin.json` 中声明同名字段。私有资产目录缺少内置 Catalog 时会读取
仓库自带的公开 Catalog，不再保留容易漂移的 Python 常量副本。

**JSON Schema** 位于 [`../schema/`](../schema/)；`validate.py` 会校验 Connector Catalog、
外部 Connector、onboarding profile 和查询模板。修改后运行 `.venv/bin/python src/secweaver.py validate --strict`。

Connector Catalog 必须声明 `format_version: "2.0"`。运行时会拒绝缺失或不支持的格式，
不会静默加载不完整注册表。旧目录先预览、再写入并严格校验：

```bash
ASSET_ROOT="${DATAASSET_ROOT:-dataasset}"
python3 src/secweaver.py dataasset migrate --root "$ASSET_ROOT" --json
python3 src/secweaver.py dataasset migrate --root "$ASSET_ROOT" --write
DATAASSET_ROOT="$ASSET_ROOT" python3 src/secweaver.py validate --strict
```

迁移会内联旧 profile 并选择 onboarding 三件套。为便于回滚，旧
`onboarding-connector-profiles.json` 不会自动删除；严格校验通过后再人工清理。
Schema 会拒绝 Connector 顶层未知字段和内置类型的未知 `config` 字段；注册的配置型
外部 Connector 与插件仍保留开放 `config`，用于厂商专有字段。

`src/dataasset/validate_roots.py` 和 CI 会执行 `shared-contracts.json`。每个受管 JSON
必须只匹配一种分类：`shared` 在各根目录逐字节一致，`override` 必须说明有意差异原因，
`root_owned` 保留为环境清单。凭证不在该策略范围内，也不会被读取或比较。
