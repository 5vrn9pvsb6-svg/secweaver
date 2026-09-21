# UI 贡献与重写指南

**语言：** [English](25-ui-contribution-guide.md) | 简体中文（本文）

SecWeaver 的 UI 不是封闭模块。社区贡献者除了写 connector 插件、外置 connector、Skill 和文档，也可以贡献 UI：改现有页面、新增页面、增强交互，甚至基于同一套后端契约重写整套 UI。

当前开源 UI 位于 [`dataasset-ui/`](../dataasset-ui/README.zh-CN.md)，定位是本地轻量 DataAsset Studio，帮助运营同学不改代码地完成数据源接入、资产编辑、校验和 demo 查看。

## 贡献方式

| 方式 | 适合场景 | 推荐入口 |
|---|---|---|
| 修改现有页面 | 修复布局、文案、表单、校验提示、国际化 | `dataasset-ui/*.html`、`dataasset-ui/*.js`、`dataasset-ui/style.css`、`dataasset-ui/styles/*.css` |
| 新增页面 | 新增 connector 管理、bundle 勾选、network 管理、fetch plan 预览 | 复制现有模块页模式，接入 `shared-nav.js` |
| 扩展本地 API | 页面需要新的读写动作或诊断能力 | `dataasset-ui/server.py`，优先复用 `src/secweaver.py` 和 `src/dataasset/validate.py` |
| 重写 UI | 想用 React/Vue/Svelte/桌面端或企业 Web Console | 保持 DataAsset 文件契约和本地 API 契约，UI 技术栈可替换 |

## 可以自由替换什么？

UI 层可以替换：

- 页面框架和组件库。
- 路由、状态管理、表单结构和视觉设计。
- 图形化能力，如拓扑、correlation matrix、scenario、fetch plan 解释。
- 本地桌面壳或浏览器端实现。

但不要替换这些平台契约：

| 契约 | 原因 |
|---|---|
| `DATAASSET_ROOT` | 默认编辑 `dataasset/`，可切换到 `dataasset_my/` 隔离目录 |
| DataAsset 文件结构 | `assets/`、`connectors/`、`query-templates/`、`hosts/`、`networks/` 是 CLI、Skill 和 validate 的共同输入 |
| `asset apply` 生成逻辑 | 运营配置化的核心能力，应让 UI 调用同一逻辑，避免页面生成另一套格式 |
| `validate.py --json/--diagnose` | UI 的错误提示应和 CLI/CI 门禁一致 |
| `credentials_ref` | UI 只写 `vault://...` 引用，不写明文密钥 |
| 双语和文档入口 | 用户可见文案要同步英文/中文，文档放入 `docs_user/` 或 `docs_dev/` |

## 推荐架构

```text
UI / 新前端
  ├─ 读写 DataAsset 对象
  ├─ 调用 onboarding preview/apply
  ├─ 调用 validate / diagnose
  ├─ 调用 demo / report / connectivity check
  └─ 展示 correlation / scenario / fetch plan 解释

后端契约
  ├─ dataasset-ui/server.py（本地 API）
  ├─ src/secweaver.py asset apply/diff/promote/rollback
  ├─ src/dataasset/validate.py
  ├─ src/dataasset/validate_lib/diagnostics.py
  └─ dataasset/ 目录结构
```

如果你要重写 UI，建议先把 `dataasset-ui/server.py` 当作本地 API 适配层；新前端通过 HTTP 调用它，而不是直接复制 Python 逻辑。后续如果要拆成更正式的 API 服务，也应先保持返回结构兼容。

## 新增页面建议

新增页面时，建议遵循现有 DataAsset Studio 的模块化方式：

1. 新增 `dataasset-ui/<page>.html`。
2. 新增或复用 `<page>.js`。
3. 在 `dataasset-ui/shared-nav.js` 增加导航项。
4. 在 `dataasset-ui/i18n.js` 同步中英文文案。
5. 如果需要后端数据，优先在 `server.py` 增加小而稳定的 API。
6. 在 `tests/test_dataasset_ui.py` 增加 smoke 或 API 测试。

不要在页面里硬编码真实环境信息、私有 endpoint、AK/SK、客户字段或内部截图。

## API 扩展原则

扩展 `dataasset-ui/server.py` 时，优先遵循：

- API 返回 JSON，包含 `ok`、`data` 或 `error`。
- 写操作必须限制在当前 `DATAASSET_ROOT` 内。
- JSON 对象保存（包括旧 API 路由）统一走 `dataasset_ui_services.objects.save_object`，在原子替换前复用 Schema 和 active 引用校验；与 CLI 的资产写入共用 `src/dataasset/registry_write.py` 锁，避免直接 `Path.write_text` 绕过边界。
- 复杂生成逻辑调用 `src/secweaver.py`，不要在 UI 后端重写一套。
- 校验结果使用 `validate.py --json` 或 `--diagnose`。
- 对外部命令传参要白名单化，避免从页面传任意 shell。

后端职责边界：

- `dataasset-ui/server.py`：HTTP 路由、静态文件、JSON 响应。
- `dataasset-ui/dataasset_ui_services/onboarding.py`：数据源接入元数据、预览、写入和错误诊断。
- `dataasset-ui/dataasset_ui_services/credentials.py`：凭证引用、示例 YAML 和加密写入。
- `dataasset-ui/dataasset_ui_services/registry.py` / `topology.py`：资产清单和拓扑。
- `dataasset-ui/dataasset_ui_services/validation.py`：校验运行和诊断卡片。
- `src/dataasset/validate_lib/diagnostics.py`：CLI/UI 共用的校验分类、优先级、负责人和修复步骤。

模块页前端职责边界：

- `dataasset-ui/module-page-config.js`：共享模块定义、默认模板和枚举值。
- `dataasset-ui/module-page-utils.js`：DOM 辅助、API wrapper、详情摘要、弹窗辅助、JSON/YAML 同步辅助。
- `dataasset-ui/module-page-list.js`：可搜索注册表列表、计数、分页和行操作。
- `dataasset-ui/module-page-editors.js`：asset、host、credential、correlation、scenario 的结构化编辑器。
- `dataasset-ui/module-page.js`：页面状态、详情加载/保存/删除、资产动作和初始化。

前端样式职责边界：

- `dataasset-ui/style.css`：稳定样式入口，只保留按顺序导入。
- `dataasset-ui/styles/00-base.css`：设计变量、reset、排版、顶部栏、标题区和共享页面壳。
- `dataasset-ui/styles/01-layout-nav.css`：Workbench 栅格、侧边栏、面板和资源导航。
- `dataasset-ui/styles/02-dashboard-topology.css`：Dashboard 卡片和拓扑可视化。
- `dataasset-ui/styles/03-forms-lists.css`：状态卡片、表单、表格、注册表列表和分页。
- `dataasset-ui/styles/04-detail-editor.css`：详情弹窗、按钮、标签、摘要和结构化编辑器。
- `dataasset-ui/styles/05-correlation-validation.css`：关联解释、建议/报告卡片和校验输出。
- `dataasset-ui/styles/06-onboarding.css`：数据源接入流程、厂商场景、connector catalog 和预览面板。
- `dataasset-ui/styles/07-utilities-responsive.css`：空状态、通用工具类和最后加载的响应式覆盖。

## 重写 UI 的最低验收

如果贡献者提交一套新的 UI，最低应能完成：

- 读取当前 `DATAASSET_ROOT`。
- 查看 assets / connectors / hosts / networks。
- 通过配置预览 `connector + asset + query template` 三件套。
- dry-run 后再 apply。
- 运行 validate 并展示 error/warning/blocking。
- 不写入明文凭证。
- 能通过本地 smoke test 或至少有截图/录屏说明。

## 测试建议

先按[开发环境说明](01-new-contributor-quickstart.zh-CN.md#环境与命令约定)准备工具并运行 `make setup`。从仓库根目录用 `.venv/bin/python` 执行；现有 UI 回归使用标准库 `unittest`，无需额外安装 pytest。

```bash
.venv/bin/python tests/run_tests.py
.venv/bin/python -m unittest tests.test_dataasset_ui
.venv/bin/python src/scripts/check_docs_links.py
```

如果只是改静态 UI，可以至少跑：

```bash
.venv/bin/python dataasset-ui/server.py
```

再访问 `http://127.0.0.1:8765/`，检查页面加载、编辑预览和错误提示；使用合成资产，避免提交真实配置。服务占用当前终端，完成后按 `Ctrl-C` 停止。这是手动页面检查，不代替完整 CI。

## 评审重点

维护者会重点看：

- 是否降低运营同学配置成本。
- 是否复用已有 CLI/validate/onboarding 逻辑。
- 是否保持 `DATAASSET_ROOT` 和私有目录隔离。
- 是否有清晰错误提示。
- 是否避免引入重型依赖或新构建链。
- 是否补了必要文档、截图或测试。

UI 可以重写，但数据资产契约要稳定。这样社区可以自由改体验，平台核心和运营配置仍能保持一致。
