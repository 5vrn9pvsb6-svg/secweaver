# 仓库维护脚本

仓库级维护程序统一放在这里，不再放在项目根目录。

| 脚本 | 用途 |
|---|---|
| `quickstart.py` | 创建 POSIX 虚拟环境、安全初始化所选 Vault 并运行 Linux/macOS/WSL2 快速上手；原生 Windows 会退出并提示安装 WSL2 |
| `release_scan.py` | 扫描私有内容、密钥、占位符和 Community 版本漂移 |
| `check_docs_links.py` | 离线检查 Markdown 本地路径及同页/跨文件章节锚点 |
| `ai_host_setup.py` | 生成不覆盖用户配置、仅路由到 `src/skills` 的本地智能体适配器 |
| `run_ai_showcase.py` | 运行并校验一个零凭证离线 AI Showcase 案例 |
<!-- private-delivery: 以下是策略示例，不是可执行命令 -->
| `check_public_doc_commands.py` | 检查 `src/es-operator/*` 和 `src/server/*` 命令是否带私有交付标记 |

日常优先使用稳定的 Make 入口：

```bash
make release-scan
make docs-check
make quickstart
make ai-setup HOST=all
make ai-setup HOST=codex
make ai-showcase
```

默认 quickstart 的 Vault 步骤需要 SOPS 和 age。共享初始化实现位于
`src/dataasset/credentials/init_vault.py`，`sops-vault.sh init` 也调用它。运行前设置
`DATAASSET_ROOT`；不轮换已有密钥，也不加密示例凭证。仅离线 demo 可用
`make quickstart SKIP_VAULT=1` 显式跳过（直接调用参数：`--skip-vault`）。已有受限策略
可用 `VAULT_CHECK_REF=vault://es/query` 指定匹配的合成探针路径（直接调用参数：
`--vault-check-ref`）。详见 [Vault 生命周期](../../dataasset/credentials/README.zh-CN.md)。

发布扫描要求 `CHANGELOG.md` 的最新发布、`pyproject.toml`、CLI
`--version` 输出和源码 SBOM 根组件使用同一个 Community 版本。Agent
继续使用 `src/tools/secweaver-agent/VERSION` 中的独立版本。

本机 `credentials/.sops.yaml`、`.age/` 和 `credentials/secrets/` 属于运行时材料，
不是公开模板。扫描器拒绝已跟踪/强制加入的对应路径，即使只有占位内容；也会检查
其他文本路径中的 age 私钥特征，并要求配置归档排除规则。导出器另行检查实际 tar 成员。
仅分发 `.sops.yaml.example`；Git 忽略规则保留本机初始化策略。
已跟踪策略需仅取消索引跟踪，操作见 [Vault Git 规则](../../dataasset/credentials/README.zh-CN.md#git-与安全规则)。

Project `wis-log` 和 Logstore `gateway_plugin_log` 是有意公开的接入标识，
允许出现在文档、测试和公开资产配置中。知道资源名称不代表拥有查询权限，Proxy
仍要求获授权的查询凭证。包含这些名称的文件仍需通过密钥、私有路径及其他私有内容
检查。可运行 `python3 -m unittest discover -s tests -p test_release_scan.py`
和 `make release-scan` 验证此策略。

也可以直接运行：

```bash
python3 src/scripts/release_scan.py --json
python3 src/scripts/quickstart.py
python3 src/scripts/check_docs_links.py
python3 src/scripts/check_public_doc_commands.py
python3 src/scripts/ai_host_setup.py --host all
python3 src/scripts/ai_host_setup.py --host codex
python3 src/scripts/run_ai_showcase.py webshell-to-ssh-lateral
```

文档链接检查会识别 GitHub 风格的标题锚点、重复标题的 `-1` 等后缀，以及显式
`<a id="...">` 锚点。公开链接需要在标题改名后继续稳定时，应使用显式锚点。
