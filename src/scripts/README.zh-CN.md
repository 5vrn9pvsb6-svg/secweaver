# 仓库维护脚本

仓库级维护程序统一放在这里，不再放在项目根目录。

| 脚本 | 用途 |
|---|---|
| `quickstart.py` | 创建当前平台虚拟环境并运行 POSIX/Windows 共用的快速上手流程 |
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

发布扫描要求 `CHANGELOG.md` 的最新发布、`pyproject.toml`、CLI
`--version` 输出和源码 SBOM 根组件使用同一个 Community 版本。Agent
继续使用 `src/tools/secweaver-agent/VERSION` 中的独立版本。

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
