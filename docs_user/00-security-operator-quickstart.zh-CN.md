# 00. 安全运营 10 分钟快速上手

**语言：** [English](00-security-operator-quickstart.md) | 简体中文（本文）

先用合成日志完成一次 AI 调查：看到攻击入口、主机执行、横向移动和证据缺口。
不需要 ES、SLS、生产凭证或 Agent 安装。真实数据接入是体验完成后的可选步骤。首次只完成下方 1–3 步；理念、字段配置和部署手册可以之后按需阅读。

> **离线说明：**“离线”表示案例取数不访问 ES、SLS 等真实数据源；首次安装依赖和调用在线模型仍可能需要网络。

## 开始前

准备带 `venv`、`pip` 的 Python 3.10+、Make，以及能读取本地仓库、执行命令的智能体。
Linux/macOS 使用 POSIX 终端；Windows 用户必须使用 WSL2，Community 客户端不支持原生
Windows Python 或 PowerShell。智能体需要在同一个 POSIX/WSL2 环境中读取仓库、执行
`.venv/bin/python`，并写入 `outputs/ai-showcase/`；当前工作目录必须是仓库根目录。
完整开发与发布门禁仍以 Ubuntu 为基线。
十分钟是依赖和智能体就绪后的体验时间，首次环境准备另计。

## 1. 初始化

先下载并解压项目，或克隆仓库。在终端进入包含 `README.zh-CN.md`、`Makefile` 和 `src/` 的那一层目录，不要进入 `docs_user/`。

### Windows：先安装 WSL2

Windows 尚未安装 WSL2 时，打开管理员 Windows Terminal 或命令提示符执行：

```text
wsl --install
```

系统提示时重启，然后启动 Ubuntu 并完成首次账号初始化。WSL 已存在但没有 Ubuntu 时，
执行 `wsl --install -d Ubuntu`。在 Windows 侧执行 `wsl --list --verbose` 检查发行版版本；
Ubuntu 显示版本 1 时，先执行 `wsl --set-version Ubuntu 2`。旧版 Windows 或安装失败时查阅
[微软 WSL 安装指南](https://learn.microsoft.com/windows/wsl/install)。下面的 SecWeaver
命令都在 Ubuntu 内执行，不在原生 Windows shell 中执行。

进入 Ubuntu 后安装依赖：

```bash
sudo apt update
sudo apt install -y git make python3 python3-venv python3-pip
```

尽量把仓库放在 WSL 文件系统中，例如 `~/src/secweaver-community`，不要优先放在
`/mnt/c/...`。

### Linux、macOS 或 WSL2

从仓库根目录检查工具并初始化：

```bash
python3 --version
make --version
```

Python 应为 3.10 或更高版本，Make 应能显示版本。若提示找不到命令，先安装对应工具或请管理员协助，再继续：

```bash
make quickstart
```

这会在 WSL Linux 用户空间中验证 Python 客户端、DataAsset、Skill、离线案例和
SLS Proxy 客户端流程，但不会采集 Windows 宿主机的 Event Log、Security 4688、Sysmon
或 Windows 服务数据。需要这些数据时，应在原生 Windows 主机上安装并运行 Windows
Agent。WSL2 复用由 Ubuntu 公共 CI 持续验证的 Linux/POSIX 流程；当前没有独立 WSL2 runner。

成功后会创建 `.venv`、校验 DataAsset、运行四个离线 demo，并生成五种智能体的薄适配器。
适配器只引用 `src/skills/`，不复制 Skill。不要把“适配器生成成功”当成 AI 已完成分析。
安装依赖前，启动器会检查选定解释器和已有虚拟环境；任一版本低于 Python 3.10，
初始化都会输出处理提示并退出。直接在原生 Windows 调用会退出并提示安装 WSL2。
终端出现 `SecWeaver quickstart completed.` 表示初始化完成。接着在智能体中打开同一个项目目录，执行第 2 步。

## 2. 在智能体中运行案例

在智能体（Codex、Cursor、Claude Code、OpenClaw 或 WorkBuddy）中打开当前仓库，输入：

```text
运行 SecWeaver 离线案例
```

默认运行全部 27 个可执行评估案例。智能体应读取对应 Skill，为每个成功案例生成报告，
并在 `outputs/ai-showcase/suite-summary.md` 汇总数量、结论与失败项。
下方以 `webshell-to-ssh-lateral` 的结果为例说明。
智能体未识别入口时，查看 [智能体配置与排错](38-ai-agent-host-setup.zh-CN.md)。

需要指定其他案例时，在提示词后附上案例 ID，例如：

```text
运行 SecWeaver 离线案例 false-positive-parameter，解释为什么不应升级处置。
```

## 3. 阅读结果

在智能体的文件列表中展开 `outputs/ai-showcase/`，打开：

- `outputs/ai-showcase/webshell-to-ssh-lateral.json`：脚本生成的结构化结果。
- `outputs/ai-showcase/webshell-to-ssh-lateral.md`：智能体按 Skill 生成的调查报告；文件不存在时，使用下方补充提示词。

这个固定样例的 JSON 预期为 `overall_verdict=confirmed_intrusion_chain`、`blocked=false`。

### 预期报告示例（节选）

下面是依据[公开合成输入](../examples/traceability/s1-web-shell-to-ssh-lateral.json)和当前分析结果编写的阅读示例，展示你应能读懂的内容；它不是完整报告模板。智能体措辞和排版可以不同，关键判断必须有证据支持。

> **结论：** 本合成案例支持 WebShell 控制、主机执行和 SSH 横向移动链路。`web-01`（`10.0.1.5`）存在命令执行，随后从该主机成功登录 `db-01` 和 `app-02`。最初如何入侵并植入 WebShell，仍未证实。

| 调查内容 | 报告应解释的事实 | 可核对的证据 ID |
|---|---|---|
| WEB 与主机行为 | `/api/upload.php` 请求后，web-01 出现 `whoami` 执行及 `shell.php` 创建 | `web-001`、`exec-001`、`file-001` |
| 工具下载与执行 | web-01 下载 `/tmp/sshscan`，赋予执行权限，再对内网 SSH 地址段运行该工具 | `exec-002`、`exec-003`、`exec-004` |
| SSH 横向到 db-01 | 来源为 `10.0.1.5`，SSH 日志记录 root 登录成功，防火墙记录对应连接 | `ssh-002`、`fw-001` |
| SSH 横向到 app-02 | 同一来源以 deploy 账号登录成功，并有对应连接记录 | `ssh-003`、`fw-002` |

> **证据边界：** 单独的 HTTP 200 或 WAF 命中不能证明入侵成功。样例没有提供横向目标登录后的命令证据，不能据此断言目标上执行了什么或发生了数据窃取。上述结论仅针对合成样例，不代表你的生产环境。

### 怎样判断体验成功

- [ ] 已找到 JSON，且上述两个预期字段一致。
- [ ] 已打开 Markdown 报告，能读出主机执行和两条 SSH 横向路径，并知道最初入侵途径仍不确定。
- [ ] 能把报告中的至少两个证据 ID 对应到输入文件中的事件；报告说明了数据缺口和结论边界。

原始指令默认已经包含可读报告，不需要追加“形成可读的报告”。只有 JSON 就结束，
说明任务尚未完成。运行器自动生成 Markdown 结构化结果报告，智能体须结合输入证据
继续完成对应 Skill 的报告，包含证据统计、调查路径、时间线、影响范围及缺口，
不要只复制上方节选。

没有智能体时，可先查看[样例报告](../examples/reports/README.zh-CN.md)，或运行：

```bash
make ai-showcase
```

该命令默认生成 JSON、逐例可读 Markdown 和可读汇总。全部当前案例及明确选例方式见
[离线 AI Showcase](../examples/ai-showcase/README.zh-CN.md)。

## 常见问题

| 现象 | 下一步 |
|---|---|
| `make` 提示找不到 Makefile 或 quickstart 目标 | 回到包含 `Makefile` 的项目根目录 |
| Windows 没有 WSL2 | 在管理员 Windows Terminal 或命令提示符执行 `wsl --install`，重启后启动 Ubuntu |
| WSL 已存在但没有 Ubuntu | 执行 `wsl --install -d Ubuntu`，启动 Ubuntu 并完成首次初始化 |
| Ubuntu 使用 WSL1 | 在 Windows 侧执行 `wsl --set-version Ubuntu 2`，完成后回到 Ubuntu 重试 |
| quickstart 提示不支持原生 Windows | 在 Ubuntu WSL2 shell 中运行，不要在原生 Windows shell 中运行 |
| quickstart 提示 Python 低于 3.10 后退出 | 删除旧 `.venv`，安装 Python 3.10+，再执行 `make quickstart` |
| 仓库位于 `/mnt/c/...` 且命令较慢 | 在 WSL 内把仓库克隆或移动到 `~/src/secweaver-community` |
| 报告中的主机显示为 IP | 对照样例映射：web-01=`10.0.1.5`，db-01=`10.0.2.10`，app-02=`10.0.2.20` |
| 依赖安装失败 | 检查 Python 版本和包下载网络，再执行 `make quickstart` |
| 适配器提示拒绝覆盖 | 备份或手动合并已有智能体配置，不删除用户自己的规则 |
| 智能体找不到案例文件 | 确认智能体打开的是仓库根目录，并允许本地读取和命令执行 |
| 脚本缺依赖 | 使用快速上手入口；直接调用时使用 `.venv/bin/python` |
| AI 只复述 JSON | 任务尚未完成；智能体应自动遵循对应 Skill 补齐报告，无须用户重复提出报告要求 |

## 可选：接真实数据

| 需求 | 继续阅读 |
|---|---|
| 使用推荐的 SaaS 查询服务 | [SLS Proxy 接入](30-sls-proxy-onboarding.zh-CN.md) |
| 安装 Agent 并上传到 SaaS | [Data Cloud 客户快速上手](29-secweaver-data-system-quickstart.zh-CN.md) |
| 把 Agent 日志写入自己的 ES | [自建 ES 完整指南](../src/tools/secweaver-agent/elasticsearch/README.zh-CN.md) |
| 接入已有 ES、SLS 或其他日志 | [数据源配置](03-configure-data-sources.zh-CN.md) |
| 熟悉 DataAsset Studio | [UI 接入教程](11-onboarding-ui-walkthrough.zh-CN.md) |

执行 `make ui`，访问 `http://127.0.0.1:8765/`，默认查看和编辑 `dataasset/`。
Studio 会持续占用当前终端；停止服务请按 `Ctrl-C`。如需隔离配置，可按接入指南
复制到 `dataasset_my/` 并设置 `DATAASSET_ROOT`。真实凭证与客户配置不要提交 Git。
Studio 是配置页面，不是 AI 分析聊天页。
更多命令见 [CLI 参考](13-SecWeaver-CLI.zh-CN.md)，不必为首次体验先阅读配置手册。
