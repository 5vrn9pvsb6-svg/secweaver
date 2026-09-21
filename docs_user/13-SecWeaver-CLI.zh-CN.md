# SecWeaver CLI

`secweaver` 是 SecWeaver 的本地轻量 CLI，用于开源用户快速校验数据资产、运行离线 demo，并封装基础 Skill 脚本。

**语言：** [English](13-SecWeaver-CLI.md) | 简体中文（本文）

---

## 一键体验

开源用户第一次 clone 后，推荐直接运行：

```bash
make quickstart
```

这会自动创建 `.venv`、安装依赖、执行数据资产校验，并运行全部离线 demo。成功后可以查看：

```text
examples/reports/README.md
examples/reports/demo-*-output.json
```

常用 Make 命令：

```bash
make help
make validate
make validate-all-roots
make demo
make demo-alert
make demo-traceability
make ui
```

---

## 准备环境

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-data-access.txt
```

查看帮助：

```bash
python3 src/secweaver.py --help
python3 src/secweaver.py list
```

---

## 数据资产校验

```bash
python3 src/secweaver.py validate
```

严格模式：

```bash
python3 src/secweaver.py validate --strict
```

输出 JSON：

```bash
python3 src/secweaver.py validate --json
```

静态检查指定资产包是否具备运行条件：

```bash
python3 src/secweaver.py validate --runtime-ready \
  --bundle bundle-incident-trace-default --json
```

`--runtime-ready` 会遍历 Bundle、Asset、Connector、agent-stream 下游 Connector、
占位值和凭证密文引用，并合并依赖对象的基础 Schema/配置错误，但不会解密凭证或访问后端。
JSON 中 `registry_valid` 表示整个资产根基础校验是否通过，Bundle 的 `status` 表示该 Bundle
依赖图是否就绪，`ready_for_execution` 只有两者同时满足才为 `true`。返回 0 只表示本地执行链已经就绪；
下一步仍需运行 `dataasset-connectivity-check`，验证真实连通性与数据存在性。可重复
`--bundle` 检查多个资产包；省略时检查全部 active Bundle。

同步 `dataasset/catalog.json`：

```bash
python3 src/secweaver.py catalog sync
```

`make validate-all-roots` 会校验仓库中所有 `dataasset*` 资产根，并执行
`dataasset/configure/shared-contracts.json`：`shared` 文件必须逐字节一致，有原因说明的
`override` 文件允许不同，`root_owned` 环境清单由各资产根独立维护。

共享契约漂移先检查、后同步；同步操作只复制 `shared` 文件，不读取凭证或覆盖
`root_owned` 环境清单：

```bash
python3 src/dataasset/sync_shared_contracts.py --check
python3 src/dataasset/sync_shared_contracts.py --write
```

Catalog 格式迁移默认只预览，显式添加 `--write` 才写入：

```bash
python3 src/secweaver.py dataasset migrate --root dataasset_my --json
python3 src/secweaver.py dataasset migrate --root dataasset_my --write
DATAASSET_ROOT=dataasset_my python3 src/secweaver.py validate --strict
```

---

## 运行离线 demo

一键运行全部 demo，并生成 `examples/reports/` 下的完整样例输出：

```bash
python3 src/secweaver.py demo all
```

也可以单独运行某个 demo：

```bash
python3 src/secweaver.py demo completeness
python3 src/secweaver.py demo alert
python3 src/secweaver.py demo traceability
python3 src/secweaver.py demo risk
```

指定 `demo all` 的输出目录：

```bash
python3 src/secweaver.py demo all -o /tmp/secweaver-reports
```

报告说明见：[`examples/reports/README.md`](../examples/reports/README.md)。

对应样例输入：

| Demo | 输入文件 |
|---|---|
| `completeness` | `examples/data-source-completeness/s1-full-traceable.json` |
| `alert` | `examples/alert-confirmation/s4-webshell-attack-success.json` |
| `traceability` | `examples/traceability/s1-web-shell-to-ssh-lateral.json` |
| `risk` | `examples/risk-identification/s5-curl-download-exec-p0.json` |

将输出写入文件：

```bash
python3 src/secweaver.py demo alert -o /tmp/secweaver-alert-result.json
```

---

## 生成 Markdown 调查报告

转换单个 JSON：

```bash
python3 src/secweaver.py report markdown \
  -i examples/reports/demo-alert-output.json \
  -o /tmp/alert-report.md
```

一键转换全部 demo 输出，并生成调查链路汇总报告：

```bash
python3 src/secweaver.py report markdown --demo all --bundle
make reports
```

默认输出到 `examples/reports/`：

- `demo-*-output.md`
- `investigation-report.md`

---

## 数据资产操作

运营配置化接入：

```bash
python3 src/secweaver.py asset apply \
  -f dataasset/onboarding/examples/data-sources.sample.json \
  --dry-run
python3 src/secweaver.py asset init --connector-type sls --asset-type waf_alert --name demo-waf
```

连通性测试：

```bash
python3 src/secweaver.py asset test <asset_id>
python3 src/secweaver.py asset test <asset_id> --plan
python3 src/secweaver.py asset test <asset_id> --dry-run
```

生产 Skill 只查询 `active` Asset 和 `active` Connector。测试、格式发现、连通性检查和
提升命令可在接入阶段测试 `draft/discovery`；`disabled` 永远不会执行查询。

日志格式发现（封装 `log-format-discovery` 的 `discover.py`）：

```bash
# 使用离线样本（推荐开源体验）
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample

# 未提供样本时，先拉取在线样例再发现
python3 src/secweaver.py asset discover-format <discovery-asset-id>
```

查看 discovery 队列、导出报告或生成 LLM prompt 等高级参数，仍可直接调用底层脚本：

```bash
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample \
  --pretty -o /tmp/discovery-report.json --prompt /tmp/prompt.md
```

样例输入见：[`examples/log-format-discovery/`](../examples/log-format-discovery/)。

---

## 运行指定 Skill

```bash
python3 src/secweaver.py skill alert-confirmation \
  -i examples/alert-confirmation/s4-webshell-attack-success.json

python3 src/secweaver.py skill traceability-analysis \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json

python3 src/secweaver.py skill data-source-completeness \
  -i examples/data-source-completeness/s1-full-traceable.json

python3 src/secweaver.py skill risk-identification \
  -i examples/risk-identification/s5-curl-download-exec-p0.json
```

可通过 `secweaver skill` 直接运行的名称（前四项还提供离线 Demo）：

- `data-source-completeness`，别名：`completeness`
- `alert-confirmation`，别名：`alert`
- `traceability-analysis`，别名：`traceability`
- `risk-identification`，别名：`risk`
- `evidence-fetch`，别名：`fetch`
- `log-format-discovery`，别名：`format-discovery`
- `dataasset-connectivity-check`，别名：`connectivity`

`secweaver list` 还会展示仅通过文档工作流使用的 Skill。请按对应 `SKILL.md`
操作，不要通过 `secweaver skill` 执行：纯提示词 `prompt-risk-analysis`、
`dataasset-validation-advisor`、`offline-showcase`、
`external-listener-cmd-risk` 和 `external-listener-connect-risk`。

---

## 传递底层参数

如果需要给底层 Skill 脚本传递额外参数，可以在 CLI 参数末尾使用 `--`：

```bash
python3 src/secweaver.py skill traceability-analysis \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json \
  -- --patterns dataasset/scenarios/anchor-patterns.json
```

封装命令调用 Skill 前会移除分隔符。示例中的输入/输出参数可以写在 `--` 前；
`--` 后的参数会原样传给 Skill 脚本。

---

## 设计边界

CI 门禁（`.github/workflows/ci.yml`）与本地 `make ci` 保持一致：

```bash
make ci
```

完整门禁：安装依赖 → 发布扫描 → 文档 → SBOM → Agent → Attack Lab → 全部 DataAsset 根
校验 → 规则同步 → 测试 → demo → 最终发布扫描。最后一次扫描会检查 demo 重新生成的
公开报告及其中的可移植元数据路径。手工运行其中几项不等价于 `make ci`。

测试说明见：[`tests/README.zh-CN.md`](../tests/README.zh-CN.md)。

推荐关系：

```text
快速体验 / 自动化脚本：使用 `python3 src/secweaver.py`
日常分析 / 运营交互：在 **AI Agent**（Cursor、Codex、Claude Code、OpenClaw、WorkBuddy 等）中请求对应 Skill，或仅用 CLI
真实数据：配置 SaaS SLS Proxy 或客户自有数据源，使用只读查询凭证
```
