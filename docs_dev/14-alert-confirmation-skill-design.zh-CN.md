**语言：** [English](14-alert-confirmation-skill-design.md) | 简体中文（本文）

# 告警确认技能设计

> 公开案例与输入输出见[技能示例](../src/skills/alert-confirmation/examples.zh-CN.md)，无需内部产品规划材料。

> SecWeaver 六大核心能力之六  
> 用途：对 WAF/WEB/IDS 等安全产品告警做 **二次研判**——误报、真实攻击、攻击是否成功  
> **当前实现参考（2026-09-16）**：[执行入口](../src/skills/alert-confirmation/scripts/confirm.py)、[判定与置信度](../src/skills/alert-confirmation/scripts/alert_confirmation/success.py)、[用户指南](../docs_user/17-alert-confirmation.zh-CN.md)。

---

## 一、技能定位

### 1.1 解决什么问题

一线 SOC 每天面对大量 WEB 安全告警，核心问题是：

| 问题 | 告警确认 Skill 应回答 |
|---|---|
| 这条告警要不要管？ | 处置优先级（关闭 / 观察 / 升级 / 封禁） |
| 是扫一下还是真攻击？ | **尝试攻击 / 真实攻击 / 误报** |
| 载荷是不是有效的？ | 基于 payload 的攻击类型与有效性分析 |
| 打穿了吗？ | **攻击是否成功**（需关联主机行为 D2） |
| 要不要深入调查？ | 是否推荐启动 **溯源分析** Skill |

### 1.2 与其他 Skill 的边界

```text
数据源完整性分析 ──▶ 告警确认 ──(真实+成功)──▶ 溯源分析
                           │
                           └── 仅 D1：告警分类，不证明打穿
```

| Skill | 职责 | 不做 |
|---|---|---|
| 数据源完整性分析 | S4 场景数据够不够 | 不研判单条告警 |
| **告警确认** | 单条/批量告警：误报·真实·成功 | 不展开横向 BFS、完整攻击链 |
| 溯源分析 | 多源攻击链还原 | 不做误报/真实二分（除非用户强制） |
| 风险识别 | exec 高危分级 | 不解释 WAF 规则为何命中 |

### 1.3 两层研判模型

告警确认是 **两层递进**，不可跳层：

```text
第一层：告警真实性（Alert Verdict）
  ├── false_positive      误报
  ├── scanning_or_probe   扫描/探测（尝试攻击）
  ├── suspicious          可疑，需更多上下文
  └── confirmed_attack    真实攻击（载荷有效）

第二层：攻击结果（Attack Outcome）—— 仅当第一层 ≥ suspicious 时评估
  ├── not_applicable      第一层已误报
  ├── blocked             WAF/网关已拦截，未到达业务
  ├── attempt_failed      到达业务但未观察到成功迹象
  ├── success_confirmed   有 D2 证据确认成功（打穿/RCE/WebShell）
  └── success_unknown     无 D2 数据，无法判断成功与否
```

**关键原则**：第一层可仅依赖 D1/D5；第二层 **必须** 有 D2（host_exec/connect/file_op）才能 `success_confirmed`。

---

## 二、适用场景

主场景复用完整性分析 **S4 WEB 告警确认**，可扩展：

| 场景 ID | 名称 | 告警来源 | 说明 |
|---|---|---|---|
| **S4** | WEB/WAF 告警确认 | waf_alert, web_access_log | S4 主场景 |
| **S4-IDS** | IDS/IPS 告警确认 | ids_alert | 规则命中 + 流量上下文 |
| **S4-批量** | 批量告警降噪 | 多条 waf_alert | 同源 IP/规则聚合后研判 |
| **S4-成功链** | 告警 + 查是否打穿 | waf + D2 | 用户显式问「有没有打穿」 |

**不做为主场景**：完整横向调查（→ 溯源分析）、账号失陷（→ S6 专用流程）。

---

## 三、前置条件

### 3.1 与完整性 Skill 的关系

| completeness 结论 | 告警确认能力 |
|---|---|
| `full_traceable` / `partial_traceable` | 第一层 + 第二层均可（第二层受 D2 覆盖影响） |
| `alert_triage_only` | **仅第一层**；第二层最高 `success_unknown` |
| `not_traceable` | 可对单条告警做 **弱研判**（标注极低置信度），或建议先补数据 |

### 3.2 启动门禁（软门禁）

与溯源不同，告警确认可在 **仅有 WAF** 时运行，但必须：

- `confirmation_mode`: `triage_only` 或 `full`
- 无 D2 时 `attack_outcome` 不得为 `success_confirmed`
- Markdown 明确写「**无法确认是否攻击成功**，建议接入 host_exec」

---

## 四、输入设计

### 4.1 单条告警确认

```json
{
  "investigation_intent": "分析今天 IP 为 203.0.113.10 的 WEB 安全告警，确认误报还是真实攻击，是否成功",
  "scenario": "S4",
  "params": {
    "attacker_ip": "203.0.113.10",
    "alert_time": "2026-06-21T14:30:00+08:00",
    "time_window_minutes": 10,
    "alert_ids": ["WAF-20260621-001"],
    "target_url": "/api/user?id=1"
  },
  "completeness_precheck": {
    "overall_verdict": "partial_traceable",
    "confidence": 0.75,
    "next_skill_blocked": false,
    "data_gaps": ["host_connect not registered"]
  },
  "primary_alerts": [
    {
      "alert_id": "WAF-20260621-001",
      "source": "waf",
      "timestamp": "2026-06-21T14:30:05+08:00",
      "src_ip": "203.0.113.10",
      "url": "/api/user?id=1' OR 1=1--",
      "method": "GET",
      "rule_id": "942100",
      "rule_name": "SQL Injection",
      "payload": "id=1' OR 1=1--",
      "action": "blocked",
      "host": "web-01"
    }
  ],
  "correlated_evidence": {
    "web_access_log": [],
    "host_exec": [],
    "host_connect": [],
    "host_file_op": [],
    "waf_alert_context": []
  }
}
```

### 4.2 批量告警确认

```json
{
  "batch_mode": true,
  "primary_alerts": [ "... 多条 ..." ],
  "group_by": ["src_ip", "rule_id"],
  "params": { "time_start": "...", "time_end": "..." }
}
```

批量输出：逐条 JSON + 末尾 `batch_summary`（类似 external-listener-cmd-risk）。

### 4.3 字段说明

| 字段 | 说明 |
|---|---|
| `primary_alerts` | **待确认告警**，至少 1 条 |
| `correlated_evidence` | 告警前后上下文 + D2 主机行为（平台按 IP/URL/host/时间窗检索） |
| `completeness_precheck` | 可选；用于 confidence 封顶与 outcome 能力判断 |
| `params.time_window_minutes` | 关联 WEB 访问日志默认 ±10min |

---

## 五、输出设计

### 5.1 双通道

1. **结构化 JSON**（每条告警一个对象）
2. **Markdown 研判卡片**（给分析师）

### 5.2 单条 JSON 结构

以下为[公开合成输入](../examples/alert-confirmation/s4-webshell-attack-success.json)的实际输出摘录，已按当前代码复核。它与前面的输入结构示意是不同案例；未列出的证据、上下文和报告字段仍保留在完整输出中。

在仓库根目录完成 `make quickstart` 后复现：

```bash
make ai-showcase CASE=webshell-attack-confirmation
```

```json
{
  "alert_type": "alert_confirmation",
  "alert_id": "WAF-20260621-002",
  "scenario": "S4",
  "confirmation_mode": "full",
  "alert_verdict": "confirmed_attack",
  "attack_outcome": "success_confirmed",
  "attack_success": true,
  "confidence": 0.88,
  "confidence_ceiling": 0.88,
  "next_skill": "traceability_analysis"
}
```

完整 JSON 位于 `outputs/ai-showcase/webshell-attack-confirmation.json`；智能体按 Skill 生成的 Markdown 报告是另一输出。上述数值只适用于固定合成案例。

### 5.3 alert_verdict 枚举

| alert_verdict | 含义 | 典型条件 |
|---|---|---|
| `false_positive` | 误报 | 业务正常参数、规则过宽、扫描器误匹配 |
| `scanning_or_probe` | 扫描/探测 | 大量 404、无有效 payload、低频指纹 |
| `suspicious` | 可疑 | 有命中但 payload 不完整或上下文不足 |
| `confirmed_attack` | 真实攻击 | 有效攻击载荷，非业务误匹配 |

### 5.4 attack_outcome 枚举

当前 `layer2_outcome` 按下列顺序返回，不能仅凭缺少日志认定攻击失败：

| 顺序 | 条件 | attack_outcome |
|---|---|---|
| 1 | `alert_verdict=false_positive` | `not_applicable` |
| 2 | 不属于 suspicious/scanning_or_probe/confirmed_attack | `success_unknown` |
| 3 | `confirmation_mode=triage_only` | `success_unknown`，即使 WAF 标记拦截 |
| 4 | 已匹配成功证据 `success_refs` | `success_confirmed` |
| 5 | 命中配置的拦截动作且为 confirmed_attack | `blocked` |
| 6 | 没有 D2 数据 | `success_unknown` |
| 7 | 有 D2，但没有成功证据，且未进入上述分支 | `attempt_failed` |

`attempt_failed` 表示当前证据未确认成功，不等于证明整个环境安全。D2 成功线索仍需匹配目标、时间窗和行为；完整分支见 [success.py](../src/skills/alert-confirmation/scripts/alert_confirmation/success.py)。

### 5.5 recommended_action 枚举

| 值 | 含义 |
|---|---|
| `close_as_fp` | 关闭告警（误报） |
| `log_only` | 仅记录 |
| `log_and_monitor` | 记录并观察 |
| `manual_review_30m` | 30 分钟内人工复核 |
| `escalate_investigate` | 升级调查 |
| `block_ip` | 建议封禁源 IP |
| `isolate_host` | 建议隔离受害主机（success_confirmed 时） |

### 5.6 触发下游 Skill

| 条件 | next_skill |
|---|---|
| `alert_verdict=confirmed_attack` 且 `attack_outcome=success_confirmed` | `traceability_analysis` |
| 用户显式要求「查横向/攻击链」 | `traceability_analysis` |
| 仅 attempt / blocked | null |
| 需补 D2 | 建议先 `data-source-completeness` |

---

## 六、研判流程（Skill 核心算法）

### 6.1 七步流水线

```text
Step 0  读取 completeness_precheck，确定 triage_only / full 模式
Step 1  解析 primary_alert：规则、payload、action、URL、IP、时间
Step 2  第一层：payload 分析 → alert_verdict（误报/扫描/可疑/真实）
Step 3  上下文：关联 web_access_log 同窗请求（同 IP、同 URL 前缀）
Step 4  第二层：若 ≥ suspicious，关联 host_exec/connect/file_op（matrix `attack_success`，同 host）
Step 5  成功判定：D2 是否存在 shell/下载/WebShell 等成功指标
Step 6  置信度 + recommended_action + next_skill
Step 7  输出 JSON + Markdown 研判卡片
```

### 6.2 第一层：payload 与误报规则

#### 攻击类型识别（attack_type）

| attack_type | 识别特征 |
|---|---|
| `sqli` | `' OR`, `UNION SELECT`, `--`, `#`, `sleep(`, `benchmark(` |
| `xss` | `<script`, `onerror=`, `javascript:`, `<svg/onload` |
| `rce` | `;`, `|`, `` ` ``, `$()`, `system(`, `exec(`, `cmd=` |
| `path_traversal` | `../`, `..\\`, `/etc/passwd`, `file://` |
| `webshell` | `eval(`, `base64_decode`, `assert(`, `shell.php` |
| `ssrf` | `url=`, `http://127.`, `http://169.254`, `file://` |
| `scanner_fingerprint` | 大量不同 URL、无 body、已知扫描器 UA |
| `unknown` | 规则命中但无法分类 |

#### 误报降级（→ false_positive / suspicious）

| 条件 | 处理 |
|---|---|
| payload 为空且规则仅基于 URL 路径 | suspicious，不得 confirmed_attack |
| 参数为已知业务白名单（订单号、UUID 格式） | 倾向 false_positive |
| 同一 IP 单条且 action=blocked 且无重复 | scanning_or_probe 或 suspicious |
| 与历史 FP 模式库匹配 | false_positive |
| 仅 URL 编码的正常中文/业务字符 | false_positive |

#### 真实攻击升级（→ confirmed_attack）

| 条件 | 处理 |
|---|---|
| 解码后含明确 exploit 语法 | confirmed_attack |
| 同 IP 短时间多条不同 exploit | confirmed_attack，升 recommended_action |
| payload 与 rule_name 一致（SQLi 规则 + SQLi 语法） | confirmed_attack |

### 6.3 第二层：攻击成功关联

| 关联 | 规则 |
|---|---|
| 时间窗 | matrix `time_windows.attack_success`，当前默认 -5/+30 分钟；存在匹配 WEB 请求时以该请求为关联锚点 |
| 主机 | `correlated.host = primary_alert.host` |
| IP | exec 无 host 时用 alert 关联的 victim host |

#### 候选成功线索（须经过目标、时间与行为关联）

| 指标 | 证据来源 | 示例 |
|---|---|---|
| Shell 执行 | host_exec | bash/sh/cmd 由 web 进程子进程启动 |
| 下载执行 | host_exec + connect | curl/wget + 外连 80/443 |
| WebShell 落地 | host_file_op | `.php`/`.jsp` 写入 upload/www |
| 回显型 exploit | web_access_log | 500 错误 + 异常响应体（若有） |
| 反弹连接 | host_connect | web 进程外连非预期 IP |

上表是候选线索，不是任意攻击类型的通用成功条件。D2 仅包含 `host_exec`、`host_connect`、`host_file_op`、`host_persistence`；单独的 HTTP 500/响应异常只作 WEB 上下文。成功证据必须满足目标主机、时间窗口和攻击类型兼容：SQLi 的 exec 只接受 `database` 类，curl 下载只可支持 RCE/WebShell/SSRF 等兼容类型。具体兼容矩阵与请求归属以 `success.py` 的 `_indicator_compatible()`、`find_d2_success()` 为准；活动级成功不能替代单条告警的成功归属。

#### 失败/拦截指标

按 §5.4 的顺序判断：`triage_only` 保留未知；full 模式下有成功证据优先确认成功，其次才检查明确的 WAF 拦截动作。无拦截、无 D2 时为 `success_unknown`；存在 D2 但未发现成功证据时才可为 `attempt_failed`。单独的 HTTP 200 或 WAF action 不足以证明攻击结果。

### 6.4 置信度

当前实现先计算有效上限，再计算判定分数。规则来源为 `attack-types.json` 的 `layer1_upgrade` 与 [success.py](../src/skills/alert-confirmation/scripts/alert_confirmation/success.py)：

```text
base_ceiling = float((completeness_precheck or {}).get("confidence") or 1.0)
若 success_confirmed 且有 success_refs：ceiling = max(base_ceiling, d2_success_confidence_floor)
否则若 confirmed_attack：ceiling = max(base_ceiling, confirmed_attack_confidence_floor)
否则：ceiling = base_ceiling
```

当前默认 floor 分别为 `0.88`、`0.75`；它们可提升有效上限，不直接把结果分数设为该值。缺省或数值 0 的上游 confidence 当前回退到 1.0，不能用 0 代替显式的门禁字段。

| 第一层结果 | 基础分 |
|---|---|
| confirmed_attack，payload validity=valid | 0.88 |
| confirmed_attack，其他 validity | 0.72 |
| false_positive | 0.82 |
| suspicious | 0.58 |
| scanning_or_probe | 0.70 |
| 其他 | 0.60 |

第二层调整：success_confirmed 为 `min(0.95, base+0.08)`；success_unknown 为 `min(base, 0.68)`；blocked 为 `min(0.88, base+0.02)`；其余保留基础分。最终 `confidence=round(min(ceiling, base), 2)`，输出的 `confidence_ceiling` 是有效上限，始终约束最终 confidence。这是规则分数，不是统计校准的攻击概率。

---

## 七、WEB 告警确认示例（S4）

### 7.1 用户操作

```text
选择 WEB 安全告警资产
分析今天 IP 为 XX 的安全报警
确认：尝试攻击 / 真实攻击（含载荷）/ 误报
若是真实攻击，确认是否攻击成功（关联其他数据）
```

### 7.2 分情况输出

#### 情况 A：仅有 WAF，无 D2

```markdown
## 告警研判

**告警**：WAF-001 | SQL 注入 | 203.0.113.10
**第一层**：confirmed_attack（真实 SQL 注入尝试，payload: `id=1' OR 1=1--`）
**第二层**：success_unknown — 无 WEB 主机 exec/connect 数据，**无法确认是否打穿**
**建议**：log_and_monitor；若需确认成功，请接入 audit-port-execmon
**下一步**：不建议直接溯源；可先做数据源完整性分析
```

#### 情况 B：full 模式、WAF blocked、无成功证据

- alert_verdict: confirmed_attack
- attack_outcome: blocked
- attack_success: false
- recommended_action: log_and_monitor 或 block_ip（视重复次数）

#### 情况 C：RCE/WebShell 告警 + 匹配目标与时间窗的 exec（curl/bash）

- alert_verdict: confirmed_attack
- attack_outcome: success_confirmed
- attack_success: true
- recommended_action: escalate_investigate
- next_skill: traceability_analysis

### 7.3 禁止输出

| 场景 | 禁止 |
|---|---|
| 无 payload | 「确认 SQL 注入成功」 |
| 无 D2 | 「已打穿服务器」 |
| 仅一条扫描 | 「组织级 APT 攻击」 |

---

## 八、批量告警降噪

### 8.1 聚合维度

- 同 `src_ip` + 同 `rule_id` → 合并为一条研判
- 同 `src_ip` 多规则 → 取最高 alert_verdict

### 8.2 batch_summary

```json
{
  "alert_type": "alert_confirmation_batch_summary",
  "total": 50,
  "false_positive": 20,
  "scanning_or_probe": 15,
  "confirmed_attack": 10,
  "success_confirmed": 2,
  "escalate_count": 2,
  "top_attack_types": ["sqli", "xss"],
  "top_ips": ["203.0.113.10"]
}
```

---

## 九、与 WAF / 风险识别 Skill 协作

```text
WAF 告警 ──▶ 告警确认
                │
                ├─ 需看 payload 细节 → 第一层
                │
                └─ 告警后已有 exec 事件 ──▶ 可调用 external-listener-cmd-risk
                    对 exec 做 P0-P3 分级，结果写入 evidence.supporting
```

---

## 十、Skill 文件结构

```text
src/skills/alert-confirmation/
├── SKILL.md                 # 智能体 入口
├── rules.md                 # 误报/真实/成功判定规则、攻击类型特征
├── fp-patterns.json         # 常见误报与白名单模式
├── attack-types.json        # SQLi/XSS/RCE 载荷特征库
├── examples.md              # S4 告警确认与批量样例
└── scripts/
    ├── confirm.py           # 薄 CLI 入口和兼容导出
    ├── alert_confirmation/
    │   ├── paths.py         # catalog 与共享 data-access 路径
    │   ├── common.py        # JSON / 时间 / 主机 / 模式匹配辅助
    │   ├── url_match.py     # URL、HTTP method、WAF 请求匹配
    │   ├── layer1.py        # payload 有效性与攻击类型分类
    │   ├── success.py       # D2 成功确认、置信度、动作、分析师问题
    │   ├── gateway.py       # 网关漏检扫描和网关成功提示
    │   ├── engine.py        # confirm_alert / analyze 编排
    │   ├── report.py        # 批量汇总和 Markdown 报告
    │   └── cli.py           # argparse 与命令输出
    └── input.example.json
```

### 10.1 SKILL.md 应包含

1. frontmatter 触发词：告警确认、误报、WAF、真实攻击、是否成功
2. 两层研判模型与禁止跳层
3. 输入/输出 schema
4. 七步流程
5. triage_only vs full 模式
6. Markdown 研判卡片模板
7. 与 traceability / completeness 衔接

### 10.2 rules.md 应包含

1. alert_verdict 决策树
2. attack_outcome 决策树
3. 攻击类型正则/关键词表
4. 误报降级清单
5. D2 成功指标表
6. recommended_action 映射表
7. 置信度公式

### 10.3 实现边界

| 模块 | 做 | 不做 |
|---|---|
| `confirm.py` | 保持 `python confirm.py -i ...` 和旧 `import confirm` 兼容 | 承载新增业务逻辑 |
| `layer1.py` | payload 模式匹配 → `attack_type` / `alert_verdict` | 成功确认 |
| `success.py` | D2 证据 → `attack_outcome`、置信度、处置动作 | 网关日志漏检扫描 |
| `gateway.py` | WAF bypass / 漏检扫描、网关成功提示 | 主机行为成功证明 |
| `engine.py` | 编排单条/批量告警并输出 JSON 骨架 | 完整溯源链 |
| `report.py` | 批量汇总和 Markdown 报告片段 | 检测规则 |

---

## 十一、Markdown 研判卡片模板

```markdown
## 告警研判报告

**告警 ID**：{alert_id}
**时间**：{timestamp} | **源 IP**：{src_ip} | **URL**：{url}
**规则**：{rule_name} ({rule_id}) | **WAF 动作**：{action}

### 第一层：告警真实性
| 项目 | 结论 |
|------|------|
| 研判结果 | {alert_verdict 中文} |
| 攻击类型 | {attack_type_label} |
| 载荷分析 | {payload_analysis.notes} |
| 置信度 | {confidence} |

### 第二层：攻击结果
| 项目 | 结论 |
|------|------|
| 是否成功 | {attack_success 是/否/未知} |
| 结果判定 | {attack_outcome 中文} |
| 成功证据 | {success_proof refs 或「无」} |

### 证据引用
- 告警：{alert refs}
- 关联：{supporting refs}

### 处置建议
**{recommended_action_label}**

### 数据缺口
{data_gaps_impact}

### 下一步
{next_skill 或补数据建议}
```

---

## 十二、禁止事项（硬约束）

1. **无 payload 不得 confirmed_attack**（最高 suspicious），除非多条关联证据
2. **无 D2 不得 attack_outcome=success_confirmed**
3. **不得虚构** correlated_evidence 中不存在的事件
4. **不得在一层判 false_positive 后仍给 success_confirmed**
5. **不得替代溯源** 输出横向清单或完整攻击链
6. **batch 模式** 每条告警单独 verdict，summary 仅聚合统计
7. WAF action=blocked 时，默认 attack_success=false，除非 D2 证明绕过

---

## 十三、验收标准（S4）

| # | 用例 | 预期 |
|---|---|---|
| 1 | 有效 SQLi payload + blocked + 无 D2 | confirmed_attack；full 模式为 blocked，triage_only 为 success_unknown |
| 2 | 正常业务参数误命中 | false_positive |
| 3 | 告警与命令满足目标、时间窗和成功证据规则 | confirmed_attack + success_confirmed + next_skill=traceability_analysis |
| 4 | 无 payload 仅规则 ID | suspicious + success_unknown |
| 5 | 同 IP 50 条扫描 | batch_summary + 大部分 scanning_or_probe |
| 6 | completeness=alert_triage_only | 第一层正常，第二层最高 success_unknown |

---

## 十四、技能链总览

```text
                    ┌─────────────────────┐
                    │ 数据源完整性分析      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       alert_triage_only   可确认成功        not_traceable
              │                │                │
              ▼                ▼                ▼
       ┌──────────────┐  ┌──────────────┐  建议补数据
       │  告警确认     │  │  告警确认     │
       │ (仅第一层)    │  │ (第一层+第二层)│
       └──────┬───────┘  └──────┬───────┘
              │                 │
              │    success_confirmed
              │                 ▼
              │          ┌──────────────┐
              └─────────▶│  溯源分析     │
                         └──────────────┘
```

---

## 十五、一句话总结

**告警确认 Skill = 对安全产品告警做「两层体检」：先判误报/真实与载荷类型，再在 D2 证据支持下判是否攻击成功；结论保守、证据可追溯，成功确认后移交溯源分析。**

---

*文档版本：v1.2 | 更新日期：2026-09-16 | 状态：已实现 Skill，并按职责拆分 → `src/skills/alert-confirmation/`*
