# 溯源分析 — 关联与判定规则

> **Heuristic 阈值与模式**见 [heuristic-rules.json](heuristic-rules.json)（运营可编辑）与 [heuristic-rules.zh-CN.md](heuristic-rules.zh-CN.md)  
> 攻击链叙事模式见 [risk-identification/rules/chain-patterns.json](../risk-identification/rules/chain-patterns.json)（`matched_rule` / policy 引用）；WebShell URL、下载/横向工具字面量由 `exec-rules.json` 经 `risk_rules_bridge` 派生。  
> 已废弃：[attack-patterns.json](attack-patterns.json)  
> **跨源 Join 合同**见 [correlation-matrix.json](../../../dataasset/assets/correlation-matrix.json)  
> **场景编排**见 [anchor-patterns.json](../../../dataasset/scenarios/anchor-patterns.json)  
> 确定性关联见 [scripts/correlate.py](scripts/correlate.py) + [scripts/correlation_trace.py](scripts/correlation_trace.py)

## 零、关联优先级（硬规则）

1. **matrix join 优先**：`join_edges` 来自 `correlation-matrix.json`，attack_chain 阶段必须挂 `join_ids`
2. **heuristic 仅补 gap**：`chain-patterns.json` + BFS 仅在 matrix `no_match:*` 时补阶段，标注 `correlation_source: heuristic_fallback`
3. **不得臆造 Join**：无 matrix 规则或无命中 → 写入 `data_gaps` / `hypotheses`，禁止虚构跨源关联
4. **多场景合并**：`scenarios: ["S1","S3"]` 合并 `S1_external_ip_trace` + `S3_lateral_movement` 的 recommended_chain

---

## 一、前置门禁

| 条件 | 动作 |
|---|---|
| `completeness_precheck.next_skill_blocked = true` | 输出 `insufficient_evidence`，不构建 confirmed 链 |
| `overall_verdict = not_traceable` | 同上 |
| 无 `completeness_precheck` | 允许分析但 `confidence_ceiling ≤ 0.7`，Markdown 标注「未做完整性预检」 |

---

## 二、关联 Join 规则

### 2.1 correlation-matrix（主路径）

| join_id | 阶段 | 说明 |
|---|---|---|
| `waf_to_web_access_by_ip` | initial_access | WAF ↔ WEB，alert_context |
| `web_access_to_host_exec` | initial_access + execution | WEB 打穿到 host_exec |
| `d2_exec_connect_same_listener` | execution | 同 host exec ↔ connect |
| `d2_exec_file_same_host` | execution | exec ↔ file_op |
| `attacker_ip_to_ssh_auth` | lateral_movement | 攻击 IP → SSH |
| `host_ip_to_ssh_auth_lateral` | lateral_movement | 跳板 IP → 新 host SSH |
| `firewall_web_to_internal` | lateral_movement | 防火墙 :22 辅助 |

调查窗由 anchor-patterns 的 `investigation_window`（通常 `trace_default`：前 24h / 后 6h）经 matrix `time_windows` 填充。

### 2.2 heuristic 补全（次路径 · TigerSec P0）

| 规则 | 触发 | 输出 |
|---|---|---|
| **exec_inferred initial_access** | 无 WAF/WEB，`nginx:80` 子进程 `sh -c` / `s.phtml`；**`has_tty=false` 优先选锚点并提升置信度**（`source_adapters/tigersec.py`） | `correlation_source: exec_inferred` + `session_signals` |
| **seed_hosts / params.hosts** | 无 initial 仍跑 execution | 不跳过 `find_execution_chain` |
| **host 归一化** | `localhost` → `host_ip` / `__source__` / `_victim_host` | matrix join 与 BFS 用 IP |
| **hosts → asset_inventory** | `dataasset/hosts/` 按调查范围注入 | `host_to_cmdb` join；`impacted_assets` 带 network/roles |
| **lateral_from_exec** | exec 中 `sshpass/ssh …@10.x` | `join_ids: lateral_from_exec`，`suspected_lateral` |
| **lateral_from_syslog** | 目标机 syslog `ssh_login_success` 且 `src_ip=源主机`（受害 IP = `__source__`） | `confirmed_lateral`；可将 exec 推断的 suspected 升级为 confirmed |
| **lateral_from_target_exec** | 源机 suspected 横向后，**目标机** `host_exec` 短窗内高危命令突发 | `likely_lateral`；规则见 **`heuristic-rules.json` → `target_exec_lateral`** |

配置化说明：§2.3 heuristic-rules.json

| 关联 | 键 | 时间窗 |
|---|---|---|
| WAF → initial_access | `src_ip = attacker_ip` | `[time_start, time_end]` |
| WAF → exec | 同 `host` | anchor ± 15min |
| exec → connect | 同 `host` | ± 2min |
| exec → file_op | 同 `host` | ± 5min |
| 入口 host → SSH | `ssh_auth.src_ip = host_ips[entry_host]` | ≥ anchor |
| SSH 横向 BFS | 新受害 host 的 IP 成为下一跳 src | 迭代至 max_hops=10 |
| firewall 辅助 | `src_ip→dst_ip:22` 与 SSH Accepted 同窗 | ± 10min |

---

## 三、攻击阶段映射

| asset_type | 事件特征 | stage |
|---|---|---|
| waf_alert | URL 含 webshell 特征 | initial_access |
| web_access_log | 攻击 IP + 可疑 URL | initial_access |
| host_exec | bash/sh/curl/wget | execution |
| host_exec | Web 入口 + `has_tty=false` + shell 命令 | initial_access（exec 推断，无 WAF/WEB 时） |
| host_exec | sshd + `has_tty=true` + 运维命令 | 通常非 Web 入口（运维会话） |
| host_connect | 外网 80/443/非标准端口 | execution 或 command_and_control |
| host_file_op | /tmp、/var/www 创建 | persistence 或 execution |
| host_persistence | cron/systemd/authorized_keys/sudoers 变更 | persistence |
| ssh_auth Accepted | 内网 src → 新 host | lateral_movement |
| ssh_auth 大量 Failed | 同 src 连续失败 | suspected_lateral |
| firewall_log | 内网 :22 连接 | lateral_movement（辅助） |

### WebShell URL 特征

`shell`, `webshell`, `cmd=`, `eval(`, `upload`, `.php`, `.jsp`, `.asp`, `backdoor`

### 下载/执行特征

`curl`, `wget`, `fetch`, `| bash`, `| sh`, `chmod +x`

### 横向工具特征

`hydra`, `ncrack`, `medusa`, `sshpass`, `patator`

---

## 四、横向移动四级分类

| lateral_class | 条件 | 输出措辞 |
|---|---|---|
| `confirmed_lateral` | SSH Accepted（syslog `ssh_login_success` 或 ssh_auth Accepted）+ 来源 IP 可解释 | 「横向至 {host}」 |
| `likely_lateral` | 源机 exec 推断 suspected + **目标机**高危 exec 突发（见 `lateral_from_target_exec`） | 「高度疑似横向至 {host}（目标机高危行为互证）」 |
| `suspected_lateral` | 源机 sshpass/ssh 指向目标，或大量 SSH Failed | 「疑似尝试横向至 {host}」 |
| `unknown` | SSH coverage partial | 「至少横向至 …，**可能遗漏**」 |

### 4.1 目标机高危 exec 互证（运营经验）

**配置入口**：`heuristic-rules.json` → `target_exec_lateral`（阈值、正则、置信度、文案模板均可改，无需改 Python）。

**场景**：91 上 exec 显示 `sshpass … devops@92`，但 92 的 syslog 只有失败、无 `ssh_login_success`。

**判定**（默认值，可在 JSON 调整）：suspected 横向后 **90 分钟内**，**92 本机** `host_exec` 出现 ≥3 条高危或 ≥2 类高危 → `likely_lateral`，overall confidence +0.03。

**注意**：91 上 `sshpass … devops@92 id` 是源机发起，不算 92 本机 exec；调查 `hosts` 须含 92。

---

### 2.3 heuristic-rules.json（运营主配置）

| 块 | 作用 |
|---|---|
| `syslog_lateral` | syslog 确认横向、impact 事件类型、置信度 |
| `target_exec_lateral` | 目标机高危 exec 互证规则与阈值 |
| `lateral_from_exec` | 源机 sshpass 推断 suspected 横向 |
| `initial_access_exec_inferred` | has_tty WebShell 入口置信度 |
| `confidence_adjustments` | matrix / likely_lateral 加成 |
| `ssh_auth_result` | SSH 成功/失败 token 与 syslog event_type |

详见 [heuristic-rules.zh-CN.md](heuristic-rules.zh-CN.md)。

---

## 五、overall_verdict 判定

```text
IF blocked OR 无 initial 且无 execution:
  verdict = insufficient_evidence

ELSE IF 有 initial 无 execution 且无 host_exec bundle:
  verdict = scanning_or_attempt_only

ELSE IF 有 initial + execution + lateral confirmed:
  verdict = confirmed_intrusion_chain
  要求: host_exec 证据存在

ELSE IF 有 initial + execution 无 lateral:
  verdict = initial_access_only

ELSE IF 有 initial 或 execution:
  verdict = likely_intrusion_chain

ELSE:
  verdict = insufficient_evidence
```

### 硬约束

- 无 `host_exec` → 不得 `confirmed_intrusion_chain`
- 无 SSH Accepted → 不得 **confirmed** 横向（`confirmed_lateral`）；`likely_lateral` 允许（目标机高危 exec 互证）
- `attack_chain` 每条必须有 `evidence_refs`，且 ref 存在于 `evidence_index`

---

## 六、置信度

```text
confidence_ceiling = completeness_precheck.confidence（默认 1.0）
单阶段:
  initial_access + WAF payload/url: 0.90
  execution + connect 关联: 0.95
  execution 仅 exec: 0.85
  lateral + firewall corroboration: 0.88
  lateral 仅 ssh Accepted: 0.82
  likely_lateral + target_host_exec: 0.86~0.90
  suspected_lateral: ≤ 0.78（exec 推断默认 0.78；纯 Failed BFS ≤ 0.55）

overall = min(ceiling, avg(attack_chain.confidence))
若存在 likely_lateral: overall += 0.03（上限 ceiling）
```

SSH partial coverage → impacted_assets.note 必填；summary 用「至少横向至」

---

## 七、hypotheses vs attack_chain

| 写入 attack_chain | 写入 hypotheses |
|---|---|
| 有 direct evidence_ref | 无 direct evidence，仅有间接推断 |
| SSH Accepted | 仅 WAF 无 exec |
| exec + connect 同窗 | 有 exec 无 SSH Accepted |
| — | 大量 SSH Failed 无 Accepted |

---

## 八、BFS 横向伪代码

```text
seeds = [initial_access.host]
visited = set(seeds)
queue = [(h, depth=0) for h in seeds]

while queue and depth < 10:
  current = pop
  current_ip = host_ips[current]
  for ssh in ssh_auth where src_ip in (current_ip, current):
    if result == Accepted:
      add lateral node(current → target)
      if target not in visited:
        visited.add(target); push(target)
  if failed_count >= 5 and no Accepted:
    add suspected_lateral for current
```

---

## 九、处置建议模板

| verdict | recommended_actions |
|---|---|
| confirmed / likely | 隔离 initial_compromise；排查 lateral_target；保全日志；重置账号/密钥 |
| initial_access_only | 隔离 WEB 主机；查是否仍有 WebShell；加强 WAF |
| scanning_or_attempt_only | 封禁 IP；观察；无需隔离主机 |
| insufficient_evidence | 先补数据源，重跑完整性分析 |

---

## 十、S1/S3 公开溯源场景验收清单

- [ ] initial_access.host = web-01
- [ ] 时间线: WebShell → curl → SSH Accepted
- [ ] 横向含 db-01、app-02
- [ ] lateral_movement_graph 可渲染
- [ ] partial SSH 时有「至少」「可能遗漏」
