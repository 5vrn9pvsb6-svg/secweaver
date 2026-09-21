# SecWeaver 离线样例逐例说明

**语言：** [English](CASE-CATALOG.md) | 简体中文（本文）

本目录提供合成证据，帮助新用户理解 Skill 的判断边界，也供开发者做本地回归。下表的“预期”来自样例 `_meta` 和当前回归测试，不是对真实环境的诊断。示例 IP、主机、时间和事件均用于演示；运行这些输入不需要连接生产数据源。

## 怎么使用

从仓库根目录安装测试依赖（首次运行 `make setup`），然后执行：

```bash
# 运行四个评估 Skill 的全部 27 份输入，并校验结论、规则、Join 和输出 Schema；
# 同时检查六份日志格式样本、WAF/主机执行归一化及提示词报告的结构。
.venv/bin/python -m unittest discover -s tests -p test_skill_catalog_and_output_contracts.py -v

# 单独体验一个例子；其他评估 Skill 的命令见各目录 README。
.venv/bin/python src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s8-dns-dga-p1.json
```

共 **27 份不同的可执行评估输入**：完整性 8、告警 5、溯源 3、风险 11。27 个 Showcase 路由各覆盖其中一份输入，不另算案例；4 份 Demo 报告是输出。另有 2 份提示词研判的 fetch 输入及 6 份格式发现的原始日志。

## 数据源完整性：8 份

这些样例只提供 `registered_assets`、调查场景及参数，检查某类调查具备哪些数据源；**没有真实日志事件**，`full_traceable` 只表示预检所需资产齐备，不表示已经证明攻击成功。

| 输入 | 模拟情况 | 预期判断与边界 |
|---|---|---|
| [s1-full-traceable.json](data-source-completeness/s1-full-traceable.json) | S1 外网 IP 溯源，登记了 9 类相关资产 | `full_traceable`；允许进入溯源分析，仍须读取实际事件 |
| [s1-not-traceable-missing-exec.json](data-source-completeness/s1-not-traceable-missing-exec.json) | S1 缺少关键 `host_exec`，无法从 Web 请求核对主机执行 | `not_traceable`，`next_skill_blocked=true`；指出关键缺口 |
| [s4-alert-triage-only.json](data-source-completeness/s4-alert-triage-only.json) | S4 仅有 WAF、WEB 两类资产，缺少主机侧证据 | `alert_triage_only`；可以对告警分类，不能确认是否打穿 |
| [s4-partial-missing-connect.json](data-source-completeness/s4-partial-missing-connect.json) | S4 必需资产齐备，建议的 `host_connect` 缺失 | `partial_traceable`；可做基础确认，外连相关判断受限 |
| [s6-full-traceable.json](data-source-completeness/s6-full-traceable.json) | S6 已登记认证、登录后执行、持久化和防火墙数据源 | `full_traceable`；数据源齐备不能证明账号已经失陷 |
| [s6-not-traceable-missing-auth.json](data-source-completeness/s6-not-traceable-missing-auth.json) | S6 有登录后数据源，但缺少 P0 认证日志 | `not_traceable`，`next_skill_blocked=true`；后续行为不能替代登录身份事实 |
| [s7-full-traceable.json](data-source-completeness/s7-full-traceable.json) | S7 已登记文件、外连、DNS、流量体量和命令数据源 | `full_traceable`；仍需实际事件才能证明外传 |
| [s7-partial-missing-traffic-volume.json](data-source-completeness/s7-partial-missing-traffic-volume.json) | S7 文件与外连数据源齐备，但缺少 NTA/防火墙流量体量 | `partial_traceable`；传输方向与体量判断受限 |

## 告警确认：5 份

其中 4 份输入各有一条主告警，批量输入含 3 条告警；相关 Web/主机事件用于分别判断“是否真实攻击”和“是否成功”。`attack_success=false` 不等价于“请求一定无害”。

| 输入 | 模拟情况 | 预期判断与边界 |
|---|---|---|
| [s4-false-positive-uuid-param.json](alert-confirmation/s4-false-positive-uuid-param.json) | 正常 UUID 参数触发 WAF 规则，Web 访问未见攻击效果 | `false_positive`，`not_applicable` |
| [s4-scanner-generic-no-payload.json](alert-confirmation/s4-scanner-generic-no-payload.json) | 扫描器特征命中通用规则，缺少有效攻击载荷和主机证据 | `scanning_or_probe`，`success_unknown`；不应声称已成功，也不应直接称为误报 |
| [s4-sqli-blocked-no-breach.json](alert-confirmation/s4-sqli-blocked-no-breach.json) | SQL 注入尝试被 WAF 拦截，无主机侧打穿证据 | `confirmed_attack`，`blocked`，`attack_success=false` |
| [s4-webshell-attack-success.json](alert-confirmation/s4-webshell-attack-success.json) | WebShell 告警与 Web 访问、主机执行、外连和文件操作互证 | `confirmed_attack`，`success_confirmed`；建议进入溯源 |
| [s4-batch-mixed-with-query-gap.json](alert-confirmation/s4-batch-mixed-with-query-gap.json) | 同一批次包含误报、扫描和被拦截攻击，且记录的主机查询失败 | 三类结果各 1 条；`query_integrity=incomplete`，不能用缺少主机事件支持否定结论 |

## 溯源分析：3 份

这些输入在 `evidence_bundles` 中组合 WAF、Web、主机、SSH 等事件，观察证据边和最终结论。`join_edges` 中有边不代表整个推荐 Join 路径都已匹配。WebShell 到 SSH 案例的控制点已观察到，但原始攻破点仍未证实。

| 输入 | 模拟情况 | 预期判断与边界 |
|---|---|---|
| [s1-scan-only-no-host-exec.json](traceability/s1-scan-only-no-host-exec.json) | WAF 与 Web 请求能够关联，缺少命令执行事件 | `scanning_or_attempt_only`；不得把扫描说成入侵成功 |
| [s1-web-shell-to-ssh-lateral.json](traceability/s1-web-shell-to-ssh-lateral.json) | WebShell 相关主机执行、下载/外连、文件操作与 SSH 横向证据 | `confirmed_intrusion_chain`；但 `web_access_to_host_exec`、`host_to_cmdb` 仍未匹配，不可称每条 Join 均完整 |
| [s2-initial-access-no-lateral.json](traceability/s2-initial-access-no-lateral.json) | 有 Web 主机执行和一次 SSH 失败，无成功登录 | `initial_access_only`；SSH 失败可形成关联边，却不能证明横向成功 |

## 风险识别：11 份

这些样例验证规则命中、分级与白名单。风险结论依据**合成证据**；`P0`/`P1` 是样例中的规则等级，不能脱离事件上下文视为现场处置结论。

| 输入 | 模拟情况 | 预期判断与边界 |
|---|---|---|
| [s5-curl-download-exec-p0.json](risk-identification/s5-curl-download-exec-p0.json) | Web 服务子进程执行 `curl | bash`，并有主动连接 | `high_risk_detected`，至少两条风险项，最高 P0 |
| [s5-reverse-shell-p0.json](risk-identification/s5-reverse-shell-p0.json) | Web 服务关联 shell 的 `/dev/tcp` 反连命令 | 命中 `reverse_shell`，最高 P0 |
| [s5-external-connect-p0.json](risk-identification/s5-external-connect-p0.json) | 对外监听服务进程发生主动连接，无对应 `host_exec` 事件 | 命中 `external_c2_connect`，最高 P0；示例使用文档保留地址，不能据此推断真实公网通信 |
| [s5-whoami-recon-p0.json](risk-identification/s5-whoami-recon-p0.json) | Web 监听进程的 shell 子进程运行 `whoami` | 命中 `internal_recon` 和 `external_listener_shell_exec`，最高 P0；高等级来自 Web 进程上下文，不是 `whoami` 本身 |
| [s5-nginx-config-test-whitelisted.json](risk-identification/s5-nginx-config-test-whitelisted.json) | 运维执行 `nginx -t` | 白名单 `wl-nginx-config-test` 命中，`no_risk_detected`；保留风险项但不告警 |
| [s5-ssh-bruteforce-p0.json](risk-identification/s5-ssh-bruteforce-p0.json) | 同一来源短时间内 10 次 SSH 认证失败 | 一个 SSH 暴力尝试波次，最高 P0；并未出现成功登录 |
| [s5-ssh-nine-failures-below-threshold.json](risk-identification/s5-ssh-nine-failures-below-threshold.json) | 与上例条件一致，仅缺第 10 次失败 | `insufficient_data`、零风险项和零暴力波次；未达检测阈值不等于证明安全 |
| [s5-persistence-authorized-keys-p0.json](risk-identification/s5-persistence-authorized-keys-p0.json) | 主机修改 `.ssh/authorized_keys` | 命中 `persistence_ssh_key_modify`，最高 P0；需结合变更授权判断实际处置 |
| [s8-dns-dga-p1.json](risk-identification/s8-dns-dga-p1.json) | 查询 DGA 风格域名，`host_connect` 为空 | DNS 模块命中 `suspected_dga_domain`，最高 P1；没有会话或流量体量证据，不能证明 C2 通信、外传 |
| [s6-root-ssh-login-p1.json](risk-identification/s6-root-ssh-login-p1.json) | 来自文档保留地址的 root SSH 登录成功 | 命中 `root_ssh_login`，最高 P1；异常认证不能单独证明账号失陷 |
| [s7-data-staging-and-scp-p0.json](risk-identification/s7-data-staging-and-scp-p0.json) | 数据库服务进程暂存业务文件、执行外发 SCP，且同进程存在连接事件 | 命中 `data_staging` 与 `network_exfil_tools`，因连接上下文提升为 P0；尚未证明传输完成和字节体量 |

## 提示词研判与取证：2 份输入

`prompt-risk-analysis` 是纯提示词 Skill，不存在与前四类相同的确定性脚本结论。两份输入是符合 `evidence-fetch` 契约的**离线取证结果**；黄金报告是比较研判质量的参考，不是自动生成的真值。

| 文件 | 用途 |
|---|---|
| [fetch-exec-syslog-mini.json](prompt-risk-analysis/fetch-exec-syslog-mini.json) | 14:00–18:30 的 6 条主机执行与 2 条系统风险事件；SSH 命令是尝试，92 上更早的事件只是上下文，不能据此确认横向成功；对照[中文叙事报告](prompt-risk-analysis/report-exec-syslog-mini.zh-CN.md) |
| [fetch-waf-bypass-mini.json](prompt-risk-analysis/fetch-waf-bypass-mini.json) | 7 条去重后的 WAF/Web/主机事件，混合拦截、漏过与良性流量；对照[严格 Schema 的 JSON 报告](prompt-risk-analysis/report-waf-bypass-mini.json)及[中文报告](prompt-risk-analysis/report-waf-bypass-mini.zh-CN.md) |

目前自动回归验证 fetch 输入和 WAF JSON 报告的 Schema，**不验证**每次模型分析的推理质量或文案一致性。使用提示词的步骤见[专项 README](prompt-risk-analysis/README.zh-CN.md)。

## 格式发现：6 份原始日志

此处 `.sample` 是**原始文本**，不是归一化的评估输入。回归检查能否识别格式并提取预览字段；WAF 与主机执行样本还会使用公开 `discovery` 资产验证归一化预览。实际字段映射应用和下游取数仍需另行验证。

| 文件 | 测试重点 |
|---|---|
| [waf-jsonl.sample](log-format-discovery/waf-jsonl.sample) | WAF JSONL 中 `client_ip`/`remote_addr` 等异名字段 |
| [ssh-auth.log.sample](log-format-discovery/ssh-auth.log.sample) | 系统 `auth.log` 的 SSH 成功和失败记录 |
| [host-exec-jsonl.sample](log-format-discovery/host-exec-jsonl.sample) | 主机执行与主动连接两类 JSONL 事件 |
| [host-exec-webshell-no-tty.sample](log-format-discovery/host-exec-webshell-no-tty.sample) | 无 TTY 的 Web 进程命令执行记录 |
| [vendor-cloud-audit.sample](log-format-discovery/vendor-cloud-audit.sample) | 多厂商云审计记录和非规范字段 |
| [vendor-edr-identity.sample](log-format-discovery/vendor-edr-identity.sample) | 多厂商 EDR/身份记录和非规范字段 |

使用 `asset-waf-api-prod` 的 WAF 样本执行 CLI 示例见[格式发现 README](log-format-discovery/README.zh-CN.md)；回归还用 `asset-sls-proxy-host-exec-demo` 归一化主机执行样本。其他类型应选择对应类型的 `discovery` 资产，不能把识别出 JSONL 视为字段映射已完成。

回归还会对现有样例做不另计数量的证据扰动：移除 WebShell 的主机侧证据后成功状态应变为未知；把 SSH 成功登录改为失败或不相关来源后，不得保留已确认的横向结论；降低 S6 来源风险后应移除 root 登录风险项；移除 S7 连接上下文后应保留两条规则，但从 P0 降为 P1。Showcase 溯源路由强制禁用在线 IP 情报与通知；单独运行溯源脚本应手工指定 `--no-ip-intel --no-notify`。

## Showcase 与输出报告

`offline-showcase` 保留原有 5 个 ID： `webshell-attack-confirmation`、`false-positive-parameter`、`webshell-to-ssh-lateral`、`reverse-shell-risk` 和 `missing-host-exec-data`，并补齐其余评估样例；未指定 ID 时默认运行全部 27 例。新增 ID 使用输入文件名去掉 `.json`。详见[Showcase 案例 ID 和运行方式](ai-showcase/README.zh-CN.md)。

`examples/reports/` 的 4 份 `demo-*-output.json` 是完整性、告警、风险、溯源各选**一份现有输入**生成的输出，供阅读输出结构；[报告说明](reports/README.zh-CN.md)提供逐字段解读。`dataasset-connectivity-check`、`dataasset-validation-advisor` 等运维/指导类 Skill 在这里没有独立的 JSON 研判案例；它们由各自的工作流和仓库测试覆盖。子 Skill `external-listener-cmd-risk`、`external-listener-connect-risk` 通过风险识别样例间接体现。
