# 风险识别 — 测试数据

离线 `evidence_bundles`，用于验证 S5/S6/S7/S8 主机、账号、外传、SSH、持久化与 DNS 风险分级及白名单。

## 场景列表

| 文件 | 场景 | 预期 overall_verdict | 说明 |
|---|---|---|---|
| [s5-curl-download-exec-p0.json](s5-curl-download-exec-p0.json) | curl\|bash 下载执行 | `high_risk_detected` | P0 exec + connect |
| [s5-reverse-shell-p0.json](s5-reverse-shell-p0.json) | 反弹 shell | `high_risk_detected` | `/dev/tcp` 特征 |
| [s5-external-connect-p0.json](s5-external-connect-p0.json) | Web 监听进程外连合成文档地址 | `high_risk_detected` | `external_c2_connect`；不代表发生真实公网通信 |
| [s5-whoami-recon-p0.json](s5-whoami-recon-p0.json) | whoami 侦察 | `high_risk_detected` | 含 `internal_recon` 规则 |
| [s5-nginx-config-test-whitelisted.json](s5-nginx-config-test-whitelisted.json) | nginx -t 运维 | `no_risk_detected` | 白名单 `wl-nginx-config-test`，保留但不告警 |
| [s5-ssh-bruteforce-p0.json](s5-ssh-bruteforce-p0.json) | 同源 10 次 SSH 失败 | `high_risk_detected` | 一个 P0 暴力尝试波次 |
| [s5-ssh-nine-failures-below-threshold.json](s5-ssh-nine-failures-below-threshold.json) | 相同来源与时间段、只有 9 次失败 | `insufficient_data` | 零风险项、零暴力波次；低于当前 10 次阈值，不等于证明安全 |
| [s5-persistence-authorized-keys-p0.json](s5-persistence-authorized-keys-p0.json) | 修改 SSH 授权密钥 | `high_risk_detected` | P0 持久化变更 |
| [s8-dns-dga-p1.json](s8-dns-dga-p1.json) | 无对应外连的异常 DNS 查询 | `high_risk_detected` | P1 DNS 特征，不证明网络会话 |
| [s6-root-ssh-login-p1.json](s6-root-ssh-login-p1.json) | 外部 root SSH 登录成功 | `high_risk_detected` | P1 候选，不证明账号失陷 |
| [s7-data-staging-and-scp-p0.json](s7-data-staging-and-scp-p0.json) | 数据暂存、SCP 外发与同窗连接 | `high_risk_detected` | 上下文提升到 P0，不证明传输完成 |

## 运行

```bash
python3 src/skills/risk-identification/scripts/assess.py \
  -i examples/risk-identification/s5-curl-download-exec-p0.json

# 自动执行全部 11 份示例并验证预期规则和输出 Schema
.venv/bin/python -m unittest discover -s tests -p test_skill_catalog_and_output_contracts.py -v
```

测试会检查 9 次与 10 次的输入除最后一条失败记录外一致；SSH 次数阈值若修改，
应同时更新这对样例及其预期，不要把旧的负例解释为无风险结论。

白名单配置：`src/skills/risk-identification/whitelist.json`

## 相关

- Skill：`src/skills/risk-identification/SKILL.md`
- 子模块：exec / connect 规则见 `external-listener-cmd-risk`、`external-listener-connect-risk`
