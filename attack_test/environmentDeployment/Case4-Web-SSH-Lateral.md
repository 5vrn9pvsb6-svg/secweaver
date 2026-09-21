# 历史实验场景 4：Web 入侵与 SSH 横向

本文整理 2026-07-05 实验的调查思路，属于历史场景说明，**不是当前发行版的性能、覆盖率或验收证明**。原始内部日志、真实调查报告和截图不随 Community 发布；无法仅凭本文复核当次实验结果。

## 调查问题

```text
Web 命令执行 → SSH 登录 → 目标主机执行
```

横向结论需要源端、认证与目标端证据互证；时间接近或同名账号单独不足以确认。

调查时记录资产范围、带时区的时间窗、数据缺口和每项结论对应的证据引用。采集或查询不完整时保留“无法判断”，不能以未发现事件等同于未发生攻击。

## 公开离线练习

以下[合成样例](../../examples/traceability/s1-web-shell-to-ssh-lateral.json)用于练习当前分析接口，**不是历史实验的原始输入**。完成 [快速上手](../../docs_user/00-security-operator-quickstart.zh-CN.md) 的 Python 安装后，从仓库根目录执行：

```bash
python3 src/skills/traceability-analysis/scripts/correlate.py --no-notify \
  -i examples/traceability/s1-web-shell-to-ssh-lateral.json \
  -o /tmp/secweaver-case-4.json
```

结果写到本地 JSON。检查证据引用、最终裁决和数据缺口；固定预期由公开 `tests/` 与[离线案例目录](../../examples/ai-showcase/README.zh-CN.md)维护。此命令不发起攻击、不取真实数据，也不发送外部通知。

## 复现实验与结论边界

需要实际演练时，先阅读 [Attack Lab](../README.md)，仅在授权隔离环境搭建对应服务并执行步骤。记录 Agent/规则版本、输入、预期和实际输出，重新验证采集与分析两条链路。

本文不保留未经公开基准支持的“秒级”“零漏报”或全量覆盖承诺。离线样例通过只能证明该合成输入下的行为，不能替代目标环境、真实数据源或新版本的端到端验收。
