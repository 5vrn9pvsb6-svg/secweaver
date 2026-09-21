# 日志格式发现 — 样本数据

原始日志样本，供 `discover.py` 预处理与字段映射（需 dataasset 中 `status: discovery` 的资产）。

## 样本列表

| 文件 | 类型 | 说明 |
|---|---|---|
| [waf-jsonl.sample](waf-jsonl.sample) | WAF JSONL | 字段名不统一（`client_ip` / `remote_addr`） |
| [ssh-auth.log.sample](ssh-auth.log.sample) | SSH auth.log | 标准 syslog 格式 |
| [host-exec-jsonl.sample](host-exec-jsonl.sample) | audit-port-execmon | exec + active_connect 各一条 |
| [host-exec-webshell-no-tty.sample](host-exec-webshell-no-tty.sample) | audit-port-execmon | WebShell/RCE：`has_tty=false`，nginx 子进程 `sh -c id/shadow` |
| [vendor-cloud-audit.sample](vendor-cloud-audit.sample) | 厂商云审计 | 非规范字段名 |
| [vendor-edr-identity.sample](vendor-edr-identity.sample) | 厂商 EDR 身份日志 | 非规范身份字段 |

## 运行

推荐经 `secweaver` CLI：

```bash
# 使用离线样本（无需在线凭证）
python3 src/secweaver.py asset discover-format asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample

# 其他样本
python3 src/secweaver.py asset discover-format <discovery-asset-id> \
  -i examples/log-format-discovery/ssh-auth.log.sample
```

查看 discovery 队列、导出报告或生成 LLM prompt 时，使用底层脚本：

```bash
# 查看 discovery 队列
python3 src/skills/log-format-discovery/scripts/discover.py --list-discovery

# 导出完整报告
python3 src/skills/log-format-discovery/scripts/discover.py \
  --asset-id asset-waf-api-prod \
  -i examples/log-format-discovery/waf-jsonl.sample \
  --preview-normalize --pretty -o /tmp/discovery-report.json
```

WAF 样本两行均在 2026-06-21 的同一分钟内，分别使用字符串 `@timestamp` 和秒级
`__time__`。`normalized_preview` 应包含两条记录的 `src_ip`、`timestamp`、`url`
等规范字段；回归测试会核对这条字段发现与归一化预览路径。预览只检查当前
`discovery` 资产，**不**代表已完成真实数据源的连接、字段映射应用或下游取数。
其他厂商样本当前只验证格式识别和预览，不应据此宣称其字段映射已完成。

## 相关

- Skill：`src/skills/log-format-discovery/SKILL.md`
- 文档：[docs_user/20-log-format-discovery.md](../../docs_user/20-log-format-discovery.md)
