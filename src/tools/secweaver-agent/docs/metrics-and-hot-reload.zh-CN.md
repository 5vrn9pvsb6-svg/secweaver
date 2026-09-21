# SecWeaver Agent 指标与配置生命周期

SecWeaver Agent 可以按需导出 Prometheus 指标。当前版本不支持本地配置热加载：修改配置后，
必须受控重启 Agent 才会生效。这样可以避免运维人员误以为审计队列、模块参数或资源策略已经
更新，而实际运行状态没有改变。

## Metrics 配置

```json
{
  "metrics": {
    "enabled": true,
    "listen_address": "127.0.0.1:9100",
    "path": "/metrics"
  }
}
```

启用后的默认值：

- 监听地址：`127.0.0.1:9100`
- 指标路径：`/metrics`
- 存活检查路径：`/live`
- 就绪检查路径：`/health`

`/live` 只检查指标 HTTP 服务是否能响应，正常时返回 HTTP 200。`/health` 是 Agent 的真实就绪
检查：只有所有配置的采集模块都处于 `running` 且 PID 有效、当前授权没有错误、并且没有
`error` 级运行诊断时才返回 HTTP 200。模块尚未启动、正在重启、熔断、授权退化、audit
reader 无法打开/轮转重开或积压已经覆盖证据时返回 HTTP 503，并在响应正文中给出原因。历史
重启计数不会阻止已经恢复的模块重新进入就绪状态。
`status.json` 持久化失败同样返回 503；恢复写入后自动清除。

Agent 在读取配置时校验地址和路径，并在启动模块监管前同步绑定端口。端口绑定失败会产生明确
的启动告警，采集模块继续运行但不提供指标端点；具体错误记录在服务日志中。

端点本身不提供认证。应保持默认回环地址；如果必须监听非回环地址，需要通过防火墙或带认证
的反向代理限制访问。指标路径不能使用 `/live` 或 `/health`，也不能包含 Go ServeMux 通配符。

修改后执行：

```bash
sudo systemctl restart secweaver-agent
curl --fail http://127.0.0.1:9100/live
curl --fail http://127.0.0.1:9100/health
curl --fail http://127.0.0.1:9100/metrics
```

## 核心指标

- `secweaver_agent_module_status`：`1` 运行、`0` 停止或尚未启动、`-1` 错误、`-2` 重启中、`-3` 熔断降级。
- `secweaver_agent_module_pid`：当前子模块 PID，未运行时为 `0`。
- `secweaver_agent_audit_backlog_lines`：共享 audit demux 当前等待重放的总行数。
- `secweaver_agent_audit_backlog_overflows_total`：固定积压环满后被覆盖的证据行累计数；生产环境任何非零增量都应立即告警。
- `secweaver_agent_audit_retired_subscribers_total`：因队列满或管道失败而退役并等待重连的订阅者累计数。
- `secweaver_agent_audit_lines_processed_total`：父进程共享 audit reader 已处理的原始行累计数。
- `secweaver_agent_audit_readers`、`secweaver_agent_audit_readers_ready`：配置的共享 reader 总数和当前成功打开源文件的数量。
- `secweaver_agent_audit_reader_failures_total`：reader 从可用进入不可用状态的累计次数；同一次故障的重试不会反复增加。
- `secweaver_agent_license_enabled`、`secweaver_agent_license_check_success`、`secweaver_agent_heartbeat_success`：授权配置和最近一次控制面结果。
- `secweaver_agent_update_info`、`secweaver_agent_update_attempts_total`、`secweaver_agent_update_failures_total`：最近升级状态与累计尝试结果。

Audit 累计指标由父进程每 5 秒从 demux 拉取一次，不在 audit reader 热路径执行 Prometheus
操作。积压环每个模块固定保留 4096 行；发生覆盖时，首条及之后每 1000 条作为诊断节流点，
由独立后台 worker 写 stderr 和 `status.json`，包含最早丢失及最新记录的 audit ID。若状态盘
很慢，单槽队列会合并为最新节流点，但 Prometheus 累计数始终精确。该 `error` 诊断在本次
Agent 进程生命周期内保持，因已经丢失的证据无法通过后续恢复补回。

Reader 首次打开、读取错误和 audit.log 轮转重开由文件跟随层上报。不可用状态生成可恢复的
`error` 诊断，成功重新打开源文件后自动清除；空闲主机不要求持续产生 audit 事件。

## 配置变更

本地配置采用严格 JSON，未知字段会导致 preflight 和启动失败。重启前应使用安装包中的配置
Schema，并执行：

```bash
/opt/secweaver-agent/bin/secweaver-agent preflight \
  -config /opt/secweaver-agent/etc/config.json
sudo systemctl restart secweaver-agent
```

远程配置遵循相同原则：签名配置原子写入后，监管进程使用专用退出码退出，由服务管理器以同一
配置代次重新启动所有模块。

当前版本不公开 `module_resources`、`audit_demux` 和 `log_level` 配置字段。安装包中的
systemd unit 负责主机级资源限制。模块级限制需要独立 cgroup 或 Windows Job Object，只有
实现并通过验证后才会作为受支持能力发布。

## audit 模块本地诊断

`audit-port-execmon` 的高频 parser 计数采用无锁原子变量；规则队列、当前规则数、规则预算和
压力恢复状态由该模块的 `processTreeMonitor` 持有。模块正常退出时会把两组真实生产指标合并
为一条 `audit runtime stats` stderr 日志。模块内部 parser/规则明细仍不通过父进程 `/metrics`
导出，也不承诺跨模块重启连续累加；父进程 `/metrics` 导出共享 demux 的积压、覆盖、处理行数
和订阅者生命周期指标。

## 发布验证

Agent 测试会严格解码所有随包样例，并核对 JSON Schema 顶层字段与运行时模型，防止配置文档
和可执行行为再次静默漂移。

另见[英文文档](metrics-and-hot-reload.md)。
