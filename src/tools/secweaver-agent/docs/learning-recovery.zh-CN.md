# 学习恢复与空名单（0.3.86）

[English](learning-recovery.md)

## 新安装与升级

新安装模板默认 enabled=true、shadow=false，首次启动从空名单学习；此时
filtering_active=false 正常，不代表未启用。一小时内相同四字段的五个不同源事件
达到准入，第五次立即过滤，不必等到一天结束。名单建立前仍输出原文。

旧策略首次迁移会归档旧名单，创建新 baseline_id 重新学习；旧日志不会回放补次数。
普通重启与后续兼容升级保留当前进度。0.3.85 放宽 Linux 命令完整性准入，也不重置
已经完成的学习期。规则见[行为学习](behavior-learning.zh-CN.md)。

空名单/缺少重复行为并不是故障，重学不能制造事件或保证立即过滤。持续断流或
audit lost 应先修复采集源，否则新 generation 仍可能降级。新安装也可能遇到这些源故障。

## Linux 脚本

`recovery/restart-behavior-learning.py` 可以单独复制。支持 Linux systemd、root、
Python 3.6+、Agent 0.3.81+，适用于 SLS SaaS/ES，不依赖网络。
要求标准目录及 audit 模块参数 `-config <安装目录>/etc/audit-port-execmon.json`。
非默认安装目录/服务名使用 `--root`、`--service`。
自定义 state_dir、额外模块参数、Windows、容器及无 systemd 主机需人工维护；
该脚本不是这些平台的自动恢复工具。

```bash
# 默认只检查，不停服务、不改配置或学习状态，输出 JSON
sudo python3 ./restart-behavior-learning.py

# 恢复已关闭、shadow、已降级或学习完成但名单为空的链路
sudo python3 ./restart-behavior-learning.py --apply

# 正常学习且空名单：明确重新开始，通常不需要
sudo python3 ./restart-behavior-learning.py --apply --relearn
```

已有正常 exec 名单或正在过滤的 file_op 名单始终跳过。未指定 --relearn 时，正常学习
即使名单为空也保留进度。重复执行普通 --apply 不会不断重置新周期；反复指定
--relearn 则明确再次重学。默认一健康日只限制新增名单，完成后空名单不会自行产生过滤。

脚本仅设置 enabled=true、shadow=false，并把 generation 提高到大于配置/状态的值，
保留学习周期和事件范围。它短暂停止整个 Agent；共用 generation 的 Linux exec 和
配置中已开启的 file_op 都重新学习。不修改审计规则配置、其他模块策略、设备身份/key、
授权、升级策略或 Logtail/Filebeat。

## 备份、验收与失败

写入前验证版本、服务路径与升级事务。停服务后把模块配置及完整学习目录（含文件名单、
journal、key）备份到 `<安装目录>/data/recovery/learning-*`，原子写入配置，由 Agent
原生生成新状态。不手改 HMAC、删除锁或伪造名单。未知/损坏学习状态拒绝操作；
升级事务须先完成。本机锁避免脚本并发；备份拒绝符号链接/特殊文件，最多
10000 项/512 MiB，并检查剩余磁盘空间。默认检查仅可创建私有互斥锁文件。

启动后默认最多等待 180 秒（--health-timeout 允许 30–600 秒）：要求新 generation、
新鲜原生 doctor 学习状态、累计健康时间及运行中的服务，返回 status=relearning。
这只证明重学已启动，不伪报 filtering_active=true；实际过滤仍需五次准入，
工作台由后续心跳更新。检查返回 checked，保留现有状态返回 skipped 并说明原因。
执行 `secweaver-agent doctor --verbose` 查看学习状态与采集源问题。

正常失败会停服务、恢复旧配置和完整学习目录并启动原服务，失败新状态保留在备份下。
并发修改/升级时拒绝覆盖其状态，返回失败及备份位置供人工处理。强杀/断电不能自动
回滚，也需从备份维护恢复。不要恢复设备身份或复制其他主机名单。
失败子命令的输出只写入本机权限 0600 的 secweaver-learning-error-*.log，结果返回路径，
避免在终端/机器可读结果泄漏配置或凭证。

验证：make recovery-test 使用真实临时文件验证备份、回退、重复执行、延迟启动及
健康名单跳过，服务/doctor 边界隔离；go test . ./pkg/behaviorlearning 验证原生策略及
generation 行为。真实 Linux 服务重学须独立验收；源码验证不代表已经部署。
