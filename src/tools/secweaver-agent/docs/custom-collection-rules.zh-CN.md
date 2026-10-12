# 企业自定义采集规则

Agent 0.3.97、Agent Server rc.84、Server rc.135/schema41。企业工作台采用 A 方案，入口为“自定义采集规则”。Owner/Admin 可编辑发布，企业成员可读；本地子管理员暂不获得规则写入能力。

新增规则时选择平台、模块与实际事件类型。条件支持 ALL/ANY/NOT、字段组合、明确类型的值、RE2、CIDR、数值区间、数组。未知/缺失/截断/类型不匹配仍为 unknown，NOT 不能将它变成匹配。

四种动作先于学习执行：告警并保留原始日志；仅计数且不进入学习；强制保留且跳过学习；继续学习。动作优先级为 alert > keep > pass > suppress，数字优先级仅用于同动作排序。新规则默认停用/观察；策略和规则都 enforce 才改变输出。观察只统计首个预测获胜规则，仍继续原学习过滤。高/严重及持久化变化默认不能仅计数；例外需要策略许可、规则许可、原因及七天内到期。

先测试语义 JSON 样本，再保存草稿；发布另需原因与全企业/指定设备范围。草稿不下发，并发冲突必须刷新核对。历史恢复为新草稿，不覆盖发布版本。回执核对当前模块 PID、摘要、版本与新鲜度；下载成功不是已生效。设备每批20台，可加载更多；计数仅汇总已加载设备/当前版本，模块重启计数清零，学习基线保留。

支持 Linux audit exec/file_op/连接、syslog、persistence；Windows process/risk/evidence 文件与连接事件。可用字段以模块注册表为准，不支持任意云端字段或 PCRE。Windows listener_process 固定空，缺少关联命令行则该字段未知。进程/主机状态快照暂不支持过滤；控制、健康、诊断、升级、自定义告警与历史回填均不参与过滤。远程交付要求 SaaS v2 签名身份，ES/离线模式不会自动收到云规则。

Linux TCP 监听范围支持 keep_listener/exclude_listener，不扩大原 loopback 范围；同根仍有保留端点时保留根监控。旧 whitelist_ports 导入绑定每台设备/精确摘要，执行策略才覆盖；本地文件保留供回滚，过期/停用/本地禁用恢复旧设置。多设备导入使用独立 device_ids，不生成企业全局端口并集。

状态在 data/collection-rules/current.json。collection_rules 支持 enabled、policy_file、public_key、alert_output；enabled=false 完全关闭能力。专用 Ed25519 公钥内置，Gateway collection_signing_key_file 指向外部0600私钥，与升级密钥分离。私钥必须备份，换钥需同步 Agent 信任。签名绑定企业/设备/不可变摘要，最长24小时，剩余六小时续租。密钥/存储故障不阻断授权；失败保留未过期 last-good，过期强制保留原始日志并恢复监听范围。

```bash
secweaver-agent whitelist validate -policy policy.json
secweaver-agent whitelist test -policy policy.json -event semantic-event.json
secweaver-agent whitelist status -config /opt/secweaver-agent/etc/config.json
secweaver-agent whitelist disable -config /opt/secweaver-agent/etc/config.json
secweaver-agent whitelist enable -config /opt/secweaver-agent/etc/config.json
secweaver-agent doctor -verbose
```

status 只显示下载元数据；应用状态看心跳回执。disable 创建 .disabled 哨兵，云端不能移除；enable 只移除哨兵，仍受企业策略控制。

告警写 logs/custom-risk-alert.log，0600，100MiB滚动5份，父进程单一写入。每模块最多64条/1MiB排队；失败/溢出计数，原始日志仍保留。告警副本入队前脱敏 sshpass -p、URL编码口令及 token/secret 字段；匹配使用原值，告警级别不能低于来源。

Logtail 需绑定 custom-risk-alert.log* 到 host-custom-risk-alert，排除压缩文件。Windows 使用 ProgramData 日志目录。运营端配置云采集，Agent 无 AK/SK。回执/本地排队不能证明入库，必须核对机器组心跳及企业/主机/新 evidence_id 的 SLS 记录。Community Filebeat 提供独立 custom-risk-alert dataset；既有 ES Operator shipper 需另加文件路由。见[Logtail 示例](../logtail/custom-risk-alert.example.json)。

发布验收包括竞态、真实 PostgreSQL 角色/发布/审计、Windows交叉编译、界面类型/交互。回退使用新的停用版本或本地禁用，保留 schema41 与学习状态。旧 Agent 可继续运行但不执行此功能。

DataAsset 提供 asset-secweaver-custom-risk-alert，复用 syslog_risk_alert 证据包和时间/主机查询模板。风险检测将自定义 critical/high/medium 告警映射为 P0/P1/P2；需按 source_evidence_id 复核保留的原始事件，规则命中不是入侵证明。先替换草稿 Connector 的占位配置并明确授权 Logstore。
