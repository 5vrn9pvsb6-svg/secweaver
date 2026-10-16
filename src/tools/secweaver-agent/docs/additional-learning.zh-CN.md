# 追加学习：源码0.3.106

[English](additional-learning.md) · [学习总览](behavior-learning.zh-CN.md)

本候选向现有已启用、非shadow、健康且enforcing的原生引擎追加24个**健康小时**。
Linux支持exec/file，Windows分别支持exec/file/network/risk；不启用或重置已关闭、缺失、过期、
降级或正在学习的类型，完整可信的空名单可具备资格。不新增Linux网络学习。
真实Linux/Windows运行验收仍待完成；本地单测和交叉编译不能证明原生部署已就绪。

## 资格与执行

须有托管V2身份、完整 `behavior-relearning-v1` 心跳及数据库owner开启的配套Gateway/工作台。
旧服务不支持新可选协议时正常采集不变。使用已安装的采集校验公钥验证独立用途的30秒开始许可。
唯一采集器在既有锁内核验安装/设备身份、类型、基线token、单调操作序号、固定86400秒和签名期限。
不执行任意命令、不接受网络路径、不新增事件读取器，也不重启服务。

保留Entries、存储HMAC密钥、baseline ID、generation、policy hash及来源去重历史，
开始时仅清未晋升候选。既有保护事件、准入与过滤规则不变。累计健康/在线计数不重置，
进度使用本次窗口增量；离线不计健康时间。达到24健康小时、额外72在线小时、实际开始后7自然日，
或受理后8天签名上限时停止准入，以先到者为准。期限/故障/未知执行不代表成功完成。
正常清洁重启恢复持久事实；非清洁重启或损坏保留原有降级保护。

只有引擎持久状态证明开始/结果；写入inbox只是待处理，不是完成。
重复或续签许可不能重新开始；持久未开始拒绝为终态。采集器暂时缺观测不抹掉已有持久进度。
回执持久化失败只撤回可选上报，不影响正常授权/采集。升级/配置修改锁在升级执行中或未知时延后领取，
不申请配置重启。

## 存储与上限

父进程和worker通过安装数据目录下固定私有 `learning-operations` 通信：
`current.json`16KiB、`receipt.json`8KiB、四个固定类型拒绝文件各4KiB，总目录128KiB。
不允许用户指定文件名。要求Unix0700/0600或Windows SYSTEM/Administrators ACL，普通文件、禁止链接。
worker环境变量 `SECWEAVER_RELEARNING_DATA`、`SECWEAVER_RELEARNING_INSTALLATION`
属于内部supervisor绑定，不是远程配置。

首次追加窗口提交前checkpoint仍为version1，之后version2保存操作身份、计数基准及结果。
新版读取version1/2，旧版不能将version2当作空基线。每流保留一份认证的
`relearning-backup.json`，含完整窗口前state/key/journal。备份、state、journal替换计入每流预算，
至少8MiB的store另外预留128KiB通信预算。空间不足拒绝追加并保留可信副本，替换备份不先删除唯一副本。

## 显式离线恢复

这是维护工具，**不是**页面“再学习”。只暂存新目录，不切换在线目录、不恢复设备凭证、不清服务器互斥。
在Agent源码目录使用0.3.106工具（需Go），或显式编译；不会自动安装为Agent服务命令：

```bash
go run ./cmd/learning-recovery -source /absolute/stopped-stream-state -destination /absolute/new-recovery-state -state-mb 64
```

1. owner关新请求/领取开关，停Agent和相关采集器，等待超过最后30秒许可加时钟安全余量。
   分别保全全部新安装状态和操作inbox，手工切换时隔离旧待处理许可；不删SQL操作、序号或回执历史。
2. 选真实单流state源路径和原配置预算8..256MiB；上面的64仅是示例。
   目标必须绝对、全新且与源目录不嵌套。工具取得源生命周期锁，验证备份HMAC、key、state和journal。
3. 确认成功、检查暂存状态后，才进行另行批准的目录切换。保留源目录；失败的部分目标保留供检查，
   不能复用为合法基线。不能对在线writer运行。
4. 仅恢复同类型/设备/策略。降级会丢失备份之后新增的名单和进度。
   最新备份可能已经包含先前version2窗口，此时仍须兼容新版Agent，不能交给旧二进制。
   未检查恢复checkpoint版本前，不能承诺旧版兼容。
5. 用兼容软件继续对账未知服务器操作；本地恢复不授权清服务器互斥或开始新操作。

## 发布前验证

本地覆盖签名/身份/续签、精确窗口计时、候选与名单保留、重启/幂等、终态拒绝、资源失败、
备份篡改/在线锁/覆盖拒绝以及协调器回执保留。在Agent模块运行：

```bash
go test -p 2 ./pkg/learningoperation ./pkg/behaviorlearning ./pkg/agentlicense ./pkg/auditportexecmon ./internal/windowsevidence ./pkg/windowseventlogriskjson . ./cmd/learning-recovery
```

仍需真实Linux audit与Windows事件源、原生负载下崩溃/资源及配置升级并发验收、审查后的跨仓不可变契约锁，
以及灰度发布授权。未执行生产部署。
