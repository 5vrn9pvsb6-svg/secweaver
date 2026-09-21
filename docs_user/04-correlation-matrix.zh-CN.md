# 04. Correlation Matrix 详解：告诉系统证据怎么关联

**语言：** [English](04-correlation-matrix.md) | 简体中文（本文）

`Correlation Matrix` 是 SecWeaver 中最重要的配置之一。它定义了不同数据源查回来的证据之间如何关联。

如果你只记一句话：

```text
Correlation Matrix 不负责决定先查什么，它负责定义：两类证据能不能连、用什么字段连、在多大时间窗内连。
```

对应配置文件：

```text
dataasset/assets/correlation-matrix.json
```

本文负责概念与阅读示例。字段、运行时支持、配置新增与校验统一维护在 [详细配置参考](21-cross-source-field-correlation.zh-CN.md)，避免两处维护同一契约。
## 1. 为什么需要 Correlation Matrix？

安全调查的关键不是看单条日志，而是看多条证据之间是否能连成链。

例如：

```text
WAF 告警：203.0.113.10 访问 /upload.php
Web 访问日志：203.0.113.10 请求 /upload.php 返回 200
主机命令日志：web-01 随后执行了 whoami、id、curl
SSH 日志：web-01 随后登录了 db-01
防火墙日志：web-01 访问了 db-01:22
```

这些单条日志各自只能说明局部事实。只有把它们关联起来，才能形成攻击链。

Correlation Matrix 就是告诉系统：

```text
哪些证据可以关联？
用哪些字段关联？
时间间隔多大才算合理？
关联成功后如何表达给大模型？
```

## 2. Correlation Matrix 和 Scenario Pattern 的区别

这两个概念很容易混淆。

| 对象 | 负责什么 | 不负责什么 |
|---|---|---|
| Scenario Pattern | 某类问题先查什么、查哪些链路、用哪个 Bundle | 不定义具体 Join 字段 |
| Correlation Matrix | 两类证据如何 Join、时间窗多大、字段怎么匹配 | 不决定某个场景完整调查流程 |

简单比喻：

```text
Scenario Pattern = 调查路线图
Correlation Matrix = 证据连接规则
```

例如：

```text
Scenario Pattern 说：Web 入侵要走 WAF → Web → Host Exec。
Correlation Matrix 说：WAF 和 Web 用 src_ip + url 关联，Web 和 Host Exec 用 host + 时间窗关联。
```

## 3. 一次关联是怎么发生的？

假设有一个 Join：

```text
waf_to_web_access_by_ip
```

它要把 WAF 告警和 Web 访问日志关联起来。

系统会做这些事：

```text
1. 从 evidence_bundles 里取 waf_alert 事件
2. 从 evidence_bundles 里取 web_access_log 事件
3. 读取 Join 规则
4. 比较 src_ip 是否一致
5. 可选比较 url 是否匹配
6. 检查时间是否在合理窗口内
7. 如果匹配成功，生成一条 join_edge
```

关联输出应包含可复核的证据引用。以下仅示意关联信息；具体运行时字段以详细配置参考和当前输出为准：

```json
{
  "join_id": "waf_to_web_access_by_ip",
  "left_ref": "waf-001",
  "right_ref": "web-009",
  "match_keys": {
    "src_ip": "203.0.113.10",
    "url": "/upload.php"
  },
  "time_window": "alert_context",
  "confidence": 0.9
}
```

## 4. 配置与验证

默认配置位于 `dataasset/`；需要隔离时可复制为 `dataasset_my/` 并设置 `DATAASSET_ROOT`。修改前先在[配置参考](21-cross-source-field-correlation.zh-CN.md)确认字段与运行时支持，再运行 `python3 src/secweaver.py validate` 和对应离线示例。关联命中不是攻击成功证明，未命中也不能替代数据完整性检查。
