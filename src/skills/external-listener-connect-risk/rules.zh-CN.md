# 主动外连高危识别规则

> 风险识别子模块：host_connect / active_connect  
> 编排入口：`risk-identification/scripts/assess.py` → `connect_rules.py`

普通下载关联外连、非白名单外连使用 `network_activity`，不证明数据外传；这两类规则不自动映射 T1048.003，风险等级和复核动作保持不变。

## P0

| 规则 | 条件 |
|---|---|
| `external_c2_connect` | Web 监听进程（443/80/8080 或 nginx/php-fpm）外连 **公网** IP |
| `suspicious_port_connect` | 目的端口 ∈ {4444, 5555, 1337, 31337, 9001, 6666, 1234} |

## P1

| 规则 | 条件 |
|---|---|
| `exec_correlated_egress` | ±5min 内有 exec 含 curl/wget/fetch |
| `suspicious_port_connect` | 非 Web 监听上下文的可疑端口外连 |

## P2

| 规则 | 条件 |
|---|---|
| `non_whitelist_egress` | 外连公网但未命中 P0/P1 |

## P3 / 白名单

| 规则 | 条件 |
|---|---|
| `business_whitelist_connect` | 目的 IP 在内网 CIDR 且端口为常见业务端口（3306/6379/443/80 等） |

## 白名单

公网业务外连、已知可信 API 等，不在 connect 规则内硬编码。请维护统一白名单：

- `src/skills/risk-identification/whitelist.json`
- 说明：[../risk-identification/whitelist.md](../risk-identification/whitelist.md)

示例规则 `wl-connect-trusted-public-api` 可按 `dst_cidrs` 放行指定公网段。

## 输出 alert_type

`high_risk_connect`
