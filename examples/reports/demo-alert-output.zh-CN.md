# Alert Confirmation Report

- **Alert ID**: WAF-20260621-002
- **Scenario**: S4
- **Alert verdict**: confirmed_attack
- **Attack type**: WebShell
- **Attack outcome**: success_confirmed
- **Attack success**: True
- **Confidence**: 0.88
- **WAF action**: logged
- **Recommended action**: 升级调查，建议隔离受害主机
- **Next skill**: traceability_analysis

真实攻击（WebShell）；检测到 webshell 攻击特征: shell.php, cmd=；攻击已成功；WAF 动作: logged。

## Payload analysis

- **Has payload**: True
- **Payload snippet**: cmd=whoami
- **Technique**: webshell
- **Validity**: valid
- **Notes**: 检测到 webshell 攻击特征: shell.php, cmd=

## Evidence summary

- **alert**: WAF-20260621-002
- **supporting**: exec-101, connect-101, file-101, web-101
- **success_proof**: exec-101, connect-101, file-101
- **false_positive_indicators**: _(none)_

## Join edges

| Join ID | Left evidence | Right evidence | Match keys | Confidence |
| --- | --- | --- | --- | --- |
| d2_exec_connect_same_listener | exec-101 | connect-101 | host=web-01, listener_port=443 | 0.9 |
| d2_exec_file_same_host | exec-101 | file-101 | host=web-01 | 0.85 |

## Next step

已确认真实攻击且成功，建议启动溯源分析
