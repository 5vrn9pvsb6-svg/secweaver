# SecWeaver Attack Lab（攻击演练环境）

> 模拟测试环境：可复现的攻击链演练，用于生成真实攻击日志并验证 SecWeaver 的分析能力。
>
> 完整部署与使用说明见 [environmentDeployment/README.md](environmentDeployment/README.md)。

## 安全边界（必读）

- 所有脚本**只能在隔离的实验靶机**上运行，禁止在任何生产主机或未授权目标上执行。
- 优先使用容器方式部署（`case4-webPenetrateToSSH/docker-compose.yml`）。
- 部署与攻击脚本均要求显式确认与目标白名单，详见环境 README 的 "Safety Guardrails" 一节。
- `teardown-lab.sh` 只删除有 Attack Lab 所有权标记的资源并恢复文件快照；如需保证完全复原，请销毁并重建一次性虚机或容器。

environmentDeployment 贡献者：1nvok3
