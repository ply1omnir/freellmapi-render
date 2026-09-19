# freellmapi-render

FreeLLMAPI 在 Render **免费档**上的部署脚手架（**零密钥**）。

## 它做什么

官方镜像 + 一个 entrypoint，解决免费档的两个限制：

| 限制 | 应对 |
|---|---|
| 文件系统易失（重部署/重启/休眠即清空） | 启动前从 GitHub Releases 载入最新备份，应用的原生还原逻辑会自动取用 |
| 无 shell | 备份由应用自己按周期推送（原生能力），entrypoint 只做转存 |

## 组成

- `entrypoint.mjs` — 兼作 receiver 与 supervisor（单进程）
- `github.mjs` — GitHub Releases 读写封装

## 备份链路

```
FreeLLMAPI --(PUT 密文, loopback)--> entrypoint receiver --> GitHub Releases
FreeLLMAPI <--(GET 密文, loopback)-- entrypoint receiver <-- GitHub Releases
```

- 备份由**应用自己加密**（AES-256-GCM），本仓库与 GitHub 上都**没有明文凭据**
- 保留策略：最近 128 份 + 最近 128 天每日 + 最近 128 周每周
- 资产可删除 ⇒ 仓库占用恒定（约几十 MB），不随时间增长

## 密钥

全部通过 Render 环境变量注入：`ENCRYPTION_KEY`、`BACKUP_TOKEN`、
`GITHUB_TOKEN`、`GITHUB_CONFIG_REPO`。本仓库与镜像内均无密钥。
## 可选的脱敏层（maskit 引擎）

本仓库另有一份 **`Dockerfile.maskit`**：在同样一个服务里，于 FreeLLMAPI 之前加一层隐私脱敏网关
（对免费上游打码、响应流式还原），因为免费 provider 普遍会用数据做训练。

- **同一个服务**，不是第二个服务；切换只需改 Render 的 Dockerfile Path（回滚同理，一行）
- 脱敏是**配置开关**：`MASK_ENABLED=true|false`，改环境变量即生效，**不用改代码或换镜像**
- 不含 maskit 的 Flask 面板（用不上），只保留脱敏引擎（AGPL-3.0，见 `maskit/NOTICE.md`）
- 完整说明（拓扑 / 开关 / 安全设计 / 回滚 / 验证清单）：**[README.maskit.md](README.maskit.md)**
- 本地自检：`node tests/router-smoke.mjs`（15 项，用测试替身，不联网）

| 文件 | 用途 |
|---|---|
| `Dockerfile` | 无脱敏版本（现状，回滚目标） |
| `Dockerfile.maskit` | 带脱敏引擎的版本 |
| `entrypoint.mjs` | 两者共用；按 `MASK_ENABLED` 决定是否启动引擎 |
| `maskit/` | 脱敏引擎源码（未修改）+ 许可证与来源说明 |
| `tests/` | 路由器冒烟测试（测试替身） |
