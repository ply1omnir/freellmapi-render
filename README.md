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
