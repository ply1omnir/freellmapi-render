# FreeLLMAPI on Render — 部署镜像
#
# 本仓库只含"部署脚手架"，不含任何密钥。
# 在官方镜像之上叠加 supervisor，用于解决 Render 免费档的两个限制：
#   1. 文件系统易失 —— 冷启动从 GitHub 私有仓库的最新快照还原 SQLite
#   2. 无 shell     —— 用带 token 的窄控制端点触发手动快照
#
# 官方镜像的 ENTRYPOINT（docker-entrypoint.sh）会先 chown 数据目录再降权到 node 用户，
# 所以我们只需覆盖 CMD。

FROM ghcr.io/tashfeenahmed/freellmapi:latest

COPY --chown=node:node supervisor.mjs snapshot-core.mjs github.mjs /app/

# 注意：Render 控制台里 Health Check Path 必须留空（用默认 TCP 探测）。
# 实测在免费实例上，HTTP 健康检查的 5 秒超时会在应用偶发卡顿时把实例判死（evicted:false），
# 且服务会停在 502 不自动恢复。

CMD ["node", "/app/supervisor.mjs"]
