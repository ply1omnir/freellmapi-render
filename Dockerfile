# FreeLLMAPI on Render (free tier) — deployment image
#
# 在官方镜像之上叠加一个 entrypoint，同时承担两个职责：
#   1) receiver  —— 通过 **仅 loopback** 的 HTTP 端点接收应用自己产生的
#                   加密数据库备份，转存到 GitHub Releases（资产可删除，
#                   空间恒定，不像 git 历史只增不减）
#   2) supervisor —— 启动前先探测 GitHub，让应用的原生还原能在本地 URL 上
#                   拿到备份；随后托管应用进程
#
# ── 信任域隔离（刻意设计，勿随意放宽）──────────────────────────────────
#   * receiver 只绑 127.0.0.1，绝不进入公网暴露面；Render 只把 $PORT 暴露出去，
#     该端口归应用使用。
#   * GET/PUT 都要求共享 bearer token，常量时间比较；token 绝不出现在
#     响应体或日志里。
#   * 备份以**不透明字节**转发：本进程不解密、不持有任何密钥，
#     因此无法泄露数据库内容。
#   * 启动探测不可恢复失败时，容器在 $PORT 上返回极简 500 页而**不启动应用**
#     —— 否则应用会用空库运行，并在下一个周期覆盖掉 GitHub 上的好备份。
#   * 公网 500 页不含堆栈、不含任何密钥值、不含上游响应体。
#
# 本仓库不含任何密钥；密钥全部经 Render 环境变量注入。

FROM ghcr.io/tashfeenahmed/freellmapi:latest

COPY --chown=node:node entrypoint.mjs github.mjs /app/

# 注意：Render 控制台里 Health Check Path 必须留空（用默认 TCP 探测）。
# 实测在免费实例上，HTTP 健康检查的 5 秒超时会在应用偶发卡顿时把实例判死
# （evicted:false），且服务会停在 502 不自动恢复。

CMD ["node", "/app/entrypoint.mjs"]
