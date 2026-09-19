# 可选脱敏层（maskit 引擎）— 部署与运维

本文件描述 `Dockerfile.maskit` 这一可选变体：在现有 FreeLLMAPI 部署前加一层**隐私脱敏网关**，
使流向免费上游的请求先被本地打码、响应再被流式还原。

- 动机：聚合进来的免费 provider 普遍会用数据做训练；脱敏放在**唯一入口**，一次配置覆盖所有 provider
- 引擎：maskit 的 `transparent.py`（mitmproxy 插件），**不含其 Flask 面板**（本部署不需要，省约 41MB）
- 许可证：maskit 为 AGPL-3.0，源码未修改地随镜像分发，见 `maskit/NOTICE.md` 与 `maskit/LICENSE`

## 1. 拓扑

```
公网 $PORT → entrypoint.mjs（路由 + supervisor + 备份 receiver）
   ├─ /v1, /v1beta   → [MASK_ENABLED=true]  mitmdump@127.0.0.1:19081 脱敏 → FreeLLMAPI@127.0.0.1:3001
   │                   [MASK_ENABLED=false] 直连 FreeLLMAPI@127.0.0.1:3001
   └─ 其余路径        → FreeLLMAPI@127.0.0.1:3001（自带管理面，仍由其自身登录鉴权）
```

`$PORT` 现在由 entrypoint 持有；FreeLLMAPI 改为监听 `APP_PORT`。备份 receiver（127.0.0.1:8787）不变。

## 2. 开关与配置（全部是 Render 环境变量，改完重新部署即生效，**无需改代码或换镜像**）

| 变量 | 默认 | 作用 |
|---|---|---|
| `MASK_ENABLED` | `true`（本镜像内置） | 脱敏总开关。设为 `false` 即回到「无脱敏」行为，**不再启动 mitmdump**（省约 85MB 内存与约 12s 冷启动） |
| `MASK_FAIL_MODE` | `closed` | 脱敏未就绪时：`closed` = 对脱敏路径返回 503；`passthrough` = 直连放行（**会明文外发，慎用**） |
| `MASK_PATHS` | `/v1,/v1beta` | 走脱敏的路径前缀（逗号分隔） |
| `APP_PORT` | `3001` | FreeLLMAPI 内部监听端口 |
| `MASK_PORT` | `19081` | mitmdump 内部监听端口（仅 loopback） |
| `ALLOW_PUBLIC_SETUP` | `false` | 是否允许公网访问 `POST /api/auth/setup`（见 §4） |

## 3. 脱敏行为要点

- 引擎以 `fail_closed: true` 运行：**已配置上游 + 无法确认安全的请求体一律脱敏或阻断，绝不静默透传**
- 支持 SSE 流式还原（跨 chunk 的占位符会被正确拼回），多轮对话中同一值映射同一占位符
- 内置规则默认开启：API Key / 连接串 / 私钥 / JWT / Token / Secret / 手机号 / 邮箱 / 身份证 / 银行卡 / 私网 IP 等
- NER 语义识别默认**关闭**（需要 ONNX 运行时，本镜像未附带）
- 事件库写入 `/tmp/maskit`（易失，重启即清空）——不影响脱敏正确性

## 4. 安全设计（不要放宽）

1. **首次建号保护**：FreeLLMAPI 用 **socket 源地址**判断「本机来访」并据此免除 setup code。加了前置代理后，
   所有请求的源地址都变成 loopback，该保护会被绕过。因此本 entrypoint **默认拒绝公网 `POST /api/auth/setup`**（403）。
   确需从公网完成首次建号时，临时设 `ALLOW_PUBLIC_SETUP=1`，完成后立刻改回。
2. **客户端 IP 透传**：entrypoint 原样透传 Render 边车写入的 `X-Forwarded-For`（其最右项才是真实客户端），
   仅在缺失时用 peer 地址兜底；同时注入 `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Real-IP`，
   并为子进程设置 `TRUST_PROXY=1`（恰好一跳）。否则依赖 loopback 判断的接口会被误判。
3. **引擎只在 loopback**：mitmdump 绑 `127.0.0.1:MASK_PORT`，公网无法直达。
4. **不注入上游密钥**：绝不把 FreeLLMAPI 的 key 写进 maskit 的 `extra_headers`——那会把服务变成开放代理。
   鉴权仍由 FreeLLMAPI 自身按客户端提供的 key 完成。

## 5. 回滚（始终只有一个 Render 服务）

1. **切换 Dockerfile（推荐，一行）**：Render 服务 → Settings → Dockerfile Path，
   把 `Dockerfile.maskit` 改回 `Dockerfile`，重新部署即可回到无脱敏版本。**不要新建第二个服务**（免费额度只够常驻一个）。
2. **不切 Dockerfile**：仅把环境变量 `MASK_ENABLED=false`，即停用脱敏（仍保留路由层与安全拦截）。
3. Render 控制台也可直接回滚到上一个成功部署。
4. 数据安全：备份链路（receiver → GitHub Releases）与「空库不启动」守卫均未改动，回滚不丢数据。

## 6. 部署后验证清单

| # | 验证项 | 方法 | 期望 |
|---|---|---|---|
| 1 | 服务可用 | `GET /api/ping` | 200 |
| 2 | 管理面可达 | 浏览器打开 `/`（FreeLLMAPI 自带 UI） | 正常登录 |
| 3 | **脱敏生效** | POST `/v1/chat/completions`（正文含假密钥） | FreeLLMAPI 会话/日志里看到的是 `{{APIKEY_xxx}}` 而非明文 |
| 4 | 响应还原 | 同上，看客户端收到的内容 | 还原为明文，无残留占位符 |
| 5 | 闸门 | 观察冷启动窗口内的 `/v1` 请求 | 返回 503（`MASK_FAIL_MODE=closed`） |
| 6 | 安全拦截 | `POST /api/auth/setup` | 403 |
| 7 | 延迟 | 100KB / 400KB / 1MB 请求 | 记录耗时；不可接受则 `MASK_ENABLED=false` |
| 8 | 内存 | Render 面板 | 应在 512MiB 内（实测：FreeLLMAPI ~109MB + 引擎 ~85MB + entrypoint ~50MB） |

## 7. 本地自检

```bash
node deploy/tests/router-smoke.mjs     # 15 项：路由 / 闸门 / 安全拦截 / 代理头 / 开关 / 自愈
```

测试用测试替身（假应用与假引擎），不联网、不需要真 mitmdump。
