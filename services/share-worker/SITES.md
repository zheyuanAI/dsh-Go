# Sites 服务 / Sites service

本 fork 的公开服务为 https://dsh-go-services.zheyuan1997.chatgpt.site 。Sites 项目 ID 为 `appgprj_6aec3a04de588191b321e86f8be91ba0`，访问模式为 public。部署源码仓库由 Sites 管理，保留该项目 ID，后续通过同一站点更新。

The public service for this fork is https://dsh-go-services.zheyuan1997.chatgpt.site . Its Sites project ID is `appgprj_6aec3a04de588191b321e86f8be91ba0`, with public access. Reuse this project when updating the deployment through Sites.

`src/sites.ts` 复用原有加密分享协议，提供 `/api/v1/c`、`/api/v1/c/<id>`、`/c/<id>`、`/share/`、`/api/usage/v1` 和 `/api/health`。分享内容在客户端加密，密钥留在 URL fragment 中。删除需要上传时取得的令牌。统计继续采用严格字段校验，仅将安装编号的 HMAC 与统计数据保存到服务端。

The Worker reuses the encrypted-share protocol. It provides the routes above, a browser viewer and anonymous health checks. Encryption happens on the client and the URL fragment retains the key. Deletion requires the upload's deletion capability. Usage reports retain the original strict field validation and store an HMAC of the installation ID instead of its raw value.

Sites 的 `.openai/hosting.json` 使用 `"r2": "BUCKET"`、`"d1": null`。通过 Sites 环境变量工具设置 secret `USAGE_SECRET`，用来对安装编号和限流键计算 HMAC。不要把其值放入源码或 APK。无需自有域名或单独的 Cloudflare 账号。

Declare `"r2": "BUCKET"` and `"d1": null` in the Sites hosting manifest. Set `USAGE_SECRET` as a runtime secret using the Sites environment tools. Keep its value out of source and APKs. Sites provisions storage without a separate domain or Cloudflare account.

分享上限 20 MiB，每个来源每分钟最多创建 5 个、每小时最多创建 20 个。限流计数通过 R2 条件写入更新。过期内容立即拒绝读取，请求触发的有界清理会删除过期对象。永久链接保留至持有人删除。统计记录保留约 30 天，同日重复上报覆盖同一条记录。没有公开读取统计记录的接口。

Shares are limited to 20 MiB and 5 creations per minute / 20 per hour per source. R2 conditional writes update rate counters. Expired shares are refused immediately, with bounded request-triggered storage cleanup. Permanent links remain until deleted. Usage records expire after about 30 days, with daily duplicates replacing the same record. No public route exposes usage records.

构建前运行 `python3 app/tool/make_replay_viewer.py`。然后在本目录安装锁定的依赖，并执行：

Generate the viewer first, install the locked dependencies, then run from this directory:

```sh
npm run build:sites -- /absolute/site/worker/index.js
npm run test:sites
npm run typecheck
```

将生成的单文件 Worker 放入 Sites Worker ESM 项目，保留许可证和本仓库源码链接，按 Sites 的 source / package / save / deploy 流程发布。`scripts/sites-smoke.mjs <HTTPS origin>` 会使用临时合成密文验证线上上传、读取、解密和删除，结束后删除该分享。

Place the single-file Worker in the Sites Worker ESM project, retain the license and source offer, and publish through the Sites source/package/save/deploy workflow. `scripts/sites-smoke.mjs <HTTPS origin>` checks the live service using synthetic ciphertext and deletes its temporary share.

App 在连通性检查成功前禁用在线分享和统计开启入口，失败后提供重新检测；每分钟重新检测可见功能。关闭统计始终可操作。服务器不可达时不向作者服务回退。旧分享链接仍按其保存的来源打开，未保存来源的旧记录按旧站点读取。

The app disables online-share creation and usage opt-in until its health check succeeds, exposes retry after failure, and rechecks visible features each minute. Statistics can always be turned off. Service failure does not fall back to the author's service. Existing links retain their stored origin; legacy records without one use the original host.
