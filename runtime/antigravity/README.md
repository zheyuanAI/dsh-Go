# Antigravity model channel / 模型渠道

This experimental provider extends DSH's `llm-pi-ai` catalog. It does not start
Antigravity CLI or replace DSH's agent, tools, permission checks, or sessions.
It uses `@cortexkit/antigravity-auth-core` **3.0.30** (MIT), pinned in the runtime
lock, for OAuth, model aliases, project context and the upstream wire transport.
Source: <https://github.com/cortexkit/antigravity-auth/tree/main/packages/core>.
The dependency's license ships with its npm package. The provider glue in this
directory is original MIT code; it uses the installed pi-ai public conversion APIs.

Consumer Antigravity OAuth in third-party clients is unsupported by Google and
may cause account restrictions. This is an unofficial, opt-in channel. Model
availability and quota remain subject to the account and upstream service.
No account rotation, proxy service or external credential vault is enabled.
Grants live in the engine's existing credential store, not the Flutter client.

这是实验性的 DSH 模型渠道，不启动 Antigravity CLI。DSH 继续负责代理、
工具、权限和会话。OAuth、模型别名、项目上下文及传输使用上述锁定版本的
CortexKit 核心；适配代码调用当前 pi-ai 的公开消息转换接口。
Google 不支持第三方客户端使用个人 Antigravity OAuth，账号可能受限。
该渠道为非官方可选功能，不启用账号轮换、代理服务器或外部凭据托管。
登录令牌由当前引擎的原有凭据服务管理，Flutter 不保存令牌。

Offline checks / 离线检查:

```sh
DSH_PREFIX=/path/to/patched/prefix node --test runtime/tests/antigravity-provider.test.mjs
```

Tests exercise the actual patched DSH catalog and provider using synthetic
credentials and injected transport. They do not establish real account access,
subscription eligibility, live model availability or Android compatibility.
离线测试使用合成凭据和模拟网络；不代表真实账号、订阅额度、在线模型或
Android 环境已经验证。上线前需用本人账号完成登录及至少两轮工具调用。

The existing Python patch-fixture suite has four CRLF-related failures on this
Windows workstation (and one fixture-dependent skip). The new provider patch
was separately applied to its clean, hash-verified original and applied again
to verify idempotency and companion installation. This is not a claim that the
complete Linux/Android CI matrix passed.
当前 Windows 工作站上，原有 Python 补丁测试有四项因 CRLF 夹具失败、一项
因缺少夹具跳过。新增补丁已针对哈希匹配的原文件独立验证首次应用、重复应用
和配套模块安装；不代表完整 Linux／Android CI 已通过。
