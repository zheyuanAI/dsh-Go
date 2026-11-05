# Disable extra DeepSeek session logs / 禁用额外会话日志

`disable-deepseek-session-log.diff` is pinned to the bundled DSH 0.2.1-rc.4.
It defaults the session-log switch to false and prevents the extension registry
from registering `dsh_session_log`. Existing enabled settings cannot bypass the
block. The log provider is never prepared, so no session events are read and no
delivery watermark is appended. Model messages and unrelated extensions retain
their existing behavior. This is a local runtime policy; remote hosts retain
their own configuration and need the same policy deployed separately.

该补丁将本地会话日志开关默认设为关闭，并在扩展注册入口阻断
`dsh_session_log`。即使旧配置或界面开关设为开启，也不会重新启用上传。
日志提供器不会执行，不读取会话事件，也不追加上传确认记录。
正常模型输入及其他扩展照常处理。此策略作用于 APK 内置运行时；
连接外部远程主机时，需要在对应主机单独部署相同策略。

Offline verification uses synthetic data and the actual registry and request
serializer. The unpatched baseline fails the regression; the patched runtime
passes. No real account or server request is required.

离线测试针对实际扩展注册器与请求序列化代码，使用合成数据。
原版失败、补丁版通过，无需真实账号或服务器请求。

```sh
DSH_PREFIX=/path/to/patched/prefix node --test runtime/tests/disable-deepseek-session-log.test.mjs
```
