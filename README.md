# WeChat → dot MCP Events bridge

v0.3：新增 owner 网页管理界面和 OAuth Authorization Code + PKCE 登录，可在事件回调域名尚未确定时进入准备模式。本版本仅完成离线代码验证，尚未与真实 Auth0、微信账号和 dot 联调或部署本版本。

链路：微信 iLink 长轮询 → 加密持久收件箱 → MCP Events 签名 webhook → 本 dot 的订阅会话 → `wechat_reply` → 原微信上下文。运行 Hermes/OpenClaw 本身会连接它们自己的 agent；本项目实现的是独立桥接。

## 本地检查

需要 Node.js 24；运行依赖锁定为 `jose`（JWT 验证）、`openid-client`（标准 OAuth/OIDC 客户端）与 `qrcode`（本地二维码渲染）。

```
npm ci --ignore-scripts
npm test
npm run check
npm run demo
```

上述测试/demo 全部使用合成身份、固定测试密钥和模拟传输，不访问微信或真实回调。测试包含生产验证器的 JWT 验签、完整扫码状态机、事件/回复回环、撤销、重启和进程崩溃恢复。源码是 Node ESM JavaScript，无 TypeScript 静态检查。

## 管理入口与 Auth0

启用 `BRIDGE_ADMIN_UI_ENABLED=true` 并完成受控部署后，管理入口为 `https://YOUR_HOST/admin`，固定回调为 `https://YOUR_HOST/admin/oauth/callback`。服务端完成授权码交换，浏览器只保存安全的 HttpOnly 会话 cookie。Auth0 使用 **Regular Web Application + Client Secret (Basic)**；具体配置、固定生产域名示例和本地退出语义见 [认证说明](docs/AUTH.md#owner-web-admin-client-v03)。

登录成功不会自动创建微信二维码。owner 必须点击创建、检查扫码状态，再逐字确认实际扫码账号；可以撤销当前扫码或已确认绑定。退出管理会话不会撤销已经确认的微信绑定。

`BRIDGE_CALLBACK_HOSTS=` 留空即可进入准备模式：认证后的 MCP discovery/status 和管理登录可用，订阅、微信消息轮询及发送关闭。取得实际 host 回调域名并经授权配置、重启后，已有有效绑定会开始消息轮询；不要预填猜测域名。

## 已实现

- 真正的 iLink HTTP 适配器：扫码请求/状态、getupdates 游标长轮询、sendmessage、失效会话处理、取消请求；默认只允许官方固定域名
- 扫码请求绑定经过 OAuth 验证的 owner；扫码成功后仍需该 owner 确认精确 scanner ID，才启用消息访问
- OAuth 2.1 资源服务器：`jose` 验证签名、issuer、resource audience、owner subject、期限、scope 与撤销状态；普通 MCP 权限与管理权限分开
- MCP 2.0 `2026-07-28`：严格请求元数据与 HTTP 头匹配、discovery/tools/events、完整响应、标准认证发现入口
- challenge 回调验证、Standard Webhooks 签名、签名换钥、TTL、幂等订阅、有限重试与死信计数
- AES-GCM 加密原子存储；SQLite OS 锁防止同目录多进程，进程崩溃后可正常重启；单 bot 单实例
- 默认拒绝非 owner、拒绝群聊/bot 回流、消息去重；注销/重新绑定后仍保留散列去重与回复幂等凭据，避免未知发送结果被重发
- 回复只接受已接收消息 ID，服务端决定收件人与 context token；不明确的发送结果不会自动重试
- HTTPS/SNI/证书验证、连接时 DNS/IP 固定、禁止私网与重定向、请求大小与超时上限、固定格式无敏感信息日志
- TLS 服务、健康检查、SIGTERM 清理、非 root Dockerfile/Compose、默认关闭的环境模板

## 部署前的真实前提

服务器本身还不够。需要用户批准并准备（已完成的基础设施无需重复创建）：

1. 持续运行的 Linux 服务器、域名、443/TLS 证书与最小权限持久目录
2. 一个符合文档要求的外部 OAuth 身份提供方及实际插件客户端注册；本项目不伪造 OAuth 授权服务器，也不以共享 bearer token 替代账号授权
3. 精确 owner subject、public JWKS、MCP resource audience、单独 admin scope，以及 host 提供的真实回调域名
4. 安全提供存储加密密钥及 TLS 私钥；微信 bot token 仅在经批准的扫码流程中写入加密存储，永不写入聊天或源码
5. 实际安装/连接远程 MCP 插件，看到本 dot 发来的 discovery/subscribe/challenge，完成一次已批准的微信→dot→微信真实回环

不预设美国一定优于德国；应在候选服务器上比较到微信 iLink 与实际回调端点的可达性、延迟和稳定性。先选任意一个合适的 Linux 主机做连通性检查即可。

完整配置与验证顺序见 [部署说明](docs/DEPLOYMENT.md)、[认证要求](docs/AUTH.md)、[iLink/绑定说明](docs/ILINK.md)、[协议与故障语义](docs/CONTRACT.md)。具体测试证据见 [验证记录](docs/VALIDATION.md)。

## 文件与安全边界

- `src/main.mjs`：真实入口；缺少显式开关或配置时拒绝启动
- `src/admin-oauth.mjs` / `admin-ui.mjs`：固定回调、PKCE/OIDC 验证、服务端会话和 owner 表单
- `src/application.mjs`：认证、绑定、撤销与运行时编排
- `src/ilink.mjs` / `linking.mjs`：真实请求实现与 owner 绑定状态机
- `src/auth.mjs` / `mcp.mjs`：OAuth 资源服务器及 MCP 2.0
- `src/bridge.mjs` / `store.mjs` / `runtime.mjs`：可靠投递与持久化
- `test/`：合成离线测试，测试密钥不可用于真实服务
- `.env.example`：仅路径/占位符，默认禁用 live
- `.codex-plugin/plugin.json`：未安装的包元数据；远程 MCP 地址和实际账号连接仍待配置

当前为文本私聊范围；媒体/群聊、无限历史、分布式多副本不支持。实际 host OAuth、Tencent 会话、浏览器/代理集成、Docker 容器构建和账号回环仍需真实环境验证，不宣称已上线或完成生产验收。

官方参考：[OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events)、[插件认证](https://developers.openai.com/plugins/build/auth)、[腾讯 iLink 协议](https://github.com/Tencent/openclaw-weixin/blob/main/docs/protocol.md)、[Hermes Weixin](https://hermes-agent.nousresearch.com/docs/user-guide/messaging/weixin/)。读取日期：2026-09-30。
