# chatlog_alpha

微信 4.x 聊天记录本地查询工具，支持 `macOS` 与 `Windows`。

> 警告：Windows 平台当前未完成实机测试，可能无法正常运行。请优先在测试环境验证后再用于正式数据。

## 平台与能力

- 数据库 Key 获取：内置扫描流程（兼容 `all_keys.json`）
- 图片 Key 获取：内置扫描与校验流程
- 数据查询：HTTP + MCP（wx-cli 风格接口）
- 数据源：内置 `wcdb_api` 兼容查询链路（非外部 DLL）
- 全局搜索：支持跨所有数据库快速搜索 / 深度搜索
- 朋友圈媒体：支持图片、视频、实况图代理解密
- 关键词推送：前端/TUI 同步配置，支持 MCP 主动推送与 POST 通知
  - 也支持推送到 Hermes Agent 的微信 home channel
- 推送事件：支持持久化保存、启动恢复与一键清理


## GitHub 自动构建产物

当前 `Release` 工作流会自动构建以下平台与架构：

- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

发布时会在 `dist/` 生成对应压缩包与二进制文件（Windows 为 `.exe`）。

## 快速开始

### 本地运行

```bash
go run .
```

或：

```bash
go build -o chatlog ./cmd/chatlog
./chatlog
```

### 常用命令（CLI）

```bash
chatlog http list
```

```bash
chatlog http call --endpoint history --query chat=<会话ID> --query limit=100 --query format=json
```

### HTTP 接口命令行调用（全接口）

```bash
# 列出所有可调用 HTTP 接口别名
chatlog http list

# 按别名调用（示例：聊天记录）
chatlog http call --endpoint history --query chat=<会话ID> --query limit=100 --query format=json

# 按原始路径调用（示例：执行 SQL）
chatlog http call --path /api/v1/db/query --query group=message --query file=message_0.db --query sql='select count(*) c from MSG'

# 全局搜索（quick / deep）
chatlog http call --path /api/v1/db/search --query keyword=朋友圈 --query mode=deep --query limit=100

# 媒体接口（模板路径参数）
chatlog http call --endpoint image --path-param key=<image_key>

# 朋友圈媒体代理解密
chatlog http call --path /api/v1/sns/media/proxy --query key=<enc_key> --query url='<sns_media_url>'
```

Skill 文档：`skills/chatlog-http-cli/SKILL.md`

## macOS 权限说明（务必阅读）

### 1) 推荐用 `sudo` 运行

macOS 内存读取依赖 `task_for_pid`，建议以 root 启动程序。

### 2) 若使用 setuid 方案（可执行文件自动 root）

请在每次重新编译后执行：

```bash
BIN_PATH="/你的实际路径/chatlog"
sudo chown root:wheel "$BIN_PATH"
sudo chmod 4755 "$BIN_PATH"
ls -l "$BIN_PATH"
```

看到 `-rwsr-xr-x` 表示生效。

### 3) SIP

在多数机器上，仅 root 仍可能不足以读取微信进程内存。  
如需稳定扫描 Key，通常还需要关闭 SIP（System Integrity Protection）。

## Windows 权限说明

- 请使用“管理员权限”启动程序，否则可能无法读取微信进程内存。

## HTTP 接口（摘要）

基础：

- `GET /health`
- `GET /api/v1/ping`

媒体：

- `GET /image/*key`
- `GET /video/*key`
- `GET /file/*key`
- `GET /voice/*key`
- `GET /data/*path`
- `GET /api/v1/sns/media/proxy`

查询（wx-cli 风格）：

- `GET /api/v1/sessions`
- `GET /api/v1/history`
- `GET /api/v1/search`
- `GET /api/v1/unread`
- `GET /api/v1/members`
- `GET /api/v1/new_messages`
- `GET /api/v1/stats`
- `GET /api/v1/favorites`
- `GET /api/v1/sns_notifications`
- `GET /api/v1/sns_feed`
- `GET /api/v1/sns_search`
- `GET /api/v1/contacts`
- `GET /api/v1/chatrooms`

数据库调试：

- `GET /api/v1/db`
- `GET /api/v1/db/search`
- `GET /api/v1/db/tables`
- `GET /api/v1/db/data`
- `GET /api/v1/db/query`
- `POST /api/v1/cache/clear`

关键词推送（前端“关键词推送”页面与 TUI 同步）：

- `GET /api/v1/hook/config`
- `POST /api/v1/hook/config`
- `GET /api/v1/hook/status`
- `GET /api/v1/hook/events`
- `POST /api/v1/hook/events/clear`
- `GET /api/v1/hook/stream`（SSE 实时事件）
- `GET /api/v1/hook/hermes/weixin`
- `POST /api/v1/hook/hermes/weixin`

输出格式：

- 默认 `YAML`
- 可选 `JSON`（`format=json`）

## 全局搜索

- 前端页面：访问根页面 `http://127.0.0.1:5030/`，切换到“全局搜索”标签页。
- 接口：`GET /api/v1/db/search`
- 参数：
  - `keyword`：搜索关键词
  - `mode`：`quick` 或 `deep`
  - `limit`：结果总数上限，默认 `100`，最大 `500`
- 返回内容包含命中的：
  - 数据库组
  - 数据库文件
  - 表名
  - 列名
  - 行标识
  - 命中内容预览

说明：

- `quick`：优先性能，适合前端实时搜索。
- `deep`：覆盖更全，会额外尝试解析压缩消息体和部分二进制字段，速度更慢。

## 朋友圈媒体代理解密

- 接口：`GET /api/v1/sns/media/proxy`
- 典型参数：
  - `url`：朋友圈图片 / 视频 / 实况图资源地址
  - `key`：对应消息 XML 中的 `<enc key="...">`
- 行为：
  - 图片：优先按 `reversed` keystream 解密，失败再尝试 `raw`
  - 视频：按前 `128 KB` 做 XOR 解密，并使用 `reversed` keystream
  - 文件头校验优先，不会只因为响应头里的 `Content-Type` 看起来像图片/视频就跳过解密
  - 优先使用微信官方 `wasm_video_decode.wasm/js` 生成 keystream，失败时回退到本地 Go 实现
- `sns_feed` / `sns_search` 返回的 `media_list` 已带代理地址，可直接访问。

示例：

```bash
curl "http://127.0.0.1:5030/api/v1/sns_feed?limit=5"
curl "http://127.0.0.1:5030/api/v1/sns/media/proxy?key=2503144471&url=https%3A%2F%2F..."
```

自动补 key：

- 如果 `sns_feed` / `sns_search` 已经解析过对应朋友圈消息，服务端会缓存媒体 `url -> key` 映射。
- 之后请求 `/api/v1/sns/media/proxy?key=0&url=...` 时，会优先尝试从缓存里自动补上真实 key。
- 如果该消息从未被解析过，且请求里又没有提供正确 `key`，则无法解密。

运行前提：

- 若要使用官方 WASM 解密路径，运行环境需要安装 `node`。
- 没有 `node` 时，程序会自动回退到内置 Go 实现，但兼容性可能略差。

## 关键词推送与持久化

- 前端页面：访问根页面 `http://127.0.0.1:5030/`，切换到“关键词推送”标签页。
- 配置项与 TUI 一致：
  - `keywords`（多个用 `｜` 分隔）
  - `notify_mode`（`mcp` / `post` / `both` / `weixin` / `all`，也支持 `mcp,weixin` 这类组合值）
  - `post_url`
  - `before_count` / `after_count`
- MCP 主动推送方法名：`notifications/chatlog/keyword_hit`
- 前端“关键词推送”页面会展示所有触发事件，不受 `notify_mode` 影响。
- Weixin Channel 推送：
  - 自动读取 Hermes Agent 的 `HERMES_HOME` 或默认 `~/.hermes`
  - 优先从 `.env` 读取 `WEIXIN_HOME_CHANNEL`、`WEIXIN_ACCOUNT_ID`、`WEIXIN_TOKEN`、`WEIXIN_BASE_URL`
  - 若 `.env` 未提供 token / base_url，会继续读取 `weixin/accounts/<account_id>.json`
  - 也会尝试读取 `config.yaml` 的 `platforms.weixin.extra`
  - 前端可直接读取并修改上述微信配置，保存时会写回 Hermes Home 下的 `.env`
  - 启用 `weixin` 模式时，会校验 Hermes Agent 已安装，且微信渠道已配置完成
- 事件持久化文件：
  - 优先：`<DataDir>/chatlog_hook_events.json`
  - 回退：`<WorkDir>/chatlog_hook_events.json`
- 清理方式：
  - 前端“清空事件”按钮
  - 或调用 `POST /api/v1/hook/events/clear`

## MCP

端点：

- `ANY /mcp`
- `ANY /mcp/`
- `ANY /sse`
- `ANY /message`

### Hermes Agent 接入

本项目可作为 Hermes 的 HTTP MCP Server 使用。

1. 先确保 chatlog HTTP 服务已启动（默认 `127.0.0.1:5030`）。

2. 在 `~/.hermes/config.yaml` 增加 MCP 配置：

```yaml
mcp_servers:
  chatlog:
    url: "http://127.0.0.1:5030/mcp"
    enabled: true
    connect_timeout: 60
    timeout: 120
    tools:
      resources: false
      prompts: false
```

3. 或使用 Hermes CLI 直接添加：

```bash
hermes mcp add chatlog --url http://127.0.0.1:5030/mcp
hermes mcp test chatlog
```

4. 在 Hermes 会话中执行：

```text
/reload-mcp
```

加载后，工具名称会以 `mcp_chatlog_` 前缀出现。

## 安全与隐私

- 所有处理在本地完成
- 请妥善保管解密数据与密钥文件

## 免责声明

详见 [DISCLAIMER.md](./DISCLAIMER.md)
