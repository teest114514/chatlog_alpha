# chatlog-plus 对外接口文档

> 以真实源码行为为准 | 更新：2026-04-02

---

## 一、能力总览

| 能力 | 入口 | 适合场景 |
|---|---|---|
| HTTP API | `http://127.0.0.1:5030` | 后端系统拉取聊天记录、联系人、媒体代理链接 |
| MCP | `/mcp` `/sse` `/message` | AI Agent 或支持 MCP 的客户端调用 |
| Action CLI | `chatlog.exe action <命令>` | 本地脚本/调试面板控制账号、取 key、启动服务 |

---

## 二、Action CLI

```powershell
chatlog.exe action <命令> [flags]
```

所有命令输出均为 **JSON 事件流**（每行一个 JSON 对象），字段：`type` / `action` / `stage` / `message` / `code` / `data`。

### 命令列表

| 命令 | 说明 |
|---|---|
| `status` | 输出当前配置快照（workDir、dataDir、httpAddr、账号信息等） |
| `list-accounts` | 列出本地所有可用的微信账号历史 |
| `get-image-key` | 从运行中的微信进程提取图片解密密钥 |
| `restart-and-get-key` | 重启微信并获取数据解压密钥（初始化流程） |
| `decompress-data` | 解压聊天数据库（需先有 key） |
| `start-http` | 启动 HTTP 服务，阻塞运行（Ctrl+C 优雅退出） |
| `start-auto-decompress` | 启动自动解压守护进程，阻塞运行 |
| `set` | 更新配置（httpAddr、workDir、dataKey、imageKey、dataDir、wal、autoDecompressDebounce） |
| `switch-account` | 切换当前账号（需 `--pid` 或 `--history`） |

### 通用 flags

| Flag | 说明 |
|---|---|
| `--pid <int>` | 指定微信进程 PID |
| `--history <string>` | 指定历史账号路径 |

### `set` 命令 flags

| Flag | 说明 |
|---|---|
| `--http-addr` | HTTP 监听地址，如 `127.0.0.1:5030` |
| `--work-dir` | 工作目录 |
| `--data-key` | 数据解压密钥 |
| `--image-key` | 图片解密密钥 |
| `--data-dir` | 微信数据目录 |
| `--wal-enabled` + `--set-wal-enabled` | 开启 WAL 模式（需同时传 `--set-wal-enabled` 才生效） |
| `--auto-decompress-debounce <int>` + `--set-auto-decompress-debounce` | 自动解压防抖间隔（毫秒，需同时传 flag 才生效） |

### 典型启动链路

```powershell
chatlog.exe action status
chatlog.exe action restart-and-get-key
chatlog.exe action decompress-data
chatlog.exe action start-http
```

---

## 三、HTTP API

默认监听：`http://127.0.0.1:5030`

> **前提**：账号已选择、key 已配置、数据库已解密、HTTP 服务已启动。否则 `/api/v1/*` 路由会直接失败。

### 3.0 健康检查

```
GET /health
```

返回 `{"status":"ok"}`。仅表示进程存活，不代表数据库可用。

### 3.1 聊天记录

```
GET /api/v1/chatlog
```

| 参数 | 必填 | 说明 |
|---|---|---|
| `time` | 是 | 时间点或范围（见「时间格式」一节） |
| `talker` | 否 | 对话方 wxid 或群 id，多个逗号分隔 |
| `sender` | 否 | 群聊内发送者过滤，多个逗号分隔 |
| `keyword` | 否 | 关键词过滤 |
| `limit` | 否 | 最多返回条数 |
| `offset` | 否 | 分页偏移 |
| `format` | 否 | `json` / `csv` / `xlsx` / `chatlab` / 默认纯文本 |

#### 时间格式

| 形式 | 示例 |
|---|---|
| 年 | `2026` |
| 月 | `2026-03` |
| 日 | `2026-03-21` |
| 分钟级时间点 | `2026-03-21/14:30` |
| 日期范围 | `2026-03-01~2026-03-21` |
| 分钟级范围 | `2026-03-21/14:30~2026-03-21/15:45` |

> 含分钟时必须用 `/` 和 `:`，不支持空格或 `T` 分隔。

#### `format=json` 消息字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `seq` | int64 | 唯一消息序列号，推荐作为主键 |
| `time` | RFC3339 | 消息时间 |
| `talker` | string | 会话 ID |
| `talkerName` | string | 会话名 |
| `isChatRoom` | bool | 是否群聊 |
| `sender` | string | 发送人 wxid |
| `senderName` | string | 发送人昵称 |
| `isSelf` | bool | 是否自己发送 |
| `type` | int64 | 主消息类型 |
| `subType` | int64 | 子类型 |
| `content` | string | 面向展示的文本内容，不适合机器解析 |
| `contents` | object | 面向机器消费的结构化内容 |

#### `contents` 媒体代理字段（规范化字段，优先使用）

| 字段 | 说明 |
|---|---|
| `proxyType` | `image` / `video` / `voice` / `file` |
| `proxyKey` | 代理所用 key（md5、path 或 voice server_id） |
| `proxyUrl` | 推荐直接消费的代理地址，如 `/image/<md5>` |
| `resolved` | 是否已得到可用代理 key |
| `keySource` | key 来源，如 `contents.md5`、`contents.path`、`contents.voice` |

#### `contents` 原始字段（降级用）

| 字段 | 说明 |
|---|---|
| `md5` | 图片/视频/文件的 md5 |
| `path` | 图片（type=3）或视频（type=43）的本地相对路径，由 PackedInfo 解析 |
| `voice` | 语音消息 ServerID（type=34），配合 `/voice/<key>` 访问 |
| `assets` | 笔记/合并转发展开后的媒体资产列表（已展平，含嵌套层级） |
| `recordInfo` | 笔记/合并转发的原始结构（含 `datalist.dataitem[]`） |

**消费优先级**：`contents.proxyUrl` → `contents.assets[].proxyUrl` → `contents.md5` / `contents.path` / `contents.voice`

> `content` 字段仅用于展示，不适合作为媒体链接来源。

#### 机器消费建议

- 笔记（type=49/subType=24）和合并转发（type=49/subType=19）优先读 `contents.assets[]`
- `assets[]` 已支持嵌套展平（合并转发内嵌套笔记时，嵌套层资产也会出现在外层 `assets[]` 中）
- 生成链接 ≠ 文件已下载，最终以 HTTP GET 响应 200 为准

### 3.2 联系人

```
GET /api/v1/contact
```

| 参数 | 说明 |
|---|---|
| `keyword` | 搜索关键词 |
| `limit` / `offset` | 分页 |
| `format` | `json` / `xlsx` / 默认文本 |

`format=json` 返回 `{"items":[{"userName","alias","remark","nickName","isFriend"}]}`

### 3.3 群聊

```
GET /api/v1/chatroom
```

| 参数 | 说明 |
|---|---|
| `keyword` / `limit` / `offset` / `format` | 同联系人 |

`format=json` 返回 `{"items":[{"name","owner","users":[],"remark","nickName"}]}`

### 3.4 最近会话

```
GET /api/v1/session
```

`format=json` 返回 `{"items":[{"userName","nOrder","nickName","content","nTime"}]}`

### 3.5 朋友圈

```
GET /api/v1/sns
```

| 参数 | 说明 |
|---|---|
| `username` | 指定用户 |
| `limit` / `offset` | 分页 |
| `format` | `json` / `csv` / `xlsx` / `raw` / 默认文本 |

`content_type` 归一值：`image` / `video` / `article` / `finder` / `text`

### 3.6 数据库浏览（调试用）

> 这组接口用于调试和内省，不建议业务系统作为稳定协议依赖。

| 接口 | 说明 |
|---|---|
| `GET /api/v1/db` | 返回已解密数据库分组与文件列表 |
| `GET /api/v1/db/tables?group=&file=` | 返回表名列表 |
| `GET /api/v1/db/data?group=&file=&table=&keyword=&limit=&offset=&format=` | 分页查表数据 |
| `GET /api/v1/db/query?group=&file=&sql=&format=` | 执行任意 SQL（不应暴露给不可信方） |
| `POST /api/v1/cache/clear` | 清理媒体解密缓存文件 |

---

## 四、��体代理 API

### 路由

| 路由 | 说明 |
|---|---|
| `GET /image/*key` | 图片代理，支持 silk 解密和多后缀回退 |
| `GET /video/*key` | 视频代理 |
| `GET /file/*key` | 文件代理 |
| `GET /voice/*key` | 语音代理，自动将 silk 转 mp3；失败则返回原始 silk（audio/silk） |
| `GET /data/*path` | 底层文件出口，业务层不建议直接构造 |

### key 类型

`*key` 可以是 md5、相对路径、或逗号分隔的多候选。外部系统统一使用 md5 即可。

### 可访问性判据

正确判断一个 md5 是否已下载：对代理链接发送 GET 请求，跟随 302，最终响应 200 = 可访问。

`?info=1` 或 `HEAD` 请求**不能**作为可访问性判据。

### voice 特殊说明

- type=34 语音消息，`contents.voice` 里存的是 `ServerID`（字符串形式的 int64）
- 访问链接：`/voice/<ServerID>`
- 服务端先尝试 silk 转 mp3（Content-Type: audio/mp3）；失败则回落到原始 silk（Content-Type: audio/silk）
- 成功率取决于本地缓存是否存在，chatlog 不会主动下载

---

## 五、MCP

> MCP 接口供 AI Agent 或支持 MCP 协议的客户端调用，路径在 `/mcp`（SSE: `/sse`，消息: `/message`）。

所有 HTTP API 能力均已通过 MCP 工具暴露。

**MCP vs HTTP 差异：**

- HTTP 层有多层 fallback（多后缀候选、findImageByMD5、dat2img 解密）
- MCP 层更直接（GetMedia → 绝对路径 → ReadFile），不等价
- 同一 md5 通过 HTTP 能访问，通过 MCP 不一定等价成功
- 业务系统消费媒体链接，**优先使用 HTTP 代理 API**，不建议依赖 MCP 做批量媒体访问

---

## 六、关键边界与注意事项

1. **`path` 字段**：仅部分消息携带（图片 type=3、视频 type=43，需 PackedInfo 成功解析），是本地相对路径，可拼接成绝对路径直接读文件，也可用作 `/data/*path` 访问
2. **嵌套媒体**：合并转发（subType=19）内嵌笔记（dataType=17）时，`assets[]` 会自动展平，嵌套层的媒体和外层一起出现，`index` 字段用点分隔标识层级，如 `2.1`
3. **语音不自动下载**：chatlog 不触发微信重新下载语音，必须由 pyweixin 触发落盘后才可访问
4. **文件访问先检查后读**：`/file/<md5>` 仅解密本地已有文件，文件未下载时返回 404
