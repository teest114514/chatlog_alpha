# Chatlog Alpha

[![Release](https://github.com/teest114514/chatlog_alpha/actions/workflows/release.yml/badge.svg)](https://github.com/teest114514/chatlog_alpha/actions/workflows/release.yml)

Chatlog Alpha 是面向微信 4.x 的本地聊天数据读取与自动化工具。它负责发现微信账号、提取和管理密钥、只读查询 WCDB、解密媒体，并通过 TUI、Web、结构化 CLI 和本机 HTTP JSON API 提供统一入口。

## 贡献致谢（置顶）

感谢以下贡献者提交问题复现、实测数据和实现方案。功能后续即使重构或下线，贡献记录也不会因此删除：

| 贡献者 | Pull Request | 吸收与反馈 |
|---|---|---|
| [@ameriadam12](https://github.com/ameriadam12) | [#90](https://github.com/teest114514/chatlog_alpha/pull/90) | 定位并修复大型数据集下仪表盘与历史查询的浏览器卡顿：按需初始化功能面板，限制群聊统计范围与并发，将趋势扫描改为手动触发，取消过期请求，并为大结果增加分页和原始下载。 |
| [@onewilk](https://github.com/onewilk) | [#81](https://github.com/teest114514/chatlog_alpha/pull/81)、[#82](https://github.com/teest114514/chatlog_alpha/pull/82)、[#83](https://github.com/teest114514/chatlog_alpha/pull/83)、[#84](https://github.com/teest114514/chatlog_alpha/pull/84)、[#85](https://github.com/teest114514/chatlog_alpha/pull/85) | 基于微信 4.1.x 实测补充 OpenIM 企业归属、webhook `owner_wxid`、`Name2Id` 群聊回填、联系人/群聊缓存刷新和群聊 @ 列表解析；当前保留刷新失败旧快照、同步关闭、并发读写和 `source` 优先于 `compress_content` 的回归保护。 |
| [@TnzGit](https://github.com/TnzGit) | [#68](https://github.com/teest114514/chatlog_alpha/pull/68) | 历史上修复大批量 Embedding 成功响应被 2 MiB 截断的问题。语义/Embedding 实验功能现已下线，贡献记录保留。 |
| [@ouyadi](https://github.com/ouyadi) | [#64](https://github.com/teest114514/chatlog_alpha/pull/64)、[#65](https://github.com/teest114514/chatlog_alpha/pull/65) | 历史上整合 MCP 请求取消、查询降采样、语义检索与索引白名单，并贡献消息钩子白名单快路径、CORS/Host 与数据库路径边界检查。MCP/语义实验功能现已下线，仍适用的安全修复继续保留。 |
| [@marswjf](https://github.com/marswjf) | [#59](https://github.com/teest114514/chatlog_alpha/pull/59)、[#60](https://github.com/teest114514/chatlog_alpha/pull/60) | 整合 Windows 主进程精确识别与 PID 缓存、Action CLI、媒体代理字段、RecordInfo 嵌套资源、Rec 媒体路径和历史账号回填；Action CLI 后续演进为当前结构化 `chatlog ops`。 |
| [@think2011](https://github.com/think2011) | [#54](https://github.com/teest114514/chatlog_alpha/pull/54) | 对旧版 webhook、WAL 自动更新、文件锁和时间范围问题进行了系统验证；当前保留 WAL 无提交时的全量回退和临时文件锁处理，旧查询路径已由 messagehook 与直读 WCDB 架构替换。 |
| [@jingmian](https://github.com/jingmian) | [#18](https://github.com/teest114514/chatlog_alpha/pull/18) | 补充图片密钥扫描的实测提示：需要触发样本时优先打开朋友圈图片。 |
| [Dependabot](https://github.com/apps/dependabot) | [#23](https://github.com/teest114514/chatlog_alpha/pull/23)、[#75](https://github.com/teest114514/chatlog_alpha/pull/75)、[#80](https://github.com/teest114514/chatlog_alpha/pull/80) | 持续提供依赖更新与安全修复建议，当前依赖升级仍按兼容性测试和安全扫描结果吸收。 |

## 能力

- 多进程、多账号发现与切换
- macOS 数据库密钥、图片密钥提取
- 会话、消息、联系人、群聊、收藏、朋友圈查询
- 图片、视频、语音、附件读取与解密
- 数据库浏览、跨库搜索、只读 SQL、CSV/Excel 导出
- POST、Hermes Weixin、Hermes QQ 消息推送
- 面向 LLM 的自描述 CLI 与机器可读 API 目录

## 安全边界

Chatlog 能读取完整聊天数据，只应在可信本机运行：

- HTTP 仅允许监听 `localhost`、`127.0.0.0/8` 或 `::1`，默认 `127.0.0.1:5030`。
- 禁止监听 `0.0.0.0`、局域网或公网地址。
- 数据库以只读、`query_only` 模式连接。
- 配置、密钥和 Hermes 环境文件使用 `0600`，配置目录使用 `0700`。
- Hermes Token/Secret 只写不回显。
- 朋友圈媒体代理拒绝私网、loopback、link-local、用户信息 URL 及非 HTTP(S) 协议，响应上限 64 MiB。

不要通过反向代理、端口映射或隧道公开 Web 控制台。

## 安装

从 [Latest Build](https://github.com/teest114514/chatlog_alpha/releases/tag/latest) 下载对应平台压缩包。macOS 示例：

```bash
chmod +x chatlog-darwin-arm64
xattr -d com.apple.quarantine chatlog-darwin-arm64 2>/dev/null || true
./chatlog-darwin-arm64
```

数据库密钥提取依赖 Frida：

```bash
python3 -m pip install --user frida-tools
frida --version
```

若 attach 在 Hook 前失败，先检查当前用户、微信进程所属用户、Developer Tools 授权与 `task_for_pid` 权限。

## 快速开始

### TUI

```bash
chatlog
```

在 TUI 中依次选择账号、获取数据库密钥、获取图片密钥、启动 HTTP 服务，然后访问 [http://127.0.0.1:5030](http://127.0.0.1:5030)。

### 自动化运维 CLI

```bash
chatlog ops accounts
chatlog ops status --account <account>
chatlog ops database-key --account <account>
chatlog ops image-key --account <account>
chatlog ops database-decrypt --account <account>
chatlog ops server-start --account <account>
chatlog ops decrypt-watch --account <account>
chatlog ops account-select --pid <wechat-pid>
chatlog ops config-set --http-addr 127.0.0.1:5030
```

`ops` 输出 JSON Lines：每行包含 `type`、`action`、`stage`、`timestamp`，并按需包含 `data` 或 `error_code`。长任务会持续输出进度，适合 LLM、守护进程和自动化编排。

### HTTP API CLI

```bash
chatlog api catalog --compact
chatlog api describe history
chatlog api openapi > openapi.json
chatlog api call sessions --param limit=50
chatlog api call history --param chat=filehelper --param limit=100
chatlog api call database_search --param keyword=项目 --param mode=deep
chatlog api call image --path-param key=<media-key> --output ./image.jpg
```

`api catalog --compact` 用低 token 成本列出入口，`api describe` 返回单接口的参数、JSON Schema、响应模式和副作用标记，`api openapi` 生成 OpenAPI 3.1。`api call` 会在发出网络请求前校验必填参数、类型、enum、范围、请求体字段和输出文件要求；具有副作用的操作还要求显式 `--confirm`。完整规范见 **[LLM CLI 调用手册](docs/LLM_CLI.md)**。

## 交互入口

| 入口 | 用途 | 输出 |
| --- | --- | --- |
| TUI | 本机人工初始化、账号与服务管理 | 终端交互界面 |
| Web 控制台 | 仪表盘、消息中心、社交数据、媒体、数据库、推送和 API 契约 | HTML/CSS/JS |
| `chatlog ops` | 密钥、解密、账号和服务生命周期 | JSON Lines |
| `chatlog api` | LLM/脚本调用本地 HTTP 服务 | JSON envelope |
| HTTP JSON API | 程序、插件、自建界面集成 | JSON/媒体文件 |
| POST / Hermes | 对外消息投递 | Webhook / Bot 消息 |

## Web 控制台

控制台包括：

- 会话与群聊/私聊分析仪表盘
- 统一消息中心：全文搜索、未读会话、增量消息、群成员和游标轮询
- 最近会话，可配置 `Limit`（1–500）
- 联系人、群聊、OpenIM 企业信息与精确消息检索
- 朋友圈动态、朋友圈全文搜索、互动通知与微信收藏
- 图片/视频/语音/附件预览、数据文件读取与朋友圈媒体代理
- 数据库文件卡片、表浏览、分页、行搜索、只读 SQL 和导出
- 推送中心：规则/渠道分区、运行状态卡、Hermes 高级设置、最近事件卡片
- API 状态页：Ping、Catalog、OpenAPI 下载与接口筛选

前端资源内嵌于二进制，不依赖第三方 CDN。统计图表由原生 HTML/CSS/SVG 渲染，无需 ECharts 或其他图表库。推送事件在页面激活时每 3 秒读取持久化事件记录，后台不使用 SSE，也不会维持长连接。状态卡同时显示增量扫描耗时、游标数、待投递数和死信数；事件卡会展示一条消息命中的全部规则及每个渠道的 pending/retry/sent/dead 状态。测试会要求 Web 控制台对 Catalog 中全部 39 个 operation 做出交互、间接媒体或开发工具接入，新增 API 不能静默遗漏。

表单字段按 Catalog/handler 契约发送：消息关键词是字面量匹配，历史查询的时间范围可选；所有整数输入都拒绝小数、尾随字符和越界值；群聊、OpenIM、媒体 URL、数据相对路径、Webhook 与 Hermes URL 会在请求前校验。服务端对 Catalog 声明了范围的 `limit`、`offset`、`mode`、`format`、布尔值和 enum 同样返回单个 HTTP 400 JSON 错误，不再静默改成默认值或拼接两个错误对象。

`/api/v1/new_messages` 是轮询接口，不是系统通知或长连接。首次调用默认从最近 24 小时开始，响应按全局时间顺序返回最早的待读消息；调用方必须把 `new_state` JSON 序列化成一个字符串后原样传回，优先放在 `X-Chatlog-State` 请求头，避免会话游标进入 URL、浏览器历史和访问日志（`state` 查询参数仅用于兼容旧客户端）。Catalog/OpenAPI 将这两个输入标成 `string` 而不是 exploded object。游标由会话时间和数据库 `local_id` 共同定位，同一秒多条消息不会互相覆盖；达到 `Limit` 时只推进已返回消息，`has_more=true` 表示仍有积压，`partial_errors` 表示本轮有会话读取失败且这些会话未推进。Web 自动轮询为 5 秒，上一请求完成前不会并发发起下一轮。

### 消息 Hook 推送架构

消息 Hook 不再使用“每轮只扫最近若干会话/消息并同步发送”的内存状态。当前链路是：

```text
WCDB message/session 文件变化
        │ fsnotify 唤醒（5 秒周期扫描兜底）
        ▼
按 (create_time, local_id) 分页增量读取
        ▼
规则匹配并一次性写入 SQLite cursor + outbox
        ▼
3 个独立 worker 投递 POST / Hermes Weixin / Hermes QQ
        ▼
sent / retry / dead 状态持久化
```

- 游标按 `account + talker` 保存，并用 `create_time + db_local_id` 定位；扫描所有会话，每页 500 条，不再存在固定 300 会话或单会话 300 消息上限。
- 消息游标与 outbox 在同一 SQLite 事务提交，进程异常退出后不会因内存状态丢失而静默漏发。
- 事件 ID 由 `account + talker + seq` 稳定生成；POST 同时发送相同的 `Idempotency-Key`。语义是 **at-least-once**，接收端仍应按该 key 去重。
- 投递失败按指数退避重试，最多尝试 12 次后进入 `dead`；清空 Web 事件历史只隐藏记录，不会删除尚未完成的投递。
- 运行数据统一位于 `<WorkDir>/runtime/hook.db`，权限为 `0600`，SQLite 使用 WAL 和 `synchronous=FULL`。首次启动会把旧 `hook_events.json` 迁入数据库并删除旧文件。
- Hook 配置通过单次快照原子替换；扫描器不会读取到关键词、渠道、URL 和上下文数量彼此混杂的中间状态。

## HTTP JSON API

### 自描述目录

```bash
curl -s http://127.0.0.1:5030/api/v1/meta | jq
curl -s http://127.0.0.1:5030/api/v1/openapi.json | jq
chatlog api catalog --compact | jq
```

当前目录包含 **39 个已注册 endpoint**，路由、CLI catalog 和 OpenAPI 由测试强制对齐：

| 分类 | 数量 | 覆盖 |
| --- | ---: | --- |
| system | 4 | health、ping、API meta、OpenAPI 3.1 |
| chat | 7 | sessions、history、search、unread、members、new messages、stats |
| social | 4 | favorites、SNS notifications/feed/search |
| address_book | 3 | contacts、chatrooms、OpenIM corp |
| database | 6 | DB 列表、跨库搜索、表、数据、SQL、缓存 |
| media | 6 | image、video、voice、file、data、SNS media proxy |
| push | 9 | config、status、events、Hermes Weixin/QQ |

### 覆盖结论

HTTP JSON API 对**服务启动后的现有 Web 产品功能**覆盖完整：router、Catalog、OpenAPI 和 Web 接入测试当前均覆盖同一组 39 个 operation。这里的“完整”不等于所有微信业务表都已有专用语义接口，也不等于 OpenAPI 已描述每个成功响应的全部字段；目前多数 JSON 成功响应仍是 generic object schema，调用方应以实际 JSON、`/api/v1/meta` 和本节字段说明为准。以下高权限操作故意只留在 TUI/`chatlog ops`：

- 账号选择
- 数据库/图片密钥提取
- 数据库解密与持续监听
- HTTP 服务启动/停止
- 持久运行配置修改

因此，LLM 的完整调用链是：`chatlog ops` 完成初始化与生命周期管理，`chatlog api` 完成服务内查询与控制。

### 数据库与语义覆盖

- `/api/v1/db` 对同一个物理数据库只返回一个规范分组，避免 `hardlink.db`、`media_*.db` 在多个分组重复出现。
- `/api/v1/db/tables` 返回当前 SQLite 驱动可直接浏览的表。依赖未加载 FTS5 模块的虚表入口会被过滤，其可读 shadow table 仍可浏览；表清单中的每一项都应能被 `/api/v1/db/data` 打开。
- 数据库浏览与 SQL 连接同时启用 `mode=ro` 和 `query_only`；SQL 入口还会拒绝多语句和 `INSERT`、`UPDATE`、`DELETE`、DDL 等写语句，只接受只读 `SELECT`、`WITH`、`EXPLAIN` 和 `PRAGMA`。
- 会话、普通/公众号消息、联系人、群聊、收藏、朋友圈与媒体已有专用 API；`biz_message_N.db` 会和普通消息 shard 一起进入 history/search，语音会遍历全部 `media_N.db` shard。
- history 的 `offset` 表示跳过较新的消息，各页互不重复，页内仍按时间正序；`total_count` 在过滤后、分页前计算。收藏、未读会话和朋友圈过滤也不会再因固定倍数预取窗口而漏掉较旧匹配项。
- `general`、`emoticon`、`bizchat`、`head_image`、`migrate` 等库目前主要通过通用数据库 API 读取。好友申请/陌生人、联系人标签、会话草稿/隐藏状态、删除记录、转账/红包、通话、撤回记录、表情包、企业会话、朋友圈草稿/发布错误、收藏标签与完整收藏结构仍缺少独立的解析模型、API 和 Web 页面。
- `migrate/unspportmsg.db` 中的兼容消息、群成员 proto 的附加状态、消息 `AtUserList`/record assets、联系人描述/企业字段以及 SNS 通知关联动态详情，尚未全部进入公开 DTO。物理表可读不代表这些字段已完成语义解析。

消息类接口同时返回可读类型名和原始映射字段：`type`、`type_num`、`sub_type`。为兼容既有调用方，`local_id` 仍是跨时间拼接后的稳定消息 ID，并增加同值别名 `message_id`；数据库原始 `local_id` 明确放在 `db_local_id`。

### 常用 HTTP 示例

```bash
curl 'http://127.0.0.1:5030/api/v1/sessions?query=项目&limit=50'
curl 'http://127.0.0.1:5030/api/v1/history?chat=filehelper&time=last-30d&limit=100&offset=0'
curl 'http://127.0.0.1:5030/api/v1/search?keyword=报价&limit=20'
curl 'http://127.0.0.1:5030/api/v1/db/search?keyword=项目&mode=deep&limit=100'
curl 'http://127.0.0.1:5030/api/v1/hook/events?limit=50'
```

以 `/api/v1/meta`、`/api/v1/openapi.json` 或 `chatlog api catalog` 为准，不在 README 手工复制易漂移的完整路由表。

时间范围使用 `last-7d`、`last-30d`、`last-3m`、`today`、`this-month` 或 `2026-07-01~2026-07-31`；不要使用未定义的 `7d`/`30d`。HTTP 错误响应统一为对象：

```json
{"error":"invalid argument: time"}
```

## 配置与运行数据

默认情况下，Chatlog 只创建一个持久化根目录 `~/.chatlog`；配置、日志、运行状态、缓存和解密工作区全部位于其下：

```text
~/.chatlog/
├── chatlog.json
├── chatlog.pid
├── log/chatlog.log
├── cache/
│   ├── filecopy/
│   ├── sns_wasm/
│   └── wcdb/
└── workspaces/<account>/
    ├── runtime/hook.db
    ├── cache/sns/
    └── cache/weixin_media/
```

设置 `CHATLOG_DIR=/path/to/root` 会整体重定位这棵目录，而不是只修改配置文件位置。旧版本自动创建的 `~/Documents/chatlog/<account>`（macOS）或 `~/chatlog/<account>` 会在目标目录不存在或为空时原子迁入新根目录；用户手动设置的自定义 `work_dir` 不会被改写。

微信原始 `DataDir` 是微信自身目录，不由 Chatlog 创建。密钥提取仍会兼容读写其中已有的 `all_keys.json`；旧版 `<DataDir>/chatlog.json` 仅作兼容读取，当前版本不再向 `DataDir` 写项目配置、Hook 事件或下载缓存。Hermes 的 `~/.hermes` 属于外部 Hermes 安装目录，也不属于 Chatlog 运行根目录。

## 从源码构建

要求 Go `1.25+`：

```bash
git clone https://github.com/teest114514/chatlog_alpha.git
cd chatlog_alpha
go test ./...
go build -trimpath -o chatlog .
```

完整验证：

```bash
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
```

CI 构建 macOS amd64/arm64、Windows amd64/arm64。所有检查和构建成功后才更新 `latest` release；失败不会删除上一版可用资产。

## 已知边界

- Windows 密钥提取和运行表现仍需按微信版本实机复核。
- 静态测试不能替代真实微信 attach、密钥提取和数据库解密验证。

## 反馈

提交问题时请附操作系统/架构、微信完整版本、Chatlog commit/release、脱敏日志和最小复现步骤。

[GitHub Issues](https://github.com/teest114514/chatlog_alpha/issues)
