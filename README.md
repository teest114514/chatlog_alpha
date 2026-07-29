# Chatlog Alpha

> [!IMPORTANT]
> ## 用户订阅（置顶）
> 因收到腾讯方面关于侵权问题的投诉，本仓库已停止公开源代码、构建产物和历史 Release，仅保留项目说明。
>
> **项目状态、更新通知与用户订阅入口：**
> **[加入 Telegram 订阅](https://t.me/+zy1N_8leq8IxYmY8)**

Chatlog Alpha 是面向微信 4.x 的本地聊天数据读取与自动化工具。项目用于发现本机微信账号、提取和管理密钥、只读查询 WCDB、解密媒体，并通过 TUI、Web、结构化 CLI 和本机 HTTP JSON API 提供统一入口。

## 当前项目状态

- GitHub 云端仓库仅保留本 README，不再公开项目源代码或二进制构建产物。
- 当前项目已移除原生文本/图片发信、发信调试、常驻注入 Session、语义检索、时序图谱和 MCP 实验功能。
- 当前保留的核心方向是本地数据读取、数据库解密、媒体处理、结构化查询、消息推送和本机自动化接口。
- 后续状态变化、版本说明和用户通知统一通过置顶的 Telegram 订阅入口发布。

## 当前能力

- 多进程、多账号发现与切换
- macOS 数据库密钥、图片密钥提取
- 会话、消息、联系人、群聊、收藏和朋友圈查询
- 图片、视频、语音与附件读取、解密
- 数据库浏览、跨库搜索、只读 SQL、CSV/Excel 导出
- POST、Hermes Weixin、Hermes QQ 消息推送
- 面向 LLM 的自描述 CLI 与机器可读 HTTP API 目录
- TUI、Web 控制台与结构化 `chatlog ops` / `chatlog api` 接口

## 已移除功能

以下能力已从当前项目代码中完整移除：

- `chatlog send` 原生文本/图片发送 CLI
- `/api/v1/send-debug/*` 原生发信调试接口
- Web 控制台“发信调试”页面及其静态资源
- Frida 原生发信脚本、图片上传 Agent、欢迎消息与常驻 Session supervisor
- 语义检索、Embedding、MCP 和时序图谱实验模块

聊天图片读取、图片密钥提取、媒体解密和本地预览仍属于当前项目的数据读取能力，不属于原生发图功能。

## 安全边界

Chatlog 可读取本机完整聊天数据，应仅在可信本机环境运行：

- HTTP 仅监听 `localhost`、`127.0.0.0/8` 或 `::1`，默认地址为 `127.0.0.1:5030`。
- 数据库以只读和 `query_only` 模式连接。
- 配置、密钥及 Hermes 环境文件使用受限文件权限。
- Hermes Token 与 Secret 只写入配置，不通过状态接口回显。
- 朋友圈媒体代理限制私网、loopback、link-local、用户信息 URL、协议及响应大小。
- Web 控制台不应通过反向代理、端口映射或隧道公开。

## 当前接口概览

当前 HTTP Catalog 包含 39 个 endpoint，覆盖：

| 分类 | 数量 | 说明 |
| --- | ---: | --- |
| system | 4 | 健康检查、Ping、API Catalog、OpenAPI |
| chat | 7 | 会话、历史、搜索、未读、群成员、增量消息、统计 |
| social | 4 | 收藏、朋友圈通知、动态与搜索 |
| address_book | 3 | 联系人、群聊、OpenIM 企业信息 |
| database | 6 | 数据库、跨库搜索、表、数据、只读 SQL、缓存 |
| media | 6 | 图片、视频、语音、附件、数据文件、朋友圈媒体代理 |
| push | 9 | 推送配置、状态、事件、Hermes Weixin/QQ |

高权限的账号选择、密钥提取、数据库解密、服务生命周期和持久配置仍由本机 TUI 或结构化 `chatlog ops` 管理。

## 运行数据

默认持久化根目录为 `~/.chatlog`：

```text
~/.chatlog/
├── chatlog.json
├── chatlog.pid
├── log/chatlog.log
├── cache/
└── workspaces/<account>/
    ├── runtime/hook.db
    └── cache/
```

微信原始数据目录由微信自身管理，不属于 Chatlog 的运行根目录。

## 获取通知

GitHub 当前不提供源代码、Release 或安装包下载。项目状态及后续通知请使用置顶入口：

### [Telegram 用户订阅：https://t.me/+zy1N_8leq8IxYmY8](https://t.me/+zy1N_8leq8IxYmY8)

## 贡献致谢

感谢以下贡献者曾提交问题复现、实测数据与实现方案。相关功能后续即使重构或下线，贡献记录仍予保留：

| 贡献者 | Pull Request | 贡献摘要 |
| --- | --- | --- |
| [@ameriadam12](https://github.com/ameriadam12) | [#90](https://github.com/teest114514/chatlog_alpha/pull/90) | 大型数据集下仪表盘与历史查询性能优化。 |
| [@onewilk](https://github.com/onewilk) | [#81](https://github.com/teest114514/chatlog_alpha/pull/81)–[#85](https://github.com/teest114514/chatlog_alpha/pull/85) | OpenIM、Webhook、群聊回填、缓存刷新与群聊 @ 解析。 |
| [@TnzGit](https://github.com/TnzGit) | [#68](https://github.com/teest114514/chatlog_alpha/pull/68) | 历史 Embedding 响应截断修复；相关实验功能现已下线。 |
| [@ouyadi](https://github.com/ouyadi) | [#64](https://github.com/teest114514/chatlog_alpha/pull/64)、[#65](https://github.com/teest114514/chatlog_alpha/pull/65) | MCP、语义检索、索引与消息钩子安全改进；仍适用的修复继续保留。 |
| [@marswjf](https://github.com/marswjf) | [#59](https://github.com/teest114514/chatlog_alpha/pull/59)、[#60](https://github.com/teest114514/chatlog_alpha/pull/60) | Windows 进程识别、Action CLI、媒体与历史账号支持。 |
| [@think2011](https://github.com/think2011) | [#54](https://github.com/teest114514/chatlog_alpha/pull/54) | Webhook、WAL、文件锁与时间范围问题验证。 |
| [@jingmian](https://github.com/jingmian) | [#18](https://github.com/teest114514/chatlog_alpha/pull/18) | 图片密钥扫描实测建议。 |
| [Dependabot](https://github.com/apps/dependabot) | [#23](https://github.com/teest114514/chatlog_alpha/pull/23)、[#75](https://github.com/teest114514/chatlog_alpha/pull/75)、[#80](https://github.com/teest114514/chatlog_alpha/pull/80) | 依赖更新与安全修复建议。 |

## 声明

Chatlog Alpha 为非官方项目，与腾讯或微信不存在隶属、授权或合作关系。“腾讯”“微信”及相关名称和标识归其权利人所有。使用者应遵守所在地法律法规、软件许可和平台规则，并自行负责本地数据与账号安全。
