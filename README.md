# Chatlog Alpha

[![Release](https://github.com/teest114514/chatlog_alpha/actions/workflows/release.yml/badge.svg)](https://github.com/teest114514/chatlog_alpha/actions/workflows/release.yml)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev/)
[![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey)](#平台兼容性)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

## 置顶：macOS 发信 Hook 调试说明

> 当前发信能力仍是**测试/调试功能**，主要为后续“自动发消息 / Bot 编排”做底层验证；目前只实现了**文本发送**和**图片发送**。欢迎 PR 拓展更多消息类型、更多微信版本 profile、群聊长 receiver 适配、队列/重试策略和更完整的机器人能力。

当前已验证环境：macOS WeChat `4.1.11.54`，`wechat.dylib` SHA256：

```text
4b6029ecb7d14a08afc1179db0d6c481b8f06826d835de6599b9dd8164c3e097
```

所有地址均为 `wechat.dylib` 内偏移，运行时地址计算方式：

```text
runtime_address = module.base + offset
```

### 关键 Hook 点

| 名称 | Offset | 用途 |
|---|---:|---|
| `sendFuncAddr` | `0x5121458` | MMStartTask 主发送函数 |
| `sendFuncHookAddr` | `0x5121468` | 捕获真实发送上下文 `x0` |
| `defaultStartTaskFuncAddr` | `0x51173b0` | 默认 MMSTN manager wrapper；当前文本/图片主动发送默认走这里 |
| `req2bufEnterHookAddr` | `0x3e5930c` | Req2Buf 入口，按 task id 替换 `x19+0x60` 为 synthetic message object |
| `req2bufExitHookAddr` | `0x3e5a260` | Req2Buf 退出，只做等待 ack 的观测 |
| `blrX8HookAddr` | `0x3e5938c` | serializer 间接调用前，向 `sp+0x140` AutoBuffer 写入 protobuf |
| `autoBufferWriteFunc` | `0x3e7ff18` | 写 AutoBuffer 的原生函数 |
| `buf2RespAckHookAddr` | `0x3e7eaf0` | 真正 ack 点，匹配 task id 后清理 fake 指针并 finish |
| `logBuf2RespFunc` | `0x51233f8` | 仅日志观测，不能当 cleanup ack |
| `uploadImageAddr` | `0x529c1fc` | 图片上传底层入口 |
| `uploadImageHookAddr` | `0x529c20c` | 捕获 upload 上下文 |
| `uploadImageEntryWrapperAddr` | `0x525a008` | 主动图片上传 wrapper |
| `cndOnCompleteAddr` | `0x3e15be8` | CDN 上传完成回调，读取 cdn/aes/md5 |
| `uploadGetCallbackWrapperAddr` | `0x525afa0` | patch get-callback wrapper |
| `uploadGetCallbackWrapperFuncAddr` | `0x3e15484` | 已验证 get-callback method |
| `uploadOnCompleteAddr` | `0x525b758` | patch on-complete wrapper |
| `uploadOnCompleteFuncAddr` | `0x3e16608` | 已验证 on-complete method |
| `uploadRsaPreflightAddr` | `0x529bba0` | 只读诊断上传 manager/RSA 状态 |

机器可读 profile 和复现步骤维护在：

```text
test/wechat_sender/skills/wechat-macos-hook-discovery/
```

### 方法调用逻辑

文本发送：

```text
构造 text protobuf
-> 构造 MMStartTask payload
-> defaultStartTaskFunc(payload)
-> Req2Buf 命中 task id，在 x19+0x60 插入 synthetic text object
-> blrX8HookAddr 写 protobuf 到 AutoBuffer
-> buf2RespAckHookAddr 匹配 task id
-> insert_cleanup(strategy=null)
-> finish
```

图片发送：

```text
复制图片到微信容器短路径并追加私有副本 MD5 salt
-> uploadImageEntryWrapperAddr(upload_x1)
-> cndOnCompleteAddr 读取 cdn_key / aes_key / md5
-> 构造 image protobuf
-> defaultStartTaskFunc(payload)
-> Req2Buf 命中 task id，在 x19+0x60 插入 synthetic image object
-> blrX8HookAddr 写 protobuf 到 AutoBuffer
-> buf2RespAckHookAddr 匹配 task id
-> insert_cleanup(strategy=null)
-> finish
-> 图片 session 最终受控重启微信释放 Frida trampoline 风险
```

当前实现重点防坑：

- `logBuf2RespFunc` 不是 ack，不能在这里释放 fake object。
- default wrapper 下同一 task 可能二次进入 Req2Buf；必须保留第一次 `insertedOriginal`，不能把 fake pointer 当 original 写回。
- 图片 upload x1 默认保持已验证的静态短字符串布局；动态长字段/群聊长 receiver 需要单独 PR 和 live 证据。
- 发过图片的 session 不热卸载，最终走受控重启；纯文本/只读 smoke 才执行 `force_cleanup -> script.unload -> session.detach -> frida.shutdown`。

## 贡献致谢（置顶）

感谢以下贡献者提交问题复现、实测数据和实现方案。本轮已基于最新 `main` 逐项复核，并把仍适用于当前架构的部分重新整合：

| 贡献者 | Pull Request | 本轮吸收与反馈 |
|---|---|---|
| [@TnzGit](https://github.com/TnzGit) | [#68](https://github.com/teest114514/chatlog_alpha/pull/68) | 修复大批量 Embedding 成功响应被 2MB 截断的问题，并保留大响应回归测试。 |
| [@ouyadi](https://github.com/ouyadi) | [#64](https://github.com/teest114514/chatlog_alpha/pull/64)、[#65](https://github.com/teest114514/chatlog_alpha/pull/65) | 整合 MCP 五分钟超时与请求取消、消息查询降采样、`wx_semantic_search`、索引会话白名单、消息钩子白名单快路径、CORS/Host 与数据库路径边界检查。 |
| [@marswjf](https://github.com/marswjf) | [#59](https://github.com/teest114514/chatlog_alpha/pull/59)、[#60](https://github.com/teest114514/chatlog_alpha/pull/60) | 整合 Windows 主进程精确识别与 PID 缓存、Action CLI、媒体代理字段、RecordInfo 嵌套资源、Rec 媒体路径和历史账号回填。 |
| [@think2011](https://github.com/think2011) | [#54](https://github.com/teest114514/chatlog_alpha/pull/54) | 对旧版 webhook、WAL 自动更新、文件锁和时间范围问题进行了系统验证；本轮适配了 WAL 无提交时的全量回退和临时文件锁处理，旧 webhook/时间范围路径已由 messagehook + 直读 WCDB 架构替换。 |
| [@jingmian](https://github.com/jingmian) | [#18](https://github.com/teest114514/chatlog_alpha/pull/18) | 补充图片密钥扫描的实测提示：需要触发样本时优先打开朋友圈图片。 |
| [Dependabot](https://github.com/apps/dependabot) | [#23](https://github.com/teest114514/chatlog_alpha/pull/23)、[#75](https://github.com/teest114514/chatlog_alpha/pull/75)、[#80](https://github.com/teest114514/chatlog_alpha/pull/80) | 依赖更新建议已复核：吸收 jsonparser `v1.1.2` 等兼容补丁；在 Go 1.26 发布、Go 1.24 退出支持后，将最低版本提升到 Go 1.25，并更新 Excelize `v2.11.0`、`x/crypto v0.53.0`、`x/net v0.56.0` 及相关安全修复。 |

Chatlog Alpha 是面向微信 4.x 的本地聊天数据读取、查询与分析工具，提供：

- 终端交互界面（TUI）
- Web 管理与数据浏览界面
- HTTP API 与 MCP 服务
- 跨数据库搜索、仪表盘和媒体读取
- 可选的语义检索、RAG 问答和时间知识图谱
- 关键词事件与 Hermes Weixin / QQ 推送
- macOS 原生文本/图片发信调试（严格区分私聊与群聊）

数据库解密、查询和缓存默认在本机执行。使用 GLM、DeepSeek 等远程模型时，相关功能会把选中的检索文本发送到你配置的模型服务；使用 Ollama 或兼容的本地 llama.cpp 服务时可保持模型处理在本机。

> 当前重点验证环境：**macOS + 微信 Mac 版 4.1.11.54**。Windows 构建可用，但密钥提取仍属于实验性能力。

## 目录

- [平台兼容性](#平台兼容性)
- [下载安装](#下载安装)
- [macOS 快速开始](#macos-快速开始)
- [Windows 快速开始](#windows-快速开始)
- [源码构建](#源码构建)
- [使用方式](#使用方式)
- [HTTP API 与 MCP](#http-api-与-mcp)
- [语义检索与时间知识图谱](#语义检索与时间知识图谱)
- [权限与数据目录](#权限与数据目录)
- [GitHub 自动构建](#github-自动构建)
- [常见问题](#常见问题)

## 主要功能

### 数据读取与查询

- 自动发现微信账号和数据目录
- 按数据库逐一验证并保存 `all_keys.json` 密钥映射
- 支持消息、联系人、群聊、收藏、朋友圈等数据接口
- 数据库表浏览、SQL 查询和跨库全局搜索
- 自动处理 WAL，并维护本地解密查询缓存
- 支持合法空数据库，例如 `weclaw.db`、`solitaire.db`

### Web 与仪表盘

- 会话、历史消息、联系人和群聊浏览
- 群聊对比、消息趋势、活跃时段和发言人排行
- 数据库浏览、全局搜索和媒体访问
- 关键词推送配置与事件查看
- 独立“发信调试”Tab：环境检查、Hook smoke、私聊/群聊目标校验、手动释放 Frida 和逐步清理反馈
- 语义检索、问答、索引管理和时间知识图谱页面

### 集成能力

- HTTP API
- MCP：`/mcp`、`/sse`、`/message`
- Hermes Agent Weixin / QQ 推送
- Ollama、llama.cpp、GLM、DeepSeek 模型配置

## 平台兼容性

| 平台 | 架构 | 数据库密钥方式 | 当前状态 |
|---|---|---|---|
| macOS | Intel `amd64` | Frida Hook `CCKeyDerivationPBKDF` | 已验证 |
| macOS | Apple Silicon `arm64` | Frida Hook `CCKeyDerivationPBKDF` | 已验证 |
| Windows | `amd64` | 微信进程内存扫描 | 实验性，建议管理员权限 |
| Windows | `arm64` | 微信进程内存扫描 | 实验性，部分 CGO 能力受限 |

macOS 当前实现会在微信启动时短暂安装 Hook，首个候选出现后继续收集约 5 秒，然后依次卸载脚本、断开会话并关闭 Frida 运行时。密钥会按数据库页实际验证，不再把一个未经验证的密钥直接分配给所有数据库。

## 下载安装

从 [Latest Build](https://github.com/teest114514/chatlog_alpha/releases/tag/latest) 下载与你的平台匹配的压缩包：

| 系统 | 处理器 | 文件名格式 |
|---|---|---|
| macOS | Apple Silicon | `chatlog_<提交>_darwin_arm64.zip` |
| macOS | Intel | `chatlog_<提交>_darwin_amd64.zip` |
| Windows | x64 | `chatlog_<提交>_windows_amd64.zip` |
| Windows | ARM64 | `chatlog_<提交>_windows_arm64.zip` |

压缩包同时包含 `README.md` 和 `LICENSE`。Release 页面还会附带未压缩的可执行文件。

### 直接下载未压缩文件

GitHub 的单文件下载不会携带 macOS 的 Unix 可执行权限位，因此直接下载
`chatlog-darwin-arm64` 后需要先赋予执行权限：

```bash
curl -fL https://github.com/teest114514/chatlog_alpha/releases/download/latest/chatlog-darwin-arm64 \
  -o chatlog-darwin-arm64
chmod 755 chatlog-darwin-arm64
# 浏览器下载带有隔离标记时执行；命令行 curl 下载通常没有该标记
xattr -d com.apple.quarantine chatlog-darwin-arm64 2>/dev/null || true
./chatlog-darwin-arm64 --help
```

更推荐下载上表中的 `.zip` 压缩包：其中的 `chatlog-darwin-arm64` 已保留 `755`
权限，解压后可以直接运行。若终端提示 `permission denied`，重新执行
`chmod 755 chatlog-darwin-arm64` 即可。

macOS 压缩包同时提供 `start-chatlog.command`。解压后在 Finder 中双击该文件，
系统会自动打开终端并启动 Chatlog。启动文件会定位同目录的对应架构二进制、
恢复其执行权限并清理二进制的下载隔离标记。首次启动若出现系统确认窗口，
可在 Finder 中右键 `start-chatlog.command`，选择“打开”。

不知道 macOS 架构时可执行：

```bash
uname -m
```

- 输出 `arm64`：下载 `darwin_arm64`
- 输出 `x86_64`：下载 `darwin_amd64`

## macOS 快速开始

### 1. 准备微信数据

1. 安装并登录微信 Mac 版。
2. 如需手机历史记录，在手机微信中进入：`我 → 设置 → 通用 → 聊天记录迁移与备份`。
3. 保持微信能够正常自动登录。

### 2. 安装 Frida

macOS 数据库密钥仅通过 Frida 获取。请使用当前登录用户安装：

```bash
python3 --version
python3 -m pip install --user -U frida-tools
python3 -c "import frida; print(frida.__version__)"
```

不要使用 `sudo pip`。Chatlog 和微信都应以当前桌面登录用户运行，否则微信可能进入错误的用户容器。

### 3. 启动 Chatlog

以 Apple Silicon 压缩包为例：

```bash
unzip chatlog_*_darwin_arm64.zip
chmod +x chatlog-darwin-arm64
./chatlog-darwin-arm64
```

也可以解压后在 Finder 中双击：

```text
start-chatlog.command
```

该启动文件会打开终端并运行同目录下的 `chatlog-darwin-arm64`。

### 4. 按 TUI 步骤操作

1. **切换账号**：确认选择了正确的微信账号。
2. **重启并获取数据库密钥**：TUI 会显示明确的 6 步进度。
3. 等待微信重新启动并完成登录。
4. **获取图片密钥**：仅在需要查看部分加密媒体时执行。
   - 如果界面提示需要图片验证样本，请优先在微信朋友圈中打开一张图片；部分微信版本打开聊天图片不会生成可识别样本。
5. **解密数据**：建立本地工作目录。
6. **启动 HTTP 服务**：浏览器访问 <http://127.0.0.1:5030/>。

数据库密钥流程完成时应看到：

```text
✓ 1/6 检查 Frida 环境
✓ 2/6 重启并启动微信
✓ 3/6 挂载进程并安装 Hook
✓ 4/6 短时收集各数据库候选密钥
✓ 5/6 卸载 Hook 并断开会话
✓ 6/6 逐库验证密钥并保存映射
```

### macOS 命令行提取密钥

```bash
# 自动探测账号目录
./chatlog-darwin-arm64 key

# 指定账号目录
./chatlog-darwin-arm64 key \
  --data-dir "$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<账号目录>"

# 只输出 data key
./chatlog-darwin-arm64 key --json
```

可选环境变量：

```bash
export CHATLOG_FRIDA_SCRIPT=/absolute/path/to/scripts/wechat_key_frida.py
export WECHAT_EXE=/Applications/WeChat.app/Contents/MacOS/WeChat
```

通常不需要设置；发布版已内嵌 Frida 脚本。

## Windows 快速开始

解压后运行对应程序：

```powershell
.\chatlog-windows-amd64.exe
```

Windows 当前通过读取微信进程内存提取数据库和图片密钥：

- 建议以管理员身份启动 Chatlog。
- 请先启动并登录微信。
- 数据库提取仍处于实验阶段，微信更新后扫描模式可能发生变化。
- `windows/arm64` 使用非 CGO 构建，语音转 MP3 等依赖 CGO 的能力会显示相应提示。

遇到问题请在 [Issues](https://github.com/teest114514/chatlog_alpha/issues) 中附上 Windows 版本、微信版本、架构和脱敏后的错误信息。

## 源码构建

### 环境要求

- Go `1.25` 或更高版本
- Git
- 支持 CGO 的 C 编译器
- macOS 数据库提钥额外需要 Python 3 与 `frida-tools`

### 构建当前平台

```bash
git clone https://github.com/teest114514/chatlog_alpha.git
cd chatlog_alpha

go test ./...
mkdir -p bin
CGO_ENABLED=1 go build -trimpath -o bin/chatlog .
./bin/chatlog
```

也可以使用 Makefile：

```bash
make clean
make build
```

跨平台发布建议直接使用仓库的 GitHub Actions；Windows `amd64` 构建需要 MinGW GCC。

## 使用方式

### TUI

直接运行不带子命令的可执行文件即可进入 TUI：

```bash
./bin/chatlog
```

基本按键：

- `↑` / `↓`：移动
- `Enter`：确认
- `Esc`：返回
- `Ctrl+C`：退出

### CLI

```bash
# 查看可调用接口
./bin/chatlog http list

# 查询会话历史
./bin/chatlog http call \
  --endpoint history \
  --query chat=<会话ID> \
  --query limit=100 \
  --query format=json

# 跨库搜索
./bin/chatlog http call \
  --path /api/v1/db/search \
  --query keyword=项目 \
  --query mode=deep \
  --query limit=100

# 执行只读查询示例
./bin/chatlog http call \
  --path /api/v1/db/query \
  --query group=message \
  --query file=message_0.db \
  --query 'sql=SELECT count(*) AS total FROM MSG'
```

更多 CLI 接口说明见 [`skills/chatlog-http-cli/SKILL.md`](./skills/chatlog-http-cli/SKILL.md)。

### Action CLI（JSON Lines）

面向前端、脚本和调试面板的动作接口会逐行输出 JSON 状态：

```bash
# 账号与状态
./bin/chatlog action list-accounts
./bin/chatlog action status --pid <微信PID>

# 密钥与数据
./bin/chatlog action restart-and-get-key --pid <微信PID>
./bin/chatlog action get-image-key --pid <微信PID>
./bin/chatlog action decompress-data --history <历史账号名>

# 长时间运行服务
./bin/chatlog action start-http --history <历史账号名>
./bin/chatlog action start-auto-decompress --history <历史账号名>
```

其他命令：`action set`、`action switch-account`。每个事件包含 `type`、`action`、`stage`、`message`、`timestamp`，成功结果放在 `data`。

### Web 原生发信调试

Web 控制台的“发信调试”Tab 提供可控生命周期的 macOS Frida 发送链路：

1. 检查微信版本、Python、Frida 和主进程。
2. 严格选择私聊 `user_id` 或群聊 `group_id`；群 ID 必须以 `@chatroom` 结尾。
3. 先执行“仅检查 Hook，不发送”。
4. 明确确认后执行一次文本或图片发送。
5. Hook 检查或首次发送成功后，Frida hooks/session 继续保持连接，“继续发送”按钮会启用。
6. 可以修改目标与内容并连续点击“继续发送”；请求会进入有序队列，在同一个 Frida session 内逐条执行，不会重复 attach。
7. 全部发送完成后点击“释放 Frida”：文本/只读任务显示 force_cleanup、script.unload、session.detach、frida.shutdown、helper 兜底和微信健康检查；执行过图片上传的 session 会显示 generation 安全窗口、受控重启微信、helper 清理、新 PID 健康检查，不再热卸载。

发送任务使用单一混合常驻 session：文本和图片共用一次 attach 与同一条有序队列，切换消息类型不会释放 Hook、不会重启微信，也不会建立第二个 session。为避免共享 native 状态竞争，图文命令按提交顺序串行执行；机器人可以连续交替提交。只有只读 Hook 检查切换到真实发送时才会结束检查 session 并建立混合发送 session。执行失败、点击“强制停止并清理”或 Chatlog 服务退出时会自动走相同释放链；优先用 Frida 官方 API 关闭 Script、Session 与 DeviceManager，只有本次 Python 宿主的直属 helper 仍残留时才 TERM/KILL，绝不全局清理其他 Frida 任务。常驻期间不能启动第二个发信调试任务；刷新 Web 页面后会自动恢复活动任务、待发送数量和释放按钮。

文本连续发送收到 `Buf2Resp ack` 后只保留约 0.5 秒节流即可处理下一条；文本与图片最终释放的最小安全窗口统一为 **5 秒**。若 session 已空闲超过 5 秒，释放会立即进行。每次图片上传前都会使用短文件名复制出一份当前微信账号容器内的私有暂存副本，并把完整路径限制为 **176 个 UTF-8 字节以内**。这既满足 macOS 沙箱，也为已捕获的 synthetic `upload x1` 路径存储保留容量余量；agent 会按实际 UTF-8 字节数写入三个路径字段长度，不再沿用捕获样本的固定 178。接收方会按 libc++ short/long string 布局动态编码，支持私聊和 `@chatroom` 群 ID。每条命令仍分配独立 native generation（upload x1、callback table、路径/密钥缓冲区、image send object 和 task payload）。旧 generation 与对应暂存图片在 5 秒安全窗口内保持不变，上一张图片收到 ack 后即可立即开始下一张；窗口到期的 generation 会进入复用池并删除暂存文件，避免机器人长时间运行时无限增长。图片发送阶段通过 `module.base + 0x51173b0` 的默认 MMSTN manager wrapper 发起任务，不再依赖碰巧捕获其他网络请求的 `StartTask x0`。只有表示上传服务未就绪的 `-20001` 会在微信启动后的 180 秒窗口内每 15 秒重试；`-20003` 表示参数或路径校验失败，不在同一 PID 上空等 180 秒。上传尚未完成时，外层兜底最多受控重启微信并重试整个链路一次，不要求用户重复点击。由于微信图片 callback coroutine 可能在固定等待后仍经过 Frida trampoline，图片 session 最终释放会受控重启微信，而不是继续执行已复现 SIGSEGV 和下次 attach 超时的热卸载流程。

微信会对相同图片进行 CDN/MD5 去重；重复发送时回调可能出现 `cdn_len=194` 但 `aes_len=0`。已经 CDN 去重的对象与它原有的 AES 密钥配对，不能用本次新 request 的 AES 硬填。项目会在上述私有暂存副本末尾追加随机 `#chatlog_md5_salt_...#`，不修改源图，使每次 MD5 唯一；如仍收到 AES 为空的不完整回调，只显示等待并继续监听，不会误报 `finish`。Web 真实复测对同一源图首次发送加连续三次发送均得到 `rv=0`、`aes_len=32` 和 ack，`completed_sends=4`。

机器人接入可复用同一组本机 API：`POST /api/v1/send-debug/jobs` 建立 session，等待返回状态中的 `session_ready=true`，再通过 `POST /api/v1/send-debug/jobs/{id}/send` 连续提交消息；接口返回独立 `command_id`，可用 `GET /api/v1/send-debug/jobs/{id}/commands/{command_id}` 查询 `queued/running/succeeded/failed`。`pending_commands` 和 `completed_sends` 可用于背压与监控，结束时调用 `POST /api/v1/send-debug/jobs/{id}/release`。文本队列上限为 256，图片队列上限为 8；队列满时接口返回 `409`，调用方应等待后重试。

当前发信 Hook profile 只支持 **macOS arm64 + 微信 4.1.11.54**。文本与图片脚本已内嵌到发布二进制；Windows 构建使用独立 stub，不会加载 macOS Hook。图片发送仍属于实验功能，建议先向 `filehelper` 验证。发信调试 API 只接受本机回环地址请求，即使 HTTP 服务监听在局域网地址，也不能从其他机器触发 Frida 发信。

## HTTP API 与 MCP

HTTP 服务默认监听 `0.0.0.0:5030`，本机访问地址为：

```text
http://127.0.0.1:5030/
```

如果不需要局域网访问，建议在配置中将监听地址限制为 `127.0.0.1:5030`。

常用接口：

| 类别 | 接口 |
|---|---|
| 健康检查 | `GET /health`、`GET /api/v1/ping` |
| 会话与消息 | `GET /api/v1/sessions`、`GET /api/v1/history`、`GET /api/v1/search` |
| 联系人与群聊 | `GET /api/v1/contacts`、`GET /api/v1/chatrooms`、`GET /api/v1/members` |
| 朋友圈 | `GET /api/v1/sns_feed`、`GET /api/v1/sns_search` |
| 数据库 | `GET /api/v1/db`、`GET /api/v1/db/tables`、`GET /api/v1/db/query` |
| 全局搜索 | `GET /api/v1/db/search` |
| 媒体 | `/image/*key`、`/video/*key`、`/voice/*key`、`/file/*key` |
| 语义能力 | `/api/v1/semantic/*` |
| 时间图谱 | `/api/v1/graph/*` |
| 关键词推送 | `/api/v1/hook/*` |
| 本机发信调试 | `/api/v1/send-debug/*` |

### MCP

支持以下入口：

- `ANY /mcp`
- `ANY /mcp/`
- `ANY /sse`
- `ANY /message`

除会话、历史、搜索等兼容工具外，MCP 还提供 `wx_semantic_search`，可直接调用现有向量索引进行跨会话语义检索。

Hermes Agent 示例：

```yaml
mcp_servers:
  chatlog:
    url: "http://127.0.0.1:5030/mcp"
    enabled: true
    connect_timeout: 60
    timeout: 120
```

也可以执行：

```bash
hermes mcp add chatlog --url http://127.0.0.1:5030/mcp
hermes mcp test chatlog
```

## 语义检索与时间知识图谱

这些能力为可选的增强模块，入口位于 Web 页面的“实验性功能”和“时间知识图谱”。

默认本地检索配置：

| 项 | 默认值 |
|---|---|
| Embedding Provider | `ollama` |
| Embedding Model | `qwen3-embedding:8b` |
| Embedding Base URL | `http://127.0.0.1:11434` |
| Rerank Model | `dengcao/Qwen3-Reranker-8B:Q5_K_M` |
| Chat Provider | `glm`，需要自行配置 API Key |

`embedding_provider=ollama` 同时兼容 Ollama 和提供 OpenAI Embeddings 接口的本地服务。使用 llama.cpp 时示例：

```bash
llama-server -m /path/to/embedding.gguf --embeddings -c 512 --port 8080
```

然后在 Web 配置中把 `ollama_base_url` 设置为 `http://127.0.0.1:8080`，并填写与模型一致的向量维度。

索引文件：

- 语义索引：`<WorkDir>/.chatlog_semantic/vector_index.db`
- 时间图谱：`<WorkDir>/.chatlog_graph/temporal_graph.db`

更换 Embedding 模型或维度后，需要重新构建向量索引。

如只需索引指定会话，可在语义配置中设置：

```yaml
index_chatrooms:
  - "123456789@chatroom"
  - "wxid_example"
```

## 权限与数据目录

### macOS

- **数据库 data key 不需要 root 权限。**
- 数据库密钥流程使用当前用户的 Frida，并在完成后释放 Hook、会话和运行时。
- “获取图片密钥”会先尝试本地推导；只有进程内存读取明确缺少权限时，才弹出系统管理员授权窗口。
- 临时提权只用于短生命周期的图片密钥扫描子进程，TUI 本身仍以普通用户运行。
- 历史 `all_keys.json` 若属于 root，TUI 会提示并请求一次授权修复文件所有权与权限。

### Windows

- 进程内存扫描通常需要管理员权限。
- Chatlog 与微信架构应匹配，优先使用 `windows_amd64` 构建。

### 主要文件位置

| 文件 | 位置 |
|---|---|
| 数据库密钥映射 | 微信账号目录下的 `all_keys.json` |
| 账号运行配置 | 数据目录下的 `chatlog.json` |
| macOS 默认工作目录 | `~/Documents/chatlog/<账号>/` |
| Windows 默认工作目录 | `~/chatlog/<账号>/` |
| 查询缓存 | `~/.chatlog/wcdb_cache/` |

`all_keys.json` 包含敏感密钥，默认以 `0600` 权限写入。不要把密钥、解密数据库、聊天内容或模型 API Key 提交到 Git 仓库。

## GitHub 自动构建

工作流文件：[`release.yml`](./.github/workflows/release.yml)

每次 `push` 的发布顺序：

1. 取消同组仍在运行的旧发布任务。
2. 删除旧的 `latest` Release 及其 Git 标签。
3. 删除旧的 `release-macos`、`release-windows` Actions Artifacts。
4. macOS 和 Windows 构建机分别删除本次工作区中的 `dist/`、`release/`。
5. 重新构建四个平台产物。
6. 上传新的 Artifacts，并创建新的 `Latest Build` 预发布版本。

构建矩阵：

- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`（CGO + MinGW GCC）
- `windows/arm64`（非 CGO）

由于旧 Release 会在编译前删除，如果新构建失败，`latest` 页面会暂时不存在；修复构建后重新推送即可生成新的发布。

## 常见问题

### Frida 未捕获到密钥

1. 确认 `python3 -c "import frida"` 成功。
2. 确认微信能够自动登录。
3. 登录后打开任意聊天窗口再重试。
4. 增加等待时间：`chatlog key --timeout 300`。
5. 确认没有使用 `sudo` 启动 Chatlog 或微信。

### 卡在“Frida script unloaded”附近

当前版本在结构化清理完成后会主动关闭 Frida 运行时，并由 Go 宿主提供有限时间的退出兜底。重新运行后，TUI 应继续进入第 6 步，而不是停在卸载提示。

### `weclaw.db` 或 `solitaire.db` 没有表

这两个文件可能是微信预先创建的一页空数据库。只要查询不再报告密钥错误且 SQLite 完整性检查通过，表数量为 `0` 属于正常状态。

### HTTP 页面打不开

- 确认 TUI 已显示“已启动 HTTP 服务”。
- 检查 `5030` 端口是否被其他程序占用。
- 本机使用 <http://127.0.0.1:5030/>，不要使用数据库文件路径作为网址。

### Windows 提取失败

以管理员身份重新运行，并确认微信已经登录。提交 Issue 时请附上系统版本、微信版本、CPU 架构和脱敏日志。

## 开发与验证

提交前建议运行：

```bash
gofmt -w <修改的 Go 文件>
go test ./...
git diff --check
```

Windows 非 CGO 交叉编译检查：

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

## 反馈与许可

- 问题反馈：[GitHub Issues](https://github.com/teest114514/chatlog_alpha/issues)
- 许可协议：[MIT License](./LICENSE)

请仅处理你有权访问的本地数据，并妥善保管生成的密钥、缓存与解密结果。
