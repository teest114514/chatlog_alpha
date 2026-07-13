# Chatlog Alpha

[![Release](https://github.com/teest114514/chatlog_alpha/actions/workflows/release.yml/badge.svg)](https://github.com/teest114514/chatlog_alpha/actions/workflows/release.yml)
[![Go](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go)](https://go.dev/)
[![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey)](#平台兼容性)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

Chatlog Alpha 是面向微信 4.x 的本地聊天数据读取、查询与分析工具，提供：

- 终端交互界面（TUI）
- Web 管理与数据浏览界面
- HTTP API 与 MCP 服务
- 跨数据库搜索、仪表盘和媒体读取
- 可选的语义检索、RAG 问答和时间知识图谱
- 关键词事件与 Hermes Weixin / QQ 推送

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

### 4. 按 TUI 步骤操作

1. **切换账号**：确认选择了正确的微信账号。
2. **重启并获取数据库密钥**：TUI 会显示明确的 6 步进度。
3. 等待微信重新启动并完成登录。
4. **获取图片密钥**：仅在需要查看部分加密媒体时执行。
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

- Go `1.24` 或更高版本
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

### MCP

支持以下入口：

- `ANY /mcp`
- `ANY /mcp/`
- `ANY /sse`
- `ANY /message`

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
