# chatlog_alpha

微信 4.x 聊天记录本地查询工具（macOS），支持：
- 重启微信后自动提取 Data Key（内置实现，不依赖外部 DLL）
- 获取 Image Key（内存扫描）
- 查询 `db_storage` 下多库数据
- 提供 HTTP + MCP 接口（wx-cli 风格）

## ⚠ 方案 1（可执行文件自动 root）必读

若你选择“方案 1（setuid root）”，请在编译后执行：

```bash
BIN_PATH="/你的项目路径/dist/chatlog-mac"
sudo chown root:wheel "$BIN_PATH"
sudo chmod 4755 "$BIN_PATH"
ls -l "$BIN_PATH"
```

或者在项目根目录直接执行（自动取当前目录）：

```bash
BIN_PATH="$(pwd)/dist/chatlog-mac"
sudo chown root:wheel "$BIN_PATH"
sudo chmod 4755 "$BIN_PATH"
ls -l "$BIN_PATH"
```

看到权限类似 `-rwsr-xr-x` 说明生效。每次重新编译后都需要重新执行上述命令。

> 重要：仅有 root 权限仍可能不够。若要稳定进行内存扫描（取 Data Key / Image Key），通常还需要先关闭 SIP（System Integrity Protection）。

## 当前状态（2026-04）

- 已移除 Windows 支持与外部 `wx_key.dll` 依赖
- macOS V4 已接入内置 key 扫描与 `all_keys.json` 回退/兼容流程
- HTTP 接口默认输出 `YAML`，可通过 `format=json` 输出 JSON
- 旧接口（如 `/api/v1/chatlog`、`/api/v1/session`、`/api/v1/contact`、`/api/v1/chatroom`、`/api/v1/sns`）已移除

## 运行环境

- Go 1.22+（建议）
- 微信 4.x
- 平台：macOS

macOS 额外要求：
- 建议使用 `sudo` 启动程序（内存读取依赖 `task_for_pid` 权限）
- 建议提前关闭 SIP（否则即使 root 也可能无法读取微信进程内存）
- 需要启用 `cgo`（未启用时无法进行 macOS 内存扫描）

## 快速开始

### 1) 启动 TUI

```bash
go run .
```

或编译后运行：

```bash
go build -o chatlog ./cmd/chatlog
./chatlog
```

### 2) 推荐操作顺序（macOS）

1. 在 TUI 点击“重启并获取密钥”
2. 等微信重启后完成登录，并打开聊天窗口
3. 程序会优先尝试：
   - 读取已存在 `all_keys.json`
   - 或执行内存扫描并写入/更新 `all_keys.json`
4. 点击“解密数据”后可启动 HTTP 服务查询

## `all_keys.json` 说明

`all_keys.json` 用于保存每个加密数据库文件对应的 `enc_key`，典型内容如下：

```json
{
  "message/message_0.db": { "enc_key": "..." },
  "contact/contact.db": { "enc_key": "..." }
}
```

作用：
- key 扫描结果持久化
- 程序重启后可直接复用
- 与 `wechat-decrypt` / `wx-cli` 流程兼容

常见路径（按账号目录）：
- `<data-dir>/all_keys.json`
- `<data-dir>/../all_keys.json`

## 常用命令（CLI）

### 启动 HTTP 服务

```bash
chatlog server -a :5030 -p darwin -v 4 -d <wechat_data_dir>
```

### 手动解密

```bash
chatlog decrypt -p darwin -v 4 -d <wechat_data_dir> -k <data_key>
```

### 批量解密 `.dat` 图片

```bash
chatlog batch-decrypt --data-dir <wechat_data_dir> --data-key <data_key> --platform darwin --version 4
```

### macOS key helper

```bash
chatlog mac-key-helper --pid <wechat_pid> --data-dir <wechat_data_dir>
```

## HTTP 接口

基础：
- `GET /health`
- `GET /api/v1/ping`

媒体：
- `GET /image/*key`
- `GET /video/*key`
- `GET /file/*key`
- `GET /voice/*key`
- `GET /data/*path`

wx-cli 兼容查询：
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
- `GET /api/v1/db/tables`
- `GET /api/v1/db/data`
- `GET /api/v1/db/query`
- `POST /api/v1/cache/clear`

### 输出格式

默认：`YAML`

可选：`JSON`

示例：

```bash
curl "http://127.0.0.1:5030/api/v1/history?chat=xxx&limit=50"
curl "http://127.0.0.1:5030/api/v1/history?chat=xxx&limit=50&format=json"
```

## MCP

端点：
- `ANY /mcp`
- `ANY /sse`
- `ANY /message`

当前 MCP Tools：
- `current_time`
- `get_media_content`
- `ocr_image_message`
- `send_webhook_notification`
- `get_user_profile`
- `search_shared_files`
- `wx_ping`
- `wx_contacts`
- `wx_chatrooms`
- `wx_sessions`
- `wx_history`
- `wx_search`
- `wx_unread`
- `wx_members`
- `wx_new_messages`
- `wx_stats`
- `wx_favorites`
- `wx_sns_notifications`
- `wx_sns_feed`
- `wx_sns_search`

## macOS 排障

### 1) 提示权限不足 / `task_for_pid` 失败

现象：
- `scan memory failed`
- `需要 root + task_for_pid 权限`

处理：
- 使用 `sudo` 启动程序
- 确保微信已登录并进入聊天界面后再触发扫描
- 若仍失败，优先走 `all_keys.json` 方式（先成功生成一次）

### 2) 提示未找到 `all_keys.json`

处理：
- 先执行“重启并获取密钥”完成一次扫描
- 确认账号目录下已生成 `all_keys.json`
- 检查文件读写权限

### 3) 图片密钥 60 秒超时

处理：
- 登录微信后打开任意聊天图片，触发 `*_t.dat` 缓存
- 再次点击“获取图片密钥”

## 目录结构（核心）

- `cmd/chatlog`：CLI 入口
- `internal/chatlog`：TUI、流程编排、HTTP/MCP
- `internal/wechat/key`：平台密钥提取实现
- `internal/wechat/decrypt`：数据库解密实现
- `internal/wechatdb`：数据库访问与查询

## 安全与隐私

- 所有处理在本地完成
- 请妥善保管解密后的数据与密钥文件

## 免责声明

详见 [DISCLAIMER.md](./DISCLAIMER.md)
