package help

import (
	"fmt"

	"github.com/sjzar/chatlog/internal/ui/style"

	"github.com/rivo/tview"
)

const (
	Title     = "help"
	ShowTitle = "帮助"
	Content   = `[yellow]Chatlog 使用指南[white]

[green]基本操作:[white]
• 使用 [yellow]←→[white] 键在主菜单和帮助页面之间切换
• 使用 [yellow]↑↓[white] 键在菜单项之间移动
• 按 [yellow]Enter[white] 选择菜单项
• 按 [yellow]Esc[white] 返回上一级菜单
• 按 [yellow]Ctrl+C[white] 退出程序

[green]使用步骤:[white]

[yellow]1. 下载并安装微信客户端[white]

[yellow]2. 迁移手机微信聊天记录[white]
   手机微信上操作 [yellow]我 - 设置 - 通用 - 聊天记录迁移与备份 - 迁移 - 迁移到电脑[white]。
   这一步的目的是将手机中的聊天记录传输到电脑上。
   可以放心操作，不会影响到手机上的聊天记录。

[yellow]3. 解密数据[white]
   重新打开 chatlog，选择"解密数据"菜单项，程序会使用获取的密钥解密微信数据库文件。
   macOS V4 下优先使用 all_keys.json + 内置查询链路，无需依赖工作目录。

[yellow]4. 启动 HTTP 服务[white]
   选择"启动 HTTP 服务"菜单项，启动 HTTP 和 MCP 服务。
   启动后可以通过浏览器访问 http://localhost:5030 查看聊天记录。

[yellow]5. 设置选项[white]
   选择"设置"菜单项，可以配置:
   • HTTP 服务端口 - 更改 HTTP 服务的监听端口
   • 数据目录 - 更改微信数据目录

[green]HTTP API 使用:[white]
• 会话列表(wx-cli): [yellow]GET http://localhost:5030/api/v1/sessions?limit=20[white]
• 聊天记录(wx-cli): [yellow]GET http://localhost:5030/api/v1/history?chat=wxid_xxx&time=2023-01-01[white]
• 搜索(wx-cli): [yellow]GET http://localhost:5030/api/v1/search?keyword=项目&chats=工作群[white]
• 联系人列表(wx-cli): [yellow]GET http://localhost:5030/api/v1/contacts?limit=20[white]
• 群聊列表(wx-cli): [yellow]GET http://localhost:5030/api/v1/chatrooms?limit=20[white]
• 朋友圈动态(wx-cli): [yellow]GET http://localhost:5030/api/v1/sns_feed?limit=20[white]

[green]MCP 集成:[white]
Chatlog 支持 Model Context Protocol，可与支持 MCP 的 AI 助手集成。
通过 MCP，AI 助手可以直接查询您的聊天记录、联系人和群聊信息。

[green]常见问题:[white]
• 如果获取密钥失败，请确保微信程序正在运行
• 如果解密失败，请检查密钥是否正确获取
• 如果 HTTP 服务启动失败，请检查端口是否被占用
• 数据目录会自动保存，下次启动时自动加载

[green]数据安全:[white]
• 所有数据处理均在本地完成，不会上传到任何外部服务器
• 请妥善保管解密后的数据，避免隐私泄露
`
)

type Help struct {
	*tview.TextView
	title string
}

func New() *Help {
	help := &Help{
		TextView: tview.NewTextView(),
		title:    Title,
	}

	help.SetDynamicColors(true)
	help.SetRegions(true)
	help.SetWrap(true)
	help.SetTextAlign(tview.AlignLeft)
	help.SetBorder(true)
	help.SetBorderColor(style.BorderColor)
	help.SetTitle(ShowTitle)

	fmt.Fprint(help, Content)

	return help
}
