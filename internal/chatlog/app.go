package chatlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sjzar/chatlog/internal/chatlog/ctx"
	"github.com/sjzar/chatlog/internal/ui/footer"
	"github.com/sjzar/chatlog/internal/ui/form"
	"github.com/sjzar/chatlog/internal/ui/help"
	"github.com/sjzar/chatlog/internal/ui/infobar"
	"github.com/sjzar/chatlog/internal/ui/menu"
	"github.com/sjzar/chatlog/internal/wechat"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	RefreshInterval = 1000 * time.Millisecond
)

type App struct {
	*tview.Application

	ctx         *ctx.Context
	m           *Manager
	stopRefresh chan struct{}

	// page
	mainPages *tview.Pages
	infoBar   *infobar.InfoBar
	tabPages  *tview.Pages
	footer    *footer.Footer

	// tab
	menu      *menu.Menu
	help      *help.Help
	activeTab int
	tabCount  int
}

func NewApp(ctx *ctx.Context, m *Manager) *App {
	app := &App{
		ctx:         ctx,
		m:           m,
		Application: tview.NewApplication(),
		mainPages:   tview.NewPages(),
		infoBar:     infobar.New(),
		tabPages:    tview.NewPages(),
		footer:      footer.New(),
		menu:        menu.New("主菜单"),
		help:        help.New(),
	}

	app.initMenu()

	app.updateMenuItemsState()

	return app
}

func (a *App) Run() error {

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(a.infoBar, infobar.InfoBarViewHeight, 0, false).
		AddItem(a.tabPages, 0, 1, true).
		AddItem(a.footer, 1, 1, false)

	a.mainPages.AddPage("main", flex, true, true)

	a.tabPages.
		AddPage("0", a.menu, true, true).
		AddPage("1", a.help, true, false)
	a.tabCount = 2

	a.SetInputCapture(a.inputCapture)

	go a.refresh()

	if err := a.SetRoot(a.mainPages, true).EnableMouse(false).Run(); err != nil {
		return err
	}

	return nil
}

func (a *App) Stop() {
	// 添加一个通道用于停止刷新 goroutine
	if a.stopRefresh != nil {
		close(a.stopRefresh)
	}
	a.Application.Stop()
}

func (a *App) updateMenuItemsState() {
	for _, item := range a.menu.GetItems() {
		// 更新HTTP服务菜单项
		if item.Index == 5 {
			if a.ctx.HTTPEnabled {
				item.Name = "停止 HTTP 服务"
				item.Description = "停止本地 HTTP & MCP 服务器"
			} else {
				item.Name = "启动 HTTP 服务"
				item.Description = "启动本地 HTTP & MCP 服务器"
			}
		}
	}
}

func (a *App) switchTab(step int) {
	index := (a.activeTab + step) % a.tabCount
	if index < 0 {
		index = a.tabCount - 1
	}
	a.activeTab = index
	a.tabPages.SwitchToPage(fmt.Sprint(a.activeTab))
}

func (a *App) refresh() {
	tick := time.NewTicker(RefreshInterval)
	defer tick.Stop()

	for {
		select {
		case <-a.stopRefresh:
			return
		case <-tick.C:
			var processErr error
			// 对齐 wechat-log 的刷新思路：每轮基于最新进程列表重绑定当前实例，避免使用陈旧对象导致状态漂移。
			instances, err := a.m.wechat.GetWeChatInstancesWithError()
			processErr = err
			if err == nil {
				a.ctx.WeChatInstances = instances
				best := selectCurrentInstance(a.ctx.Current, instances)
				switch {
				case best != nil && (a.ctx.Current == nil || a.ctx.Current.PID != best.PID || a.ctx.Current.Name != best.Name):
					a.ctx.SwitchCurrent(best)
				case best != nil:
					// 同一个实例也刷新字段，确保 Status/DataDir 与 detector 最新结果一致。
					a.ctx.Current = best
					a.ctx.Refresh()
				case a.ctx.Current != nil:
					// 当前实例已不在进程列表中，标记离线并刷新展示。
					a.ctx.Current.Status = "offline"
					a.ctx.Refresh()
				}
			}

			if a.ctx.HTTPEnabled {
				a.m.RefreshSession()
			}
			a.infoBar.UpdateAccount(a.ctx.Account)
			a.infoBar.UpdateBasicInfo(a.ctx.PID, a.ctx.FullVersion, a.ctx.ExePath)
			statusText := a.ctx.Status
			if a.ctx.PID == 0 && processErr != nil {
				statusText = fmt.Sprintf("[red]获取进程失败: %v[white]", processErr)
			}
			a.infoBar.UpdateStatus(statusText)
			a.infoBar.UpdateDataKey(a.ctx.DataKey)
			a.infoBar.UpdateImageKey(a.ctx.ImgKey)
			a.infoBar.UpdatePlatform(a.ctx.Platform)
			a.infoBar.UpdateDataUsageDir(a.ctx.DataUsage, a.ctx.DataDir)
			allKeysPath, allKeysStatus := resolveAllKeysDisplay(a.ctx.DataDir)
			a.infoBar.UpdateAllKeys(allKeysStatus, allKeysPath)
			if a.ctx.LastSession.Unix() > 1000000000 {
				a.infoBar.UpdateSession(a.ctx.LastSession.Format("2006-01-02 15:04:05"))
			}
			if a.ctx.HTTPEnabled {
				a.infoBar.UpdateHTTPServer(fmt.Sprintf("[green][已启动][white] [%s]", a.ctx.HTTPAddr))
			} else {
				a.infoBar.UpdateHTTPServer("[未启动]")
			}
			// Update latest message in footer
			if session, err := a.m.GetLatestSession(); err == nil && session != nil {
				sender := session.NickName
				if sender == "" {
					sender = session.UserName
				}
				a.footer.UpdateLatestMessage(sender, session.NTime.Format("15:04:05"), session.Content)
			}

			a.Draw()
		}
	}
}

func selectCurrentInstance(current *wechat.Account, instances []*wechat.Account) *wechat.Account {
	if len(instances) == 0 {
		return nil
	}
	if current == nil {
		return instances[0]
	}

	// 1) PID 精确匹配（最可靠）
	for _, inst := range instances {
		if inst != nil && current.PID != 0 && inst.PID == current.PID {
			return inst
		}
	}
	// 2) Name 匹配（账号切换场景）
	for _, inst := range instances {
		if inst != nil && current.Name != "" && inst.Name == current.Name {
			return inst
		}
	}
	// 3) ExePath 匹配（重启后 PID 变化）
	for _, inst := range instances {
		if inst != nil && current.ExePath != "" && inst.ExePath == current.ExePath {
			return inst
		}
	}
	// 4) 回退：使用第一项
	return instances[0]
}

func resolveAllKeysDisplay(dataDir string) (path string, status string) {
	clean := filepath.Clean(dataDir)
	if clean == "" || clean == "." {
		return "all_keys.json", "[yellow]未配置数据目录[white]"
	}
	base := filepath.Base(clean)
	if base == "db_storage" {
		path = filepath.Join(filepath.Dir(clean), "all_keys.json")
	} else {
		path = filepath.Join(clean, "all_keys.json")
	}
	if _, err := os.Stat(path); err == nil {
		return path, "[green]可读[white]"
	}
	if _, err := os.Stat(path); err != nil && os.IsPermission(err) {
		return path, "[red]无权限[white]"
	}
	return path, "[yellow]不存在[white]"
}

func (a *App) inputCapture(event *tcell.EventKey) *tcell.EventKey {

	// 如果当前页面不是主页面，ESC 键返回主页面
	if a.mainPages.HasPage("submenu") && event.Key() == tcell.KeyEscape {
		a.mainPages.RemovePage("submenu")
		a.mainPages.SwitchToPage("main")
		return nil
	}

	if a.tabPages.HasFocus() {
		switch event.Key() {
		case tcell.KeyLeft:
			a.switchTab(-1)
			return nil
		case tcell.KeyRight:
			a.switchTab(1)
			return nil
		}
	}

	switch event.Key() {
	case tcell.KeyCtrlC:
		a.Stop()
	}

	return event
}

func (a *App) initMenu() {
	getDataKey := &menu.Item{
		Index:       2,
		Name:        "获取图片密钥",
		Description: "扫描内存获取图片密钥(需微信V4)",
		Selected: func(i *menu.Item) {
			modal := tview.NewModal()
			modal.SetText("正在扫描内存获取图片密钥...\n请确保微信已登录并浏览过图片")
			a.mainPages.AddPage("modal", modal, true, true)
			a.SetFocus(modal)

			go func() {
				err := a.m.GetImageKey()

				// 在主线程中更新UI
				a.QueueUpdateDraw(func() {
					if err != nil {
						// 解密失败
						modal.SetText("获取图片密钥失败: " + err.Error())
					} else {
						// 解密成功
						modal.SetText("获取图片密钥成功")
					}

					// 添加确认按钮
					modal.AddButtons([]string{"OK"})
					modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
						a.mainPages.RemovePage("modal")
					})
					a.SetFocus(modal)
				})
			}()
		},
	}

	restartAndGetDataKey := &menu.Item{
		Index:       3,
		Name:        "重启并获取密钥",
		Description: "结束当前微信进程，重启后获取密钥",
		Selected: func(i *menu.Item) {
			modal := tview.NewModal().SetText("正在准备重启微信...")
			a.mainPages.AddPage("modal", modal, true, true)
			a.SetFocus(modal)

			go func() {
				// 定义状态更新回调
				onStatus := func(msg string) {
					a.QueueUpdateDraw(func() {
						modal.SetText(msg)
					})
				}

				err := a.m.RestartAndGetDataKey(onStatus)

				a.QueueUpdateDraw(func() {
					if err != nil {
						modal.SetText("操作失败: " + err.Error())
					} else {
						modal.SetText("操作成功，请检查密钥是否已更新")
					}

					modal.AddButtons([]string{"OK"})
					modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
						a.mainPages.RemovePage("modal")
					})
					a.SetFocus(modal)
				})
			}()
		},
	}

	decryptData := &menu.Item{
		Index:       4,
		Name:        "解密数据",
		Description: "解密数据文件",
		Selected: func(i *menu.Item) {
			// 创建一个没有按钮的模态框，显示"解密中..."
			modal := tview.NewModal().
				SetText("解密中...")

			a.mainPages.AddPage("modal", modal, true, true)
			a.SetFocus(modal)

			// 在后台执行解密操作
			go func() {
				// 执行解密
				err := a.m.DecryptDBFiles()

				// 在主线程中更新UI
				a.QueueUpdateDraw(func() {
					if err != nil {
						// 解密失败
						modal.SetText("解密失败: " + err.Error())
					} else {
						// 解密成功
						modal.SetText("解密数据成功")
					}

					// 添加确认按钮
					modal.AddButtons([]string{"OK"})
					modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
						a.mainPages.RemovePage("modal")
					})
					a.SetFocus(modal)
				})
			}()
		},
	}

	httpServer := &menu.Item{
		Index:       5,
		Name:        "启动 HTTP 服务",
		Description: "启动本地 HTTP & MCP 服务器",
		Selected: func(i *menu.Item) {
			modal := tview.NewModal()

			// 根据当前服务状态执行不同操作
			if !a.ctx.HTTPEnabled {
				// HTTP 服务未启动，启动服务
				modal.SetText("正在启动 HTTP 服务...")
				a.mainPages.AddPage("modal", modal, true, true)
				a.SetFocus(modal)

				// 在后台启动服务
				go func() {
					err := a.m.StartService()

					// 在主线程中更新UI
					a.QueueUpdateDraw(func() {
						if err != nil {
							// 启动失败
							modal.SetText("启动 HTTP 服务失败: " + err.Error())
						} else {
							// 启动成功
							modal.SetText("已启动 HTTP 服务")
						}

						// 更改菜单项名称
						a.updateMenuItemsState()

						// 添加确认按钮
						modal.AddButtons([]string{"OK"})
						modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
							a.mainPages.RemovePage("modal")
						})
						a.SetFocus(modal)
					})
				}()
			} else {
				// HTTP 服务已启动，停止服务
				modal.SetText("正在停止 HTTP 服务...")
				a.mainPages.AddPage("modal", modal, true, true)
				a.SetFocus(modal)

				// 在后台停止服务
				go func() {
					err := a.m.StopService()

					// 在主线程中更新UI
					a.QueueUpdateDraw(func() {
						if err != nil {
							// 停止失败
							modal.SetText("停止 HTTP 服务失败: " + err.Error())
						} else {
							// 停止成功
							modal.SetText("已停止 HTTP 服务")
						}

						// 更改菜单项名称
						a.updateMenuItemsState()

						// 添加确认按钮
						modal.AddButtons([]string{"OK"})
						modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
							a.mainPages.RemovePage("modal")
						})
						a.SetFocus(modal)
					})
				}()
			}
		},
	}

	setting := &menu.Item{
		Index:       6,
		Name:        "设置",
		Description: "设置应用程序选项",
		Selected:    a.settingSelected,
	}

	selectAccount := &menu.Item{
		Index:       7,
		Name:        "切换账号",
		Description: "切换当前操作的账号，可以选择进程或历史账号",
		Selected:    a.selectAccountSelected,
	}

	a.menu.AddItem(getDataKey)
	a.menu.AddItem(restartAndGetDataKey)
	a.menu.AddItem(decryptData)
	a.menu.AddItem(httpServer)
	a.menu.AddItem(setting)
	a.menu.AddItem(selectAccount)

	a.menu.AddItem(&menu.Item{
		Index:       8,
		Name:        "退出",
		Description: "退出程序",
		Selected: func(i *menu.Item) {
			a.Stop()
		},
	})
}

// settingItem 表示一个设置项
type settingItem struct {
	name        string
	description string
	action      func()
}

func (a *App) settingSelected(i *menu.Item) {

	settings := []settingItem{
		{
			name:        "设置 HTTP 服务地址",
			description: "配置 HTTP 服务监听的地址",
			action:      a.settingHTTPPort,
		},
		{
			name:        "设置数据密钥",
			description: "配置数据解密密钥",
			action:      a.settingDataKey,
		},
		{
			name:        "设置图片密钥",
			description: "配置图片解密密钥",
			action:      a.settingImgKey,
		},
		{
			name:        "设置数据目录",
			description: "配置微信数据文件所在目录",
			action:      a.settingDataDir,
		},
		{
			name:        "设置关键词触发器",
			description: "多个关键词使用 ｜ 分割",
			action:      a.settingHookKeywords,
		},
		{
			name:        "设置触发通知方式",
			description: "可选 mcp / post / both / weixin / all",
			action:      a.settingHookNotifyMode,
		},
		{
			name:        "设置触发 POST 地址",
			description: "通知方式包含 post 时生效",
			action:      a.settingHookPostURL,
		},
		{
			name:        "设置触发前文条数",
			description: "命中关键词前保留条数（默认5）",
			action:      a.settingHookBeforeCount,
		},
		{
			name:        "设置触发后文条数",
			description: "命中关键词后保留条数（默认5）",
			action:      a.settingHookAfterCount,
		},
	}

	subMenu := menu.NewSubMenu("设置")
	for idx, setting := range settings {
		item := &menu.Item{
			Index:       idx + 1,
			Name:        setting.name,
			Description: setting.description,
			Selected: func(action func()) func(*menu.Item) {
				return func(*menu.Item) {
					action()
				}
			}(setting.action),
		}
		subMenu.AddItem(item)
	}

	a.mainPages.AddPage("submenu", subMenu, true, true)
	a.SetFocus(subMenu)
}

// settingHTTPPort 设置 HTTP 端口
func (a *App) settingHTTPPort() {
	// 使用我们的自定义表单组件
	formView := form.NewForm("设置 HTTP 地址")

	// 临时存储用户输入的值
	tempHTTPAddr := a.ctx.HTTPAddr

	// 添加输入字段 - 不再直接设置HTTP地址，而是更新临时变量
	formView.AddInputField("地址", tempHTTPAddr, 0, nil, func(text string) {
		tempHTTPAddr = text // 只更新临时变量
	})

	// 添加按钮 - 点击保存时才设置HTTP地址
	formView.AddButton("保存", func() {
		a.m.SetHTTPAddr(tempHTTPAddr) // 在这里设置HTTP地址
		a.mainPages.RemovePage("submenu2")
		a.showInfo("HTTP 地址已设置为 " + a.ctx.HTTPAddr)
	})

	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})

	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

// settingWorkDir 设置工作目录
func (a *App) settingWorkDir() {
	// 使用我们的自定义表单组件
	formView := form.NewForm("设置工作目录")

	// 临时存储用户输入的值
	tempWorkDir := a.ctx.WorkDir

	// 添加输入字段 - 不再直接设置工作目录，而是更新临时变量
	formView.AddInputField("工作目录", tempWorkDir, 0, nil, func(text string) {
		tempWorkDir = text // 只更新临时变量
	})

	// 添加按钮 - 点击保存时才设置工作目录
	formView.AddButton("保存", func() {
		a.ctx.SetWorkDir(tempWorkDir) // 在这里设置工作目录
		a.mainPages.RemovePage("submenu2")
		a.showInfo("工作目录已设置为 " + a.ctx.WorkDir)
	})

	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})

	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

// settingDataKey 设置数据密钥
func (a *App) settingDataKey() {
	// 使用我们的自定义表单组件
	formView := form.NewForm("设置数据密钥")

	// 临时存储用户输入的值
	tempDataKey := a.ctx.DataKey

	// 添加输入字段 - 不直接设置数据密钥，而是更新临时变量
	formView.AddInputField("数据密钥", tempDataKey, 0, nil, func(text string) {
		tempDataKey = text // 只更新临时变量
	})

	// 添加按钮 - 点击保存时才设置数据密钥
	formView.AddButton("保存", func() {
		a.ctx.DataKey = tempDataKey // 设置数据密钥
		a.mainPages.RemovePage("submenu2")
		a.showInfo("数据密钥已设置")
	})

	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})

	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

// settingImgKey 设置图片密钥 (ImgKey)
func (a *App) settingImgKey() {
	formView := form.NewForm("设置图片密钥")

	tempImgKey := a.ctx.ImgKey

	formView.AddInputField("图片密钥", tempImgKey, 0, nil, func(text string) {
		tempImgKey = text
	})

	formView.AddButton("保存", func() {
		a.ctx.SetImgKey(tempImgKey)
		a.mainPages.RemovePage("submenu2")
		a.showInfo("图片密钥已设置")
	})

	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})

	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

// settingDataDir 设置数据目录
func (a *App) settingDataDir() {
	// 使用我们的自定义表单组件
	formView := form.NewForm("设置数据目录")

	// 临时存储用户输入的值
	tempDataDir := a.ctx.DataDir

	// 添加输入字段 - 不直接设置数据目录，而是更新临时变量
	formView.AddInputField("数据目录", tempDataDir, 0, nil, func(text string) {
		tempDataDir = text // 只更新临时变量
	})

	// 添加按钮 - 点击保存时才设置数据目录
	formView.AddButton("保存", func() {
		a.ctx.DataDir = tempDataDir // 设置数据目录
		a.mainPages.RemovePage("submenu2")
		a.showInfo("数据目录已设置为 " + a.ctx.DataDir)
	})

	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})

	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

func (a *App) settingHookKeywords() {
	formView := form.NewForm("设置关键词触发器")
	tempKeywords := a.ctx.HookKeywords
	formView.AddInputField("关键词", tempKeywords, 0, nil, func(text string) {
		tempKeywords = text
	})
	formView.AddButton("保存", func() {
		a.ctx.SetHookKeywords(tempKeywords)
		a.mainPages.RemovePage("submenu2")
		a.showInfo("关键词触发器已更新")
	})
	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})
	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

func (a *App) settingHookNotifyMode() {
	formView := form.NewForm("设置触发通知方式")
	tempMode := a.ctx.HookNotifyMode
	if strings.TrimSpace(tempMode) == "" {
		tempMode = "mcp"
	}
	formView.AddInputField("方式", tempMode, 0, nil, func(text string) {
		tempMode = text
	})
	formView.AddButton("保存", func() {
		a.ctx.SetHookNotifyMode(tempMode)
		a.mainPages.RemovePage("submenu2")
		a.showInfo("通知方式已更新为 " + a.ctx.HookNotifyMode)
	})
	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})
	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

func (a *App) settingHookPostURL() {
	formView := form.NewForm("设置触发 POST 地址")
	tempURL := a.ctx.HookPostURL
	formView.AddInputField("POST URL", tempURL, 0, nil, func(text string) {
		tempURL = text
	})
	formView.AddButton("保存", func() {
		a.ctx.SetHookPostURL(tempURL)
		a.mainPages.RemovePage("submenu2")
		a.showInfo("POST 地址已更新")
	})
	formView.AddButton("取消", func() {
		a.mainPages.RemovePage("submenu2")
	})
	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

func (a *App) settingHookBeforeCount() {
	formView := form.NewForm("设置触发前文条数")
	temp := fmt.Sprintf("%d", a.ctx.HookBeforeCount)
	formView.AddInputField("前文条数", temp, 0, nil, func(text string) { temp = text })
	formView.AddButton("保存", func() {
		n := 0
		if v, err := strconv.Atoi(strings.TrimSpace(temp)); err == nil && v >= 0 {
			n = v
		}
		a.ctx.SetHookBeforeCount(n)
		a.mainPages.RemovePage("submenu2")
		a.showInfo(fmt.Sprintf("前文条数已设置为 %d", n))
	})
	formView.AddButton("取消", func() { a.mainPages.RemovePage("submenu2") })
	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

func (a *App) settingHookAfterCount() {
	formView := form.NewForm("设置触发后文条数")
	temp := fmt.Sprintf("%d", a.ctx.HookAfterCount)
	formView.AddInputField("后文条数", temp, 0, nil, func(text string) { temp = text })
	formView.AddButton("保存", func() {
		n := 0
		if v, err := strconv.Atoi(strings.TrimSpace(temp)); err == nil && v >= 0 {
			n = v
		}
		a.ctx.SetHookAfterCount(n)
		a.mainPages.RemovePage("submenu2")
		a.showInfo(fmt.Sprintf("后文条数已设置为 %d", n))
	})
	formView.AddButton("取消", func() { a.mainPages.RemovePage("submenu2") })
	a.mainPages.AddPage("submenu2", formView, true, true)
	a.SetFocus(formView)
}

// selectAccountSelected 处理切换账号菜单项的选择事件
func (a *App) selectAccountSelected(i *menu.Item) {
	// 创建子菜单
	subMenu := menu.NewSubMenu("切换账号")

	// 添加微信进程
	instances := a.m.wechat.GetWeChatInstances()
	if len(instances) > 0 {
		// 添加实例标题
		subMenu.AddItem(&menu.Item{
			Index:       0,
			Name:        "--- 微信进程 ---",
			Description: "",
			Hidden:      false,
			Selected:    nil,
		})

		// 添加实例列表
		for idx, instance := range instances {
			// 创建一个实例描述
			description := fmt.Sprintf("版本: %s 目录: %s", instance.FullVersion, instance.DataDir)

			// 标记当前选中的实例
			name := fmt.Sprintf("%s [%d]", instance.Name, instance.PID)
			if a.ctx.Current != nil && a.ctx.Current.PID == instance.PID {
				name = name + " [当前]"
			}

			// 创建菜单项
			instanceItem := &menu.Item{
				Index:       idx + 1,
				Name:        name,
				Description: description,
				Hidden:      false,
				Selected: func(instance *wechat.Account) func(*menu.Item) {
					return func(*menu.Item) {
						// 如果是当前账号，则无需切换
						if a.ctx.Current != nil && a.ctx.Current.PID == instance.PID {
							a.mainPages.RemovePage("submenu")
							a.showInfo("已经是当前账号")
							return
						}

						// 显示切换中的模态框
						modal := tview.NewModal().SetText("正在切换账号...")
						a.mainPages.AddPage("modal", modal, true, true)
						a.SetFocus(modal)

						// 在后台执行切换操作
						go func() {
							err := a.m.Switch(instance, "")

							// 在主线程中更新UI
							a.QueueUpdateDraw(func() {
								a.mainPages.RemovePage("modal")
								a.mainPages.RemovePage("submenu")

								if err != nil {
									// 切换失败
									a.showError(fmt.Errorf("切换账号失败: %v", err))
								} else {
									// 切换成功
									a.showInfo("切换账号成功")
									// 更新菜单状态
									a.updateMenuItemsState()
								}
							})
						}()
					}
				}(instance),
			}
			subMenu.AddItem(instanceItem)
		}
	}

	// 添加历史账号
	if len(a.ctx.History) > 0 {
		// 添加历史账号标题
		subMenu.AddItem(&menu.Item{
			Index:       100,
			Name:        "--- 历史账号 ---",
			Description: "",
			Hidden:      false,
			Selected:    nil,
		})

		// 添加历史账号列表
		idx := 101
		for account, hist := range a.ctx.History {
			// 创建一个账号描述
			description := fmt.Sprintf("版本: %s 目录: %s", hist.FullVersion, hist.DataDir)

			// 标记当前选中的账号
			name := account
			if name == "" {
				name = filepath.Base(hist.DataDir)
			}
			if a.ctx.DataDir == hist.DataDir {
				name = name + " [当前]"
			}

			// 创建菜单项
			histItem := &menu.Item{
				Index:       idx,
				Name:        name,
				Description: description,
				Hidden:      false,
				Selected: func(account string) func(*menu.Item) {
					return func(*menu.Item) {
						// 如果是当前账号，则无需切换
						if a.ctx.Current != nil && a.ctx.DataDir == a.ctx.History[account].DataDir {
							a.mainPages.RemovePage("submenu")
							a.showInfo("已经是当前账号")
							return
						}

						// 显示切换中的模态框
						modal := tview.NewModal().SetText("正在切换账号...")
						a.mainPages.AddPage("modal", modal, true, true)
						a.SetFocus(modal)

						// 在后台执行切换操作
						go func() {
							err := a.m.Switch(nil, account)

							// 在主线程中更新UI
							a.QueueUpdateDraw(func() {
								a.mainPages.RemovePage("modal")
								a.mainPages.RemovePage("submenu")

								if err != nil {
									// 切换失败
									a.showError(fmt.Errorf("切换账号失败: %v", err))
								} else {
									// 切换成功
									a.showInfo("切换账号成功")
									// 更新菜单状态
									a.updateMenuItemsState()
								}
							})
						}()
					}
				}(account),
			}
			idx++
			subMenu.AddItem(histItem)
		}
	}

	// 如果没有账号可选择
	if len(a.ctx.History) == 0 && len(instances) == 0 {
		subMenu.AddItem(&menu.Item{
			Index:       1,
			Name:        "无可用账号",
			Description: "未检测到微信进程或历史账号",
			Hidden:      false,
			Selected:    nil,
		})
	}

	// 显示子菜单
	a.mainPages.AddPage("submenu", subMenu, true, true)
	a.SetFocus(subMenu)
}

// showModal 显示一个模态对话框
func (a *App) showModal(text string, buttons []string, doneFunc func(buttonIndex int, buttonLabel string)) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons(buttons).
		SetDoneFunc(doneFunc)

	a.mainPages.AddPage("modal", modal, true, true)
	a.SetFocus(modal)
}

// showError 显示错误对话框
func (a *App) showError(err error) {
	a.showModal(err.Error(), []string{"OK"}, func(buttonIndex int, buttonLabel string) {
		a.mainPages.RemovePage("modal")
	})
}

// showInfo 显示信息对话框
func (a *App) showInfo(text string) {
	a.showModal(text, []string{"OK"}, func(buttonIndex int, buttonLabel string) {
		a.mainPages.RemovePage("modal")
	})
}
