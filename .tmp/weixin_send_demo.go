package main

import (
  "fmt"
  "os"
  "time"
  hp "github.com/sjzar/chatlog/internal/chatlog/hermespush"
)

func main() {
  cfg, err := hp.DiscoverWeixinConfigAt(os.ExpandEnv("$HOME/.hermes"))
  if err != nil {
    fmt.Println("DISCOVER_ERR:", err)
    os.Exit(1)
  }
  cfg.HomeChannel = "o9cq806sjchnuvMWiLf4-aWVTE6w@im.wechat"
  err = hp.SendWeixinText(hp.NewHTTPClient(), cfg, "[chatlog test] 微信推送联调测试 " + time.Now().Format(time.RFC3339))
  if err != nil {
    fmt.Println("SEND_ERR:", err)
    os.Exit(2)
  }
  fmt.Println("SEND_OK")
}
