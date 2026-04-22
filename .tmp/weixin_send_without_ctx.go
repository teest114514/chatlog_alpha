package main
import (
  "fmt"
  "os"
  "time"
  hp "github.com/sjzar/chatlog/internal/chatlog/hermespush"
)
func main(){
  cfg, _ := hp.DiscoverWeixinConfigAt(os.ExpandEnv("$HOME/.hermes"))
  cfg.HomeChannel = "o9cq806sjchnuvMWiLf4-aWVTE6w@im.wechat"
  cfg.AccountID = ""
  err := hp.SendWeixinText(hp.NewHTTPClient(), cfg, "[chatlog test/noctx] "+time.Now().Format(time.RFC3339))
  fmt.Println(err)
}
