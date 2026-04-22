package main
import (
  "fmt"
  hp "github.com/sjzar/chatlog/internal/chatlog/hermespush"
)
func main() {
  cfg, err := hp.DiscoverWeixinConfigAt("/Users/lee/.hermes")
  if err != nil { panic(err) }
  fmt.Println("home_channel=", cfg.HomeChannel)
  fmt.Println("home_channel_name=", cfg.HomeChannelName)
  fmt.Println("home_channel_from=", cfg.HomeChannelFrom)
  fmt.Println("channel_file=", cfg.ChannelFile)
  fmt.Println("account_file=", cfg.AccountFile)
}
