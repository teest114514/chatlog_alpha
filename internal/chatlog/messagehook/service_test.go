package messagehook

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/model"
)

type eventTestConfig struct{ account string }

func (c eventTestConfig) GetMessageHook() *conf.MessageHook       { return nil }
func (c eventTestConfig) GetDataDir() string                      { return "" }
func (c eventTestConfig) GetHTTPAddr() string                     { return "" }
func (c eventTestConfig) GetSemanticConfig() *conf.SemanticConfig { return nil }
func (c eventTestConfig) GetAccount() string                      { return c.account }

func TestSessionInForwardWhitelistMatchesIDOrDisplayName(t *testing.T) {
	contacts := map[string]struct{}{"wxid_friend": {}}
	chatrooms := map[string]struct{}{"项目群": {}}

	if !sessionInForwardWhitelist("wxid_friend", "好友", contacts, chatrooms) {
		t.Fatal("contact ID should match")
	}
	if !sessionInForwardWhitelist("123@chatroom", "项目群", contacts, chatrooms) {
		t.Fatal("chatroom display name should match")
	}
	if sessionInForwardWhitelist("other@chatroom", "其他群", contacts, chatrooms) {
		t.Fatal("unlisted session should be skipped")
	}
}

func TestFailedPostDeliveryIsRetried(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	service := &Service{
		httpClient:  server.Client(),
		pendingPost: make(map[string]pendingPostDelivery),
	}
	evt := Event{Talker: "room", TriggerSeq: 7, RuleType: "keyword", RuleLabel: "build"}
	result := service.deliverPost(server.URL, evt)
	if result.Success {
		t.Fatal("first delivery should fail")
	}
	evt.Deliveries = append(evt.Deliveries, result)
	service.queuePostRetry(server.URL, evt)
	service.retryPendingPosts(time.Now().Add(maxPostRetryDelay))
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(service.pendingPost) != 0 {
		t.Fatalf("successful retry was retained: %#v", service.pendingPost)
	}
}

func TestBuildEventIncludesOwnerAndAtUserList(t *testing.T) {
	service := &Service{conf: eventTestConfig{account: "wxid_owner_abcd"}}
	trigger := &model.Message{
		Seq:        42,
		Time:       time.Unix(123, 0),
		Talker:     "room@chatroom",
		Sender:     "sender",
		Type:       1,
		AtUserList: []string{"wxid_a", "wxid_b"},
	}
	cfg := &conf.MessageHook{BeforeCount: 0, AfterCount: 0}
	event := service.buildEvent(trigger, "keyword", "rule", "hello", "hello", cfg)
	if event.OwnerWxid != "wxid_owner" {
		t.Fatalf("OwnerWxid = %q, want wxid_owner", event.OwnerWxid)
	}
	if !reflect.DeepEqual(event.AtUserList, trigger.AtUserList) {
		t.Fatalf("AtUserList = %#v, want %#v", event.AtUserList, trigger.AtUserList)
	}
}
