package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sjzar/chatlog/internal/model"
)

type refreshTestDataSource struct {
	mu sync.Mutex

	contacts    []*model.Contact
	chatRooms   []*model.ChatRoom
	contactErr  error
	chatRoomErr error

	blockContacts  <-chan struct{}
	contactStarted chan struct{}
	closed         chan struct{}
	closeCount     int
}

func (ds *refreshTestDataSource) GetContacts(context.Context, string, int, int) ([]*model.Contact, error) {
	ds.mu.Lock()
	err := ds.contactErr
	block := ds.blockContacts
	started := ds.contactStarted
	items := cloneContacts(ds.contacts)
	ds.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}
	return items, err
}

func (ds *refreshTestDataSource) GetChatRooms(context.Context, string, int, int) ([]*model.ChatRoom, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return cloneChatRooms(ds.chatRooms), ds.chatRoomErr
}

func (ds *refreshTestDataSource) GetOpenimWordings(context.Context) ([]*model.OpenimWording, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetMessages(context.Context, time.Time, time.Time, string, string, string, int, int) ([]*model.Message, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetMessage(context.Context, string, int64) (*model.Message, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetSessions(context.Context, string, int, int) ([]*model.Session, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetMedia(context.Context, string, string) (*model.Media, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetMediaByName(context.Context, string, string, int64) (*model.Media, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetSNSTimeline(context.Context, string, int, int) ([]map[string]interface{}, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetSNSCount(context.Context, string) (int, error) {
	return 0, nil
}

func (ds *refreshTestDataSource) SetCallback(string, func(fsnotify.Event) error) error {
	return nil
}

func (ds *refreshTestDataSource) GetDBs() (map[string][]string, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetTables(string, string) ([]string, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) GetTableData(string, string, string, int, int, string) ([]map[string]interface{}, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) ExecuteSQL(string, string, string) ([]map[string]interface{}, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) SearchAll(string, int, bool) ([]map[string]interface{}, error) {
	return nil, nil
}

func (ds *refreshTestDataSource) Close() error {
	ds.mu.Lock()
	ds.closeCount++
	closed := ds.closed
	count := ds.closeCount
	ds.mu.Unlock()
	if closed != nil && count == 1 {
		close(closed)
	}
	return nil
}

func cloneContacts(items []*model.Contact) []*model.Contact {
	out := make([]*model.Contact, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		copyItem := *item
		out = append(out, &copyItem)
	}
	return out
}

func cloneChatRooms(items []*model.ChatRoom) []*model.ChatRoom {
	out := make([]*model.ChatRoom, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		copyItem := *item
		out = append(out, &copyItem)
	}
	return out
}

func TestFailedRefreshPreservesLastKnownGoodSnapshots(t *testing.T) {
	ds := &refreshTestDataSource{
		contacts:  []*model.Contact{{UserName: "old-contact", NickName: "Old"}},
		chatRooms: []*model.ChatRoom{{Name: "old@chatroom"}},
	}
	r, err := newRepository(ds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ds.mu.Lock()
	ds.contacts = []*model.Contact{{UserName: "new-contact", NickName: "New"}}
	ds.chatRooms = []*model.ChatRoom{{Name: "new@chatroom"}}
	ds.contactErr = errors.New("temporary contact read failure")
	ds.chatRoomErr = errors.New("temporary chatroom read failure")
	ds.mu.Unlock()

	if err := r.initContactCache(context.Background()); err == nil {
		t.Fatal("contact refresh unexpectedly succeeded")
	}
	if err := r.initChatRoomCache(context.Background()); err == nil {
		t.Fatal("chatroom refresh unexpectedly succeeded")
	}
	if got, err := r.GetContact(context.Background(), "old-contact"); err != nil || got == nil {
		t.Fatalf("last contact snapshot was lost: contact=%#v err=%v", got, err)
	}
	if got, err := r.GetChatRoom(context.Background(), "old@chatroom"); err != nil || got == nil {
		t.Fatalf("last chatroom snapshot was lost: chatroom=%#v err=%v", got, err)
	}
	if got, _ := r.GetContact(context.Background(), "new-contact"); got != nil {
		t.Fatalf("failed contact refresh leaked partial data: %#v", got)
	}
	if got, _ := r.GetChatRoom(context.Background(), "new@chatroom"); got != nil {
		t.Fatalf("failed chatroom refresh leaked partial data: %#v", got)
	}
}

func TestCloseWaitsForRefreshAndIsIdempotent(t *testing.T) {
	ds := &refreshTestDataSource{
		contacts:  []*model.Contact{{UserName: "contact"}},
		chatRooms: []*model.ChatRoom{{Name: "room@chatroom"}},
		closed:    make(chan struct{}),
	}
	r, err := newRepository(ds, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	block := make(chan struct{})
	started := make(chan struct{}, 1)
	ds.mu.Lock()
	ds.blockContacts = block
	ds.contactStarted = started
	ds.mu.Unlock()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("periodic refresh did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- r.Close() }()
	select {
	case <-ds.closed:
		t.Fatal("datasource closed before in-flight refresh exited")
	case <-time.After(30 * time.Millisecond):
	}

	close(block)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after refresh unblocked")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	ds.mu.Lock()
	closeCount := ds.closeCount
	ds.mu.Unlock()
	if closeCount != 1 {
		t.Fatalf("datasource Close called %d times, want 1", closeCount)
	}
}

func TestConcurrentCacheReadsAndRefreshes(t *testing.T) {
	ds := &refreshTestDataSource{
		contacts:  []*model.Contact{{UserName: "contact-0"}},
		chatRooms: []*model.ChatRoom{{Name: "room-0@chatroom"}},
	}
	r, err := newRepository(ds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 100; j++ {
				_, _ = r.GetContacts(context.Background(), "", 0, 0)
				_, _ = r.GetChatRooms(context.Background(), "", 0, 0)
			}
		}()
	}
	for i := 1; i <= 100; i++ {
		ds.mu.Lock()
		ds.contacts = []*model.Contact{{UserName: "contact"}}
		ds.chatRooms = []*model.ChatRoom{{Name: "room@chatroom"}}
		ds.mu.Unlock()
		if err := r.initContactCache(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := r.initChatRoomCache(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
}
