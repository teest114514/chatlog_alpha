package model

import (
	"reflect"
	"testing"

	kzstd "github.com/klauspost/compress/zstd"
)

func TestMessageV4AtUserListPrefersSource(t *testing.T) {
	msg := (&MessageV4{
		LocalType:      1,
		UserName:       "sender",
		MessageContent: []byte("sender:\nhello"),
		Source: []byte(
			`<msgsource><atuserlist>source-a, source-b</atuserlist></msgsource>`,
		),
		CompressContent: []byte(
			`<msg><atuserlist><item>legacy-a</item></atuserlist></msg>`,
		),
	}).Wrap("room@chatroom")

	want := []string{"source-a", "source-b"}
	if !reflect.DeepEqual(msg.AtUserList, want) {
		t.Fatalf("AtUserList = %#v, want %#v", msg.AtUserList, want)
	}
}

func TestParseAtUserListFromZstdSource(t *testing.T) {
	encoder, err := kzstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	raw := []byte(`<msgsource><atuserlist>wxid_a,wxid_b</atuserlist></msgsource>`)
	compressed := encoder.EncodeAll(raw, nil)

	want := []string{"wxid_a", "wxid_b"}
	if got := parseAtUserListFromSource(compressed); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseAtUserListFromSource(zstd) = %#v, want %#v", got, want)
	}
}

func TestMessageV4AtUserListFallsBackToCompressContent(t *testing.T) {
	msg := (&MessageV4{
		LocalType:      1,
		UserName:       "sender",
		MessageContent: []byte("sender:\nhello"),
		Source:         []byte(`<msgsource><atuserlist>broken`),
		CompressContent: []byte(
			`<msg><atuserlist><item> legacy-a </item><item></item><item>legacy-a</item><item>legacy-b</item></atuserlist></msg>`,
		),
	}).Wrap("room@chatroom")

	want := []string{"legacy-a", "legacy-b"}
	if !reflect.DeepEqual(msg.AtUserList, want) {
		t.Fatalf("AtUserList = %#v, want %#v", msg.AtUserList, want)
	}
}

func TestParseAtUserListRejectsMalformedOrEmptyInput(t *testing.T) {
	tests := [][]byte{
		nil,
		[]byte("not xml"),
		[]byte(`<msgsource><atuserlist></atuserlist></msgsource>`),
		[]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00},
	}
	for _, input := range tests {
		if got := parseAtUserListFromSource(input); got != nil {
			t.Fatalf("parseAtUserListFromSource(%q) = %#v, want nil", input, got)
		}
	}
}

func TestMessageV4DoesNotExposeAtListForDirectMessages(t *testing.T) {
	msg := (&MessageV4{
		LocalType:      1,
		UserName:       "friend",
		MessageContent: []byte("hello"),
		Source:         []byte(`<msgsource><atuserlist>wxid_a</atuserlist></msgsource>`),
	}).Wrap("friend")
	if msg.AtUserList != nil {
		t.Fatalf("direct message AtUserList = %#v, want nil", msg.AtUserList)
	}
}
