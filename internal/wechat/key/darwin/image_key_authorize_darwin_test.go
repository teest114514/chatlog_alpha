//go:build darwin

package darwin

import (
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	got := shellQuote("/tmp/a'b")
	want := `'/tmp/a'"'"'b'`
	if got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

func TestBuildPrivilegedImageKeyAppleScript(t *testing.T) {
	script := buildPrivilegedImageKeyAppleScript("/tmp/Chat Log/chatlog", 1234, "/tmp/account data")
	for _, want := range []string{
		"do shell script",
		"with administrator privileges",
		PrivilegedImageKeyHelperCommand,
		"--pid 1234",
		"--data-dir",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("AppleScript missing %q: %s", want, script)
		}
	}
}

func TestParsePrivilegedImageKeyResult(t *testing.T) {
	result, err := parsePrivilegedImageKeyResult([]byte("unrelated log\n{\"key\":\"0123456789abcdef\"}\n"))
	if err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result.Key != "0123456789abcdef" {
		t.Fatalf("key = %q", result.Key)
	}
}

func TestAuthorizationCanceled(t *testing.T) {
	for _, message := range []string{
		"execution error: User canceled. (-128)",
		"执行错误：用户已取消。(-128)",
	} {
		if !isAuthorizationCanceled(message) {
			t.Fatalf("did not recognize cancellation: %q", message)
		}
	}
}
