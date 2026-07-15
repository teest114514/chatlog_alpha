//go:build darwin

package darwin

import (
	"strings"
	"testing"
)

func TestSIPEnabledFromCSRUtil(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "enabled",
			output: "System Integrity Protection status: enabled.\n",
			want:   true,
		},
		{
			name:   "disabled",
			output: "System Integrity Protection status: disabled.\n",
			want:   false,
		},
		{
			name:   "custom configuration",
			output: "System Integrity Protection status: unknown (Custom Configuration).\n",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sipEnabledFromCSRUtil(tt.output); got != tt.want {
				t.Fatalf("sipEnabledFromCSRUtil(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestFridaUserFacingErrorAddsSIPHint(t *testing.T) {
	raw := "attach failed: unable to access process with pid 35618 from the current user account"
	got := fridaUserFacingError(raw)
	if got == raw {
		t.Fatal("known attach permission error was not translated")
	}
	for _, want := range []string{"SIP", "csrutil status", "csrutil disable"} {
		if !strings.Contains(got, want) {
			t.Fatalf("translated error %q does not contain %q", got, want)
		}
	}
}

func TestFridaUserFacingErrorPreservesUnrelatedError(t *testing.T) {
	raw := "timeout: no key captured"
	if got := fridaUserFacingError(raw); got != raw {
		t.Fatalf("fridaUserFacingError(%q) = %q", raw, got)
	}
}
