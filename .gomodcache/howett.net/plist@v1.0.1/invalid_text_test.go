package plist

import (
	"strings"
	"testing"
)

var InvalidTextPlists = []struct {
	Name string
	Data string
}{
	{"Truncated array", "("},
	{"Truncated dictionary", "{a=b;"},
	{"Truncated dictionary 2", "{"},
	{"Unclosed nested array", "{0=(/"},
	{"Unclosed dictionary", "{0=/"},
	{"Broken GNUStep data", "(<*I5>,<*I5>,<*I5>,<*I5>,*I16777215>,<*I268435455>,<*I4294967295>,<*I18446744073709551615>,)"},
	{"Truncated nested array", "{0=(((/"},
	{"Truncated dictionary with comment-like", "{/"},
	{"Truncated array with comment-like", "(/"},
	{"Truncated array with empty data", "(<>"},
	{"Bad Extended Character", "{¬=A;}"},
	{"Missing Equals in Dictionary", `{"A"A;}`},
	{"Missing Semicolon in Dictionary", `{"A"=A}`},
	{"Invalid GNUStep type", "<*F33>"},
	{"Invalid GNUStep int", "(<*I>"},
	{"Invalid GNUStep date", "<*D5>"},
	{"Truncated GNUStep value", "<*I3"},
	{"Invalid data", "<EQ>"},
	{"Truncated unicode escape", `"\u231`},
	{"Truncated hex escape", `"\x2`},
	{"Truncated octal escape", `"\02`},
	{"Truncated data", `<33`},
	{"Uneven data", `<3>`},
	{"Truncated block comment", `/* hello`},
	{"Truncated quoted string", `"hi`},
	{"Garbage after end of non-string", "<ab> cde"},
	{"Broken UTF-16", "\xFE\xFF\x01"},
	{"Truncated GNUStep data", "<"},
	{"Truncated GNUStep base64 data (missing ])", `<[33==`},
	{"Truncated GNUStep base64 data (missing >)", `<[33==]`},
	{"Invalid GNUStep base64 data", `<[3]>`}, // TODO: this is actually valid
	{"GNUStep extended value with EOF before type", "<*"},
	{"GNUStep extended value terminated before type", "<*>"},
	{"Empty GNUStep extended value", "<*I>"},
	{"Unterminated GNUStep quoted value", "<*D\"5>"},
	{"Unterminated GNUStep quoted value (EOF)", "<*D\""},
	{"Poorly-terminated GNUStep quoted value", "<*D\">"},
	{"Empty GNUStep quoted extended value", "<*D\"\">"},
}

func TestInvalidTextPlists(t *testing.T) {
	for _, test := range InvalidTextPlists {
		subtest(t, test.Name, func(t *testing.T) {
			var obj interface{}
			buf := strings.NewReader(test.Data)
			err := NewDecoder(buf).Decode(&obj)
			if err == nil {
				t.Fatal("invalid plist failed to throw error")
			} else {
				t.Log(err)
			}
		})
	}
}
