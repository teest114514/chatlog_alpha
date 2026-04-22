package types

import (
	"testing"
	"time"
)

// example from site: http://www.silisoftware.com/tools/date.php
func TestTime(t *testing.T) {
	ft := FileTime{0xEC2DE500, 0x01CF9BCF}
	expect := time.Unix(1404949554, 0)
	if !ft.Time().Equal(expect) {
		t.Errorf("Date type: expect %v to equal %v", ft.Time(), expect)
	}
}
