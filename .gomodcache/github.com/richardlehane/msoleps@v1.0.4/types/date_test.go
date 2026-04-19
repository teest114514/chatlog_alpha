package types

import (
	"testing"
	"time"
)

// example from http://msdn.microsoft.com/en-us/library/cc237601.aspx
func TestDate(t *testing.T) {
	var d Date = 5.25
	expect := time.Date(1900, 1, 4, 6, 0, 0, 0, time.UTC)
	if !d.Time().Equal(expect) {
		t.Errorf("Date type: expect %v to equal %v", d, expect)
	}
}
