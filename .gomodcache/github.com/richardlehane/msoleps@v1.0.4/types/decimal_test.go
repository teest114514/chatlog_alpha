package types

import "testing"

func TestDec(t *testing.T) {
	dec := Decimal{
		[2]byte{0, 0},
		0x15,
		0x80,
		0x15,
		0x20,
	}
	str := dec.String()
	if str != "-0.38738162554790058397" {
		t.Errorf("Bad decimal: expecting -0.38738162554790058397 got %v", str)
	}
}
