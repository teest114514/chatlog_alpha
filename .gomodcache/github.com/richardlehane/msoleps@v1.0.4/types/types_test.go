package types

import "testing"

func TestTypes(t *testing.T) {
	if VT_UINT != 0x0017 {
		t.Errorf("Expecting VT_UINT to equal 0x0017, equals %v", VT_UINT)
	}
	if VT_LPSTR != 0x001E {
		t.Errorf("Expecting VT_LPSTR to equal 0x001E, equals %v", VT_LPSTR)
	}
	if VT_FILETIME != 0x0040 {
		t.Errorf("Expecting VT_FILETIME to equal 0x0040, equals %v", VT_FILETIME)
	}
	if VT_VERSIONED_STREAM != 0x0049 {
		t.Errorf("Expecting VT_VERSIONED_STRING to equal 0x0049, equals %v", VT_VERSIONED_STREAM)
	}
}
