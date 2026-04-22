package mp4_test

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

// TestUnknown including non-ascii character in name (box typs is uint32 according to spec)
func TestUnknown(t *testing.T) {

	payload := []byte{0, 0, 0, 0}

	unknownBox := mp4.CreateUnknownBox("\xa9enc", 12, payload)

	boxDiffAfterEncodeAndDecode(t, unknownBox)

	if !bytes.Equal(unknownBox.Payload(), payload) {
		t.Errorf("Payload not decoded correctly")
	}
}
