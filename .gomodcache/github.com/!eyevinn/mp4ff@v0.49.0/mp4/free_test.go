package mp4_test

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestFree(t *testing.T) {
	freeEmpty := mp4.NewFreeBox([]byte{})
	boxDiffAfterEncodeAndDecode(t, freeEmpty)

	emptySmall := mp4.NewFreeBox([]byte{0x01, 0x02})
	boxDiffAfterEncodeAndDecode(t, emptySmall)
	if !bytes.Equal(emptySmall.Payload(), []byte{0x01, 0x02}) {
		t.Error("Payload not equal")
	}
	skip := mp4.NewSkipBox([]byte{0x02, 0x03})
	boxDiffAfterEncodeAndDecode(t, skip)
}
