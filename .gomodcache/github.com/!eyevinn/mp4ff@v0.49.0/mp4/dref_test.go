package mp4_test

import (
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

const data = `000000326472656600000000000000010000002275726c200000000168747470733a2f2f666c7573736f6e69632e636f6d2f`

func TestDref(t *testing.T) {
	dref := mp4.CreateDref()
	boxDiffAfterEncodeAndDecode(t, dref)
}

func TestDrefDecode(t *testing.T) {
	d, err := hex.DecodeString(data)
	if err != nil {
		t.Error(err)
	}
	sr := bits.NewFixedSliceReader(d)
	box, err := mp4.DecodeBoxSR(0, sr)
	if err != nil {
		t.Error(err)
	}
	if box.Type() != "dref" {
		t.Errorf("Expected 'dref', got %s", box.Type())
	}
}
