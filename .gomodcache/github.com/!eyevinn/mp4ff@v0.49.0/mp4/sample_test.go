package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSample(t *testing.T) {
	s := mp4.NewSample(mp4.SyncSampleFlags, 1000, 100, -1001)
	fs := mp4.FullSample{
		Sample:     s,
		DecodeTime: 1000,
		Data:       []byte{0x01, 0x02, 0x03, 0x04},
	}
	if !s.IsSync() {
		t.Error("Expected sync sample")
	}
	if fs.PresentationTime() != 0 {
		t.Error("Expected presentation time 0")
	}
}
