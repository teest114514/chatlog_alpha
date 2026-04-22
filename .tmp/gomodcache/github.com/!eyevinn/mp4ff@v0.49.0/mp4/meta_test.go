package mp4_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

func TestMeta(t *testing.T) {
	hdlr, err := mp4.CreateHdlr("zzzz")
	if err != nil {
		t.Error(err)
	}
	meta := mp4.CreateMetaBox(0, hdlr)
	boxDiffAfterEncodeAndDecode(t, meta)
}

func TestQuickTimeMeta(t *testing.T) {
	quickTimeMetaAtom := (`000000416d6574610000002168646c7200000000000000006d64746100000000` +
		`000000000000000000000000106b657973000000000000000000000008696c7374`)
	data, err := hex.DecodeString(quickTimeMetaAtom)
	if err != nil {
		t.Error(err)
	}
	sr := bits.NewFixedSliceReader(data)
	box, err := mp4.DecodeBoxSR(0, sr)
	if err != nil {
		t.Error(err)
	}
	meta, ok := box.(*mp4.MetaBox)
	if !ok {
		t.Error("box is not meta")
	}
	if !meta.IsQuickTime() {
		t.Errorf("meta box not detected as QuickTime")
	}
	info := bytes.Buffer{}
	err = meta.Info(&info, "", "", "")
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(info.String(), "is QuickTime meta atom") {
		t.Error("lacks QuickTime in info string")
	}
	outBuf := bytes.Buffer{}
	err = meta.Encode(&outBuf)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(data, outBuf.Bytes()) {
		t.Errorf("output meta for QuickTime differs from input")
	}
}
