package mp4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

// TestBadBoxAndRemoveBoxDecoder checks that we can avoid decoder error by removing a BoxDecode.
//
// The box is then interpreted as an UnknownBox and its data is not further processed with decoded.
func TestBadBoxAndRemoveBoxDecoder(t *testing.T) {
	badMetaBox := (`000000416d6574610000002168646c7300000000000000006d64746100000000` +
		`000000000000000000000000106b657973000000000000000000000008696c7374`)
	data, err := hex.DecodeString(badMetaBox)
	if err != nil {
		t.Error(err)
	}
	sr := bits.NewFixedSliceReader(data)
	_, err = mp4.DecodeBoxSR(0, sr)
	if err == nil {
		t.Errorf("reading bad meta box should have failed")
	}
	sr = bits.NewFixedSliceReader(data)
	mp4.RemoveBoxDecoder("meta")
	defer mp4.SetBoxDecoder("meta", mp4.DecodeMeta, mp4.DecodeMetaSR)
	box, err := mp4.DecodeBoxSR(0, sr)
	if err != nil {
		t.Error(err)
	}
	_, ok := box.(*mp4.MetaBox)
	if ok {
		t.Errorf("box should not be MetaBox")
	}
	unknown, ok := box.(*mp4.UnknownBox)
	if !ok {
		t.Errorf("box should be unknown")
	}
	if unknown.Type() != "meta" {
		t.Errorf("unknown type %q instead of meta", unknown.Type())
	}
	b := bytes.Buffer{}
	err = unknown.Encode(&b)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(data, b.Bytes()) {
		t.Errorf("written unknown differs")
	}
}

func TestFixed16and32(t *testing.T) {
	f16 := mp4.Fixed16(256)
	if f16.String() != "1.0" {
		t.Errorf("Fixed16(256) should be 1.0, not %s", f16.String())
	}
	f32 := mp4.Fixed32(65536)
	if f16.String() != "1.0" {
		t.Errorf("Fixed32(65536) should be 1.0, not %s", f32.String())
	}
}
