package mp4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

func TestUrl(t *testing.T) {

	urlBox := &mp4.URLBox{
		Version:  0,
		Flags:    0,
		Location: "location",
	}

	boxDiffAfterEncodeAndDecode(t, urlBox)
}

func TestUrlDecode(t *testing.T) {
	cases := []struct {
		desc              string
		data              string
		wantedFlags       uint32
		wantedLocation    string
		NoLocation        bool
		NoZeroTermination bool
	}{
		{
			desc:              "self-contained, with location and zero termination",
			data:              `0000002375726c200000000168747470733a2f2f666c7573736f6e69632e636f6d2f00`,
			wantedFlags:       0x00001,
			wantedLocation:    "",
			NoLocation:        false,
			NoZeroTermination: false,
		},
		{
			desc:              "self-contained,  with location but no zero termination",
			data:              `0000002275726c200000000168747470733a2f2f666c7573736f6e69632e636f6d2f`,
			wantedFlags:       0x00001,
			wantedLocation:    "",
			NoLocation:        false,
			NoZeroTermination: true,
		},
		{
			desc:              "self-contained,  without location",
			data:              `0000000c75726c2000000001`,
			wantedFlags:       0x00001,
			wantedLocation:    "",
			NoLocation:        false,
			NoZeroTermination: true,
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			d, err := hex.DecodeString(c.data)
			if err != nil {
				t.Error(err)
			}
			sr := bits.NewFixedSliceReader(d)
			box, err := mp4.DecodeBoxSR(0, sr)
			if err != nil {
				t.Error(err)
			}
			if box.Type() != "url " {
				t.Errorf("Expected 'url ', got %s", box.Type())
			}
			urlBox := box.(*mp4.URLBox)
			o := bytes.Buffer{}
			err = urlBox.Encode(&o)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(d, o.Bytes()) {
				t.Errorf("Encode mismatch: got %s, wanted %s", hex.EncodeToString(o.Bytes()), c.data)
			}
		})
	}
}
