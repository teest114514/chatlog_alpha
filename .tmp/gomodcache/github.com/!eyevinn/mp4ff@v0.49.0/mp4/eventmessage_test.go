package mp4_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

func TestEvteDecode(t *testing.T) {
	hexEvte := "0000002465767465000000000000000100000014627472740000000000001f4000001f40"
	data, err := hex.DecodeString(hexEvte)
	if err != nil {
		t.Error(err)
	}
	sr := bits.NewFixedSliceReader(data)
	box, err := mp4.DecodeBoxSR(0, sr)
	if err != nil {
		t.Error(err)
	}
	evte := box.(*mp4.EvteBox)
	if evte.DataReferenceIndex != 1 {
		t.Errorf("Wrong DataReferenceIndex %d", evte.DataReferenceIndex)
	}

	if evte.Btrt == nil {
		t.Error("btrt is nil")
	}
}

func TestEvteInclSilb(t *testing.T) {
	silb := mp4.SilbBox{
		Version: 0,
		Flags:   0,
		Schemes: []mp4.SilbEntry{
			{
				SchemeIdURI:    "urn:mpeg:dash:event:2012",
				Value:          "event1",
				AtLeastOneFlag: false,
			},
		},
	}
	boxDiffAfterEncodeAndDecode(t, &silb)
	evte := mp4.EvteBox{
		DataReferenceIndex: 1,
	}
	evte.AddChild(&silb)
	boxDiffAfterEncodeAndDecode(t, &evte)
}

func TestEmib(t *testing.T) {
	scteSchemeIdURI := "urn:scte:scte35:2013:bin"
	t.Run("DecodeEmib", func(t *testing.T) {
		data, err := os.ReadFile("testdata/emib.dat")
		if err != nil {
			t.Error(err)
		}
		buf := bytes.NewBuffer(data)
		box, err := mp4.DecodeBox(0, buf)
		if err != nil {
			t.Error(err)
		}
		emib := box.(*mp4.EmibBox)
		if emib.SchemeIdURI != scteSchemeIdURI {
			t.Errorf("Wrong SchemeIdURI %s", emib.SchemeIdURI)
		}
		out := bytes.Buffer{}
		err = emib.Encode(&out)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(data, out.Bytes()) {
			t.Error("Encode/Decode mismatch")
		}
	})
	t.Run("EncodeDecodeEmib", func(t *testing.T) {
		emib := mp4.EmibBox{
			Version:               0,
			Flags:                 0,
			PresentationTimeDelta: -1000,
			EventDuration:         2000,
			Id:                    1234,
			SchemeIdURI:           scteSchemeIdURI,
			Value:                 "2",
			MessageData:           []byte{0x01, 0x02, 0x03},
		}
		boxDiffAfterEncodeAndDecode(t, &emib)
	})
}

func TestEmeb(t *testing.T) {
	emeb := mp4.EmebBox{}
	boxDiffAfterEncodeAndDecode(t, &emeb)
}
