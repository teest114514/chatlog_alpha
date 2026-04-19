package mp4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
)

const (
	esdsProgIn   = `00000036657364730000000003808080250002000480808017401500000000010d88000003f80580808005128856e500068080800102`
	esdsMp4Box   = `0000002a6573647300000000031c0000000414401500000000010d88000003f80505128856e500060102`
	esdsEncAudio = `0000003365736473000000000380808022000000048080801440150018000003eb100002710005808080021190068080800102`
	esdsLongEnd  = `0000002f65736473000000000321000000041140150002440001ea940001ea94050212100680808080808080800102`
	esdsShort    = `0000002365736473000000000315000000040d6b150001e00002850000027100060102`
)

func TestEsdsEncodeAndDecode(t *testing.T) {
	decCfg := []byte{0x11, 0x90}

	esdsIn := mp4.CreateEsdsBox(decCfg)

	// Write to a buffer so that we can read and check
	var buf bytes.Buffer
	err := esdsIn.Encode(&buf)
	if err != nil {
		t.Fatal(err)
	}

	// Read back from buffer
	decodedBox, err := mp4.DecodeBox(0, &buf)
	if err != nil {
		t.Error("Did not get a box back")
	}
	esdsOut := decodedBox.(*mp4.EsdsBox)
	decCfgOut := esdsOut.DecConfigDescriptor.DecSpecificInfo.DecConfig
	if !bytes.Equal(decCfgOut, decCfg) {
		t.Errorf("Decode cfg out %s differs from decode cfg in %s",
			hex.EncodeToString(decCfgOut), hex.EncodeToString(decCfg))
	}

	boxDiffAfterEncodeAndDecode(t, esdsIn)
}
func TestDecodeEncodeEsds(t *testing.T) {
	inputs := []string{esdsShort, esdsProgIn, esdsMp4Box, esdsEncAudio, esdsLongEnd}
	for i, inp := range inputs {
		data, err := hex.DecodeString(inp)
		if err != nil {
			t.Error(err)
		}
		sr := bits.NewFixedSliceReader(data)
		esds, err := mp4.DecodeBoxSR(0, sr)
		if err != nil {
			t.Error(err)
		}
		out := make([]byte, len(data))
		sw := bits.NewFixedSliceWriterFromSlice(out)
		err = esds.EncodeSW(sw)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(sw.Bytes(), data) {
			t.Errorf("case %d does not reproduce esds", i)
		}

	}
}
