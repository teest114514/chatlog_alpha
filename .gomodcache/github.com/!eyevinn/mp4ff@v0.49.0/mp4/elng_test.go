package mp4_test

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestDecodeElng(t *testing.T) {

	elng := &mp4.ElngBox{Language: "en-US"}
	boxDiffAfterEncodeAndDecode(t, elng)
}

// TestElngWithoutFullBox tests erronous case where full box headers are not present.
func TestElngWithoutFullBox(t *testing.T) {
	data := []byte("\x00\x00\x00\x0belngdk\x00")
	bufIn := bytes.NewBuffer(data)
	box, err := mp4.DecodeBox(0, bufIn)
	if err != nil {
		t.Errorf("could not decode elng")
	}
	elng := box.(*mp4.ElngBox)
	if !elng.MissingFullBoxBytes() {
		t.Errorf("missing full box not set")
	}
	bufOut := bytes.Buffer{}
	err = elng.Encode(&bufOut)
	if err != nil {
		t.Errorf("error encoding elng")
	}
	if !bytes.Equal(bufOut.Bytes(), data) {
		t.Errorf("encoded elng differs from input")
	}
}

func TestFixElngMissingFullBoxBytes(t *testing.T) {
	dataIn := []byte("\x00\x00\x00\x0belngdk\x00")
	dataOut := []byte("\x00\x00\x00\x0felng\x00\x00\x00\x00dk\x00")
	bufIn := bytes.NewBuffer(dataIn)
	box, err := mp4.DecodeBox(0, bufIn)
	if err != nil {
		t.Errorf("could not decode elng")
	}
	elng := box.(*mp4.ElngBox)
	if !elng.MissingFullBoxBytes() {
		t.Errorf("missing full box not set")
	}
	outBuf := bytes.Buffer{}
	elng.FixMissingFullBoxBytes()
	err = elng.Encode(&outBuf)
	if err != nil {
		t.Errorf("error encoding elng")
	}
	if !bytes.Equal(outBuf.Bytes(), dataOut) {
		t.Errorf("encoded elng differs from input")
	}
}
