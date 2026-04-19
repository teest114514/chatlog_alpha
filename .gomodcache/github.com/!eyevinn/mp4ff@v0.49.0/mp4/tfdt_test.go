package mp4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestTfdtReadingV0(t *testing.T) {
	byteData, _ := hex.DecodeString("00000010746664740000000000ffffff")

	r := bytes.NewReader(byteData[8:]) // Don't include header
	bHdr := mp4.BoxHeader{
		Name:   "tfdt",
		Size:   uint64(len(byteData)),
		Hdrlen: 8,
	}
	box, _ := mp4.DecodeTfdt(bHdr, 0, r)
	tfdt := box.(*mp4.TfdtBox)

	if tfdt.Version != 0 {
		t.Errorf("Tfdt version is not 0")
	}
	if tfdt.BaseMediaDecodeTime() != 0x00ffffff {
		t.Errorf("Tfdt basemediaDecodeTime is %x not %x", tfdt.BaseMediaDecodeTime(), 0x00ffffff)
	}
}

func TestTfdtReadingV1(t *testing.T) {
	byteData, _ := hex.DecodeString("0000001474666474010000000000000000ffffff")

	r := bytes.NewReader(byteData[8:]) // Don't include header
	bHdr := mp4.BoxHeader{
		Name:   "tfdt",
		Size:   uint64(len(byteData)),
		Hdrlen: 8,
	}
	box, _ := mp4.DecodeTfdt(bHdr, 0, r)
	tfdt := box.(*mp4.TfdtBox)

	if tfdt.Version != 1 {
		t.Errorf("Tfdt version is not 1")
	}
	if tfdt.BaseMediaDecodeTime() != 0x00ffffff {
		t.Errorf("Tfdt basemediaDecodeTime is %x not %x", tfdt.BaseMediaDecodeTime(), 0x00ffffff)
	}
}

func TestTfdtWriteV1(t *testing.T) {
	byteData, _ := hex.DecodeString("0000001474666474010000000000000000ffffff")

	r := bytes.NewReader(byteData[8:]) // Don't include header
	bHdr := mp4.BoxHeader{
		Name:   "tfdt",
		Size:   uint64(len(byteData)),
		Hdrlen: 8,
	}
	box, err := mp4.DecodeTfdt(bHdr, 0, r)
	if err != nil {
		t.Error(err)
	}
	tfdt := box.(*mp4.TfdtBox)

	outBuf := make([]byte, 0, tfdt.Size())

	w := bytes.NewBuffer(outBuf)
	err = tfdt.Encode(w)
	if err != nil {
		t.Error(err)
	}

	writtenBytes := w.Bytes()

	if !bytes.Equal(byteData, writtenBytes) {
		t.Errorf("Encoded tfdt body not same as decoded")
	}
}
