package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestWriteReadOfAudioSampleEntry(t *testing.T) {
	ascBytes := []byte{0x11, 0x90}
	esds := mp4.CreateEsdsBox(ascBytes)
	ase := mp4.CreateAudioSampleEntryBox("mp4a", 2, 16, 48000, esds)
	boxDiffAfterEncodeAndDecode(t, ase)
	_, err := ase.RemoveEncryption()
	expectedErrMsg := "is not encrypted: mp4a"
	if err == nil || err.Error() != expectedErrMsg {
		t.Errorf("expected error with message: %q", err.Error())
	}
}
