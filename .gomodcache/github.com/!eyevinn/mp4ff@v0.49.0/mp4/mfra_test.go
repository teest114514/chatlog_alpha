package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestMfra(t *testing.T) {
	mfra := &mp4.MfraBox{}
	tfra := &mp4.TfraBox{
		TrackID:               1,
		LengthSizeOfTrafNum:   0,
		LengthSizeOfTrunNum:   1,
		LengthSizeOfSampleNum: 2,
	}
	te := mp4.TfraEntry{
		Time:         3145,
		MoofOffset:   1892,
		TrafNumber:   1,
		TrunNumber:   2,
		SampleNumber: 1,
	}
	tfra.Entries = append(tfra.Entries, te)
	err := mfra.AddChild(tfra)
	if err != nil {
		t.Error(err)
	}
	mfro := &mp4.MfroBox{
		ParentSize: 12345,
	}
	err = mfra.AddChild(mfro)
	if err != nil {
		t.Error(err)
	}
	boxDiffAfterEncodeAndDecode(t, mfra)
}
