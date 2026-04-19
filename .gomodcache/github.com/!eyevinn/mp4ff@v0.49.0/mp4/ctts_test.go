package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestCtts(t *testing.T) {
	ctts := &mp4.CttsBox{
		Version: 0,
		Flags:   0,
	}
	err := ctts.AddSampleCountsAndOffset([]uint32{12, 35}, []int32{-2000, 2000})
	if err != nil {
		t.Error(err)
	}

	boxDiffAfterEncodeAndDecode(t, ctts)
}

func TestGetCompositionTimeOffset(t *testing.T) {
	ctts := &mp4.CttsBox{
		Version: 0,
		Flags:   0,
	}
	err := ctts.AddSampleCountsAndOffset([]uint32{2, 1, 3, 1}, []int32{0, -1000, 1000, 0})
	if err != nil {
		t.Error(err)
	}

	testCases := []struct {
		sampleNr    uint32
		expectedCTO int32
	}{
		{1, 0},
		{2, 0},
		{3, -1000},
		{4, 1000},
		{5, 1000},
		{6, 1000},
		{7, 0},
	}
	for idx, tc := range testCases {
		gotCTO := ctts.GetCompositionTimeOffset(tc.sampleNr)
		if gotCTO != tc.expectedCTO {
			t.Errorf("test case %d: got cto %d instead of %d for sampleNr %d", idx, gotCTO, tc.expectedCTO, tc.sampleNr)
		}
	}
}
