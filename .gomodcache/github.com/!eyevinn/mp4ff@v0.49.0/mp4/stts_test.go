package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSttsEncDec(t *testing.T) {
	stts := mp4.SttsBox{
		SampleCount:     []uint32{3, 2},
		SampleTimeDelta: []uint32{10, 14},
	}
	boxDiffAfterEncodeAndDecode(t, &stts)
}

func TestGetSampleNrAtTime(t *testing.T) {

	stts := mp4.SttsBox{
		SampleCount:     []uint32{3, 2},
		SampleTimeDelta: []uint32{10, 14},
	}

	sttsZero := mp4.SttsBox{
		SampleCount:     []uint32{2, 1},
		SampleTimeDelta: []uint32{10, 0}, // Single zero duration at end
	}

	testCases := []struct {
		stts        mp4.SttsBox
		startTime   uint64
		sampleNr    uint32
		expectError bool
	}{
		{stts, 0, 1, false},
		{stts, 1, 2, false},
		{stts, 10, 2, false},
		{stts, 20, 3, false},
		{stts, 30, 4, false},
		{stts, 31, 5, false},
		{stts, 43, 5, false},
		{stts, 44, 5, false},
		{stts, 45, 6, false},
		{stts, 57, 6, false},
		{stts, 58, 0, true},
		{sttsZero, 0, 1, false},
		{sttsZero, 10, 2, false},
		{sttsZero, 19, 3, false},
		{sttsZero, 20, 3, false},
		{sttsZero, 21, 0, true},
	}

	for _, tc := range testCases {
		gotNr, err := tc.stts.GetSampleNrAtTime(tc.startTime)
		if tc.expectError {
			if err == nil {
				t.Errorf("Did not get error for startTime %d", tc.startTime)
			}
			continue
		}
		if err != nil {
			t.Error(err)
		}
		if gotNr != tc.sampleNr {
			t.Errorf("Got sampleNr %d instead of %d for %d", gotNr, tc.sampleNr, tc.startTime)
		}
	}
}

func TestGetDecodeTime(t *testing.T) {
	stts := mp4.SttsBox{
		SampleCount:     []uint32{3, 1, 1},
		SampleTimeDelta: []uint32{1024, 1025, 1024},
	}

	testCases := []struct {
		sampleNr    uint32
		expectedDec uint64
		expectedDur uint32
	}{
		{1, 0, 1024},
		{3, 2 * 1024, 1024},
		{4, 3 * 1024, 1025},
		{5, 3*1024 + 1025, 1024},
	}
	for idx, tc := range testCases {
		gotDec, gotDur := stts.GetDecodeTime(tc.sampleNr)
		if gotDec != tc.expectedDec {
			t.Errorf("test case %d: got dec %d instead of %d for sampleNr %d", idx, gotDec, tc.expectedDec, tc.sampleNr)
		}
		if gotDur != tc.expectedDur {
			t.Errorf("test case %d: got dur %d instead of %d for sampleNr %d", idx, gotDur, tc.expectedDur, tc.sampleNr)
		}
	}
}
