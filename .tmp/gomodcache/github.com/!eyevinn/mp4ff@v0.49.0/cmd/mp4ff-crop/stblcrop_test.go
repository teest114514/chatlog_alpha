package main

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSttsCrop(t *testing.T) {
	stts1 := mp4.SttsBox{
		SampleCount:     []uint32{3189, 1, 22968, 3, 1, 130878},
		SampleTimeDelta: []uint32{1024, 6752, 1024, 1, 61, 1024},
	}
	cases := []struct {
		sttsIn               mp4.SttsBox
		lastSampleNr         uint32
		expectedSampleCounts []uint32
		expectedTimeDeltas   []uint32
	}{
		{stts1, 1, []uint32{1}, []uint32{1024}},
		{stts1, 2, []uint32{2}, []uint32{1024}},
		{stts1, 3189, []uint32{3189}, []uint32{1024}},
		{stts1, 3190, []uint32{3189, 1}, []uint32{1024, 6752}},
		{stts1, 3191, []uint32{3189, 1, 1}, []uint32{1024, 6752, 1024}},
		{stts1, 3191, []uint32{3189, 1, 1}, []uint32{1024, 6752, 1024}},
		{stts1, 157040, []uint32{3189, 1, 22968, 3, 1, 130878}, []uint32{1024, 6752, 1024, 1, 61, 1024}},
	}

	for _, c := range cases {
		stts := mp4.SttsBox{
			SampleCount:     make([]uint32, len(c.sttsIn.SampleCount)),
			SampleTimeDelta: make([]uint32, len(c.sttsIn.SampleTimeDelta)),
		}
		copy(stts.SampleCount, c.sttsIn.SampleCount)
		copy(stts.SampleTimeDelta, c.sttsIn.SampleTimeDelta)
		cropStts(&stts, c.lastSampleNr)
		if len(stts.SampleCount) != len(c.expectedSampleCounts) {
			t.Errorf("Expected %d sampleCounts, got %d", len(c.expectedSampleCounts), len(stts.SampleCount))
		}
		if len(stts.SampleTimeDelta) != len(c.expectedTimeDeltas) {
			t.Errorf("Expected %d timeDeltas, got %d", len(c.expectedTimeDeltas), len(stts.SampleTimeDelta))
		}
		for i := 0; i < len(stts.SampleCount); i++ {
			if stts.SampleCount[i] != c.expectedSampleCounts[i] {
				t.Errorf("Expected sampleCount %d to be %d, got %d", i, c.expectedSampleCounts[i], stts.SampleCount[i])
			}
		}
		for i := 0; i < len(stts.SampleTimeDelta); i++ {
			if stts.SampleTimeDelta[i] != c.expectedTimeDeltas[i] {
				t.Errorf("Expected timeDelta %d to be %d, got %d", i, c.expectedTimeDeltas[i], stts.SampleTimeDelta[i])
			}
		}
	}
}
