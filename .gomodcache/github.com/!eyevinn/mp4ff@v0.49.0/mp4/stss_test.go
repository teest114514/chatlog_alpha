package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestStss(t *testing.T) {

	// The following stss box has two sync samples
	stss := &mp4.StssBox{
		SampleNumber: []uint32{1, 26},
	}

	tests := []struct {
		sample uint32
		isSync bool
	}{
		{
			sample: 1,
			isSync: true,
		},
		{
			sample: 2,
			isSync: false,
		},
		{
			sample: 26,
			isSync: true,
		},
		{
			sample: 30,
			isSync: false,
		},
	}

	for _, test := range tests {
		isSync := stss.IsSyncSample(test.sample)
		if isSync != test.isSync {
			t.Errorf("Sample %d has not write sync state", test.sample)
		}
	}
}

func TestStssEncodeDecode(t *testing.T) {
	stss := &mp4.StssBox{
		SampleNumber: []uint32{1, 26},
	}

	boxDiffAfterEncodeAndDecode(t, stss)
}

func TestStssNoSamples(t *testing.T) {
	// The following pathological stss box has no samples
	stss := &mp4.StssBox{
		SampleNumber: nil,
	}

	tests := []struct {
		sample uint32
		isSync bool
	}{
		{
			sample: 1,
			isSync: false,
		},
	}

	for _, test := range tests {
		isSync := stss.IsSyncSample(test.sample)
		if isSync != test.isSync {
			t.Errorf("Sample %d has not write sync state", test.sample)
		}
	}
}
