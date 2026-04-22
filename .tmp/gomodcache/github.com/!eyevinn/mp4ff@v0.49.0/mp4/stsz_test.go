package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestStszEncDec(t *testing.T) {
	stsz := mp4.StszBox{
		SampleUniformSize: 0,
		SampleNumber:      3,
		SampleSize:        []uint32{112, 234, 120},
	}
	boxDiffAfterEncodeAndDecode(t, &stsz)

	stsz = mp4.StszBox{
		SampleUniformSize: 512,
		SampleNumber:      1, // One sample with uniform size
		SampleSize:        nil,
	}
	boxDiffAfterEncodeAndDecode(t, &stsz)
}

func TestStszGetTotalSize(t *testing.T) {
	testCases := []struct {
		name       string
		stsz       mp4.StszBox
		startNr    uint32
		endNr      uint32
		wantedSize uint64
	}{
		{
			name: "uniform size",
			stsz: mp4.StszBox{
				SampleUniformSize: 512,
				SampleNumber:      4,
			},
			startNr:    1,
			endNr:      3,
			wantedSize: 3 * 512,
		},
		{
			name: "sample sizes",
			stsz: mp4.StszBox{
				SampleUniformSize: 0,
				SampleNumber:      4,
				SampleSize:        []uint32{1, 2, 3, 4},
			},
			startNr:    1,
			endNr:      3,
			wantedSize: 1 + 2 + 3,
		},
	}

	for _, tc := range testCases {
		gotSize, err := tc.stsz.GetTotalSampleSize(tc.startNr, tc.endNr)
		if err != nil {
			t.Error(err)
		}
		if gotSize != tc.wantedSize {
			t.Errorf("%q: got size %d instead of %d", tc.name, gotSize, tc.wantedSize)
		}
	}
}
