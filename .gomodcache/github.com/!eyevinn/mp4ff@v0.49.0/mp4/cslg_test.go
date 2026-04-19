package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestCslgEncodeDecode(t *testing.T) {
	cslg := mp4.CslgBox{
		Version:                      0,
		CompositionToDTSShift:        -100,
		LeastDecodeToDisplayDelta:    200,
		GreatestDecodeToDisplayDelta: -30,
		CompositionStartTime:         1600,
		CompositionEndTime:           1000,
	}

	boxDiffAfterEncodeAndDecode(t, &cslg)

	cslg = mp4.CslgBox{
		Version:                      1,
		CompositionToDTSShift:        -100,
		LeastDecodeToDisplayDelta:    200,
		GreatestDecodeToDisplayDelta: -30,
		CompositionStartTime:         1600,
		CompositionEndTime:           1000,
	}

	boxDiffAfterEncodeAndDecode(t, &cslg)
}
