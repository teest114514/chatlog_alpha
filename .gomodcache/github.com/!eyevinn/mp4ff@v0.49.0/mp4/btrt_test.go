package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestBtrt(t *testing.T) {

	boxes := []mp4.Box{
		&mp4.BtrtBox{
			BufferSizeDB: 123456,
			MaxBitrate:   2000000,
			AvgBitrate:   1500000,
		},
	}

	for _, inBox := range boxes {
		boxDiffAfterEncodeAndDecode(t, inBox)
	}
}
