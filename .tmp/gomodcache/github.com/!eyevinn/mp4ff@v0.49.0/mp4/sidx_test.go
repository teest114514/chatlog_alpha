package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSidx(t *testing.T) {

	sidx := &mp4.SidxBox{}

	sidx.ReferenceID = 1
	sidx.Timescale = 48000
	sidx.EarliestPresentationTime = 12
	sidx.FirstOffset = 1024
	sidx.AnchorPoint = 1068

	ref := mp4.SidxRef{
		ReferenceType:      0, // Media
		ReferencedSize:     2048,
		SubSegmentDuration: 1024 * 15,
		StartsWithSAP:      1,
		SAPType:            1,
		SAPDeltaTime:       0,
	}
	sidx.SidxRefs = append(sidx.SidxRefs, ref)

	boxDiffAfterEncodeAndDecode(t, sidx)
}
