package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSsix(t *testing.T) {
	ssix := mp4.SsixBox{}
	ss := mp4.SubSegment{
		Ranges: []mp4.SubSegmentRange{
			mp4.NewSubSegmentRange(1, 2),
			mp4.NewSubSegmentRange(3, 4),
		}}
	ssix.SubSegments = append(ssix.SubSegments, ss)
	ss = mp4.SubSegment{
		Ranges: []mp4.SubSegmentRange{
			mp4.NewSubSegmentRange(2, 2),
			mp4.NewSubSegmentRange(5, 4),
		}}
	ssix.SubSegments = append(ssix.SubSegments, ss)
	boxDiffAfterEncodeAndDecode(t, &ssix)
}
