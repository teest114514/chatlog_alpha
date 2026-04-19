package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestTrep(t *testing.T) {
	trep := &mp4.TrepBox{TrackID: 1}
	trep.AddChild(&mp4.KindBox{SchemeURI: "X", Value: "Y"})
	boxDiffAfterEncodeAndDecode(t, trep)
}
