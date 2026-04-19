package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestFrma(t *testing.T) {
	frma := &mp4.FrmaBox{DataFormat: "avc1"}
	boxDiffAfterEncodeAndDecode(t, frma)
}
