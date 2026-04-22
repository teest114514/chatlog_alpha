package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestEncDecClap(t *testing.T) {

	b := &mp4.ClapBox{
		CleanApertureWidthN: 1, CleanApertureWidthD: 2,
		CleanApertureHeightN: 3, CleanApertureHeightD: 4,
		HorizOffN: 5, HorizOffD: 6,
		VertOffN: 7, VertOffD: 8,
	}
	boxDiffAfterEncodeAndDecode(t, b)
}
