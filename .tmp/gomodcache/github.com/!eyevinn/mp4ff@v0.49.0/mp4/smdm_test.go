package mp4_test

import (
	"fmt"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSmDm(t *testing.T) {
	// Create a sample SmDm box with test values
	smdm := mp4.CreateSmDmBox(
		1000, 2000, // Primary R
		3000, 4000, // Primary G
		5000, 6000, // Primary B
		7000, 8000, // White Point
		10000, 100, // Luminance Max/Min
	)

	// Test the box using the common test function
	boxDiffAfterEncodeAndDecode(t, smdm)

	// Test bad box size
	data := encodeBox(t, smdm)
	changeBoxSizeAndAssertError(t, data, 0, uint32(smdm.Size()-1), fmt.Sprintf("decode SmDm pos 0: invalid box size %d", smdm.Size()-1))
}
