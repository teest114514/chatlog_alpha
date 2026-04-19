package mp4_test

import (
	"fmt"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestCoLL(t *testing.T) {
	// Create a sample CoLL box with test values
	coll := mp4.CreateCoLLBox(
		1000, // maxCLL
		500,  // maxFALL
	)

	// Test the box using the common test function
	boxDiffAfterEncodeAndDecode(t, coll)

	// Test bad box size
	data := encodeBox(t, coll)
	changeBoxSizeAndAssertError(t, data, 0, uint32(coll.Size()-1), fmt.Sprintf("decode CoLL pos 0: invalid box size %d", coll.Size()-1))
}
