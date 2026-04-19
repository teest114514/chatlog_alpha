package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestFtyp(t *testing.T) {

	ftyp := mp4.CreateFtyp()
	boxDiffAfterEncodeAndDecode(t, ftyp)
}
