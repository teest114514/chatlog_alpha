package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestEncDecPasp(t *testing.T) {

	b := &mp4.PaspBox{HSpacing: 3, VSpacing: 2}
	boxDiffAfterEncodeAndDecode(t, b)
}
