package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSaiz(t *testing.T) {
	saiz := &mp4.SaizBox{DefaultSampleInfoSize: 1}
	boxDiffAfterEncodeAndDecode(t, saiz)
}
