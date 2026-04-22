package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSaio(t *testing.T) {
	saioV0 := &mp4.SaioBox{
		Version: 0,
		Offset:  []int64{12},
	}
	boxDiffAfterEncodeAndDecode(t, saioV0)

	saioV1 := &mp4.SaioBox{
		Version: 0,
		Offset:  []int64{12},
	}
	boxDiffAfterEncodeAndDecode(t, saioV1)

}
