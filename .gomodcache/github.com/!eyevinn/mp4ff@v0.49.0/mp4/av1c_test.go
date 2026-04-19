package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/av1"
	"github.com/Eyevinn/mp4ff/mp4"
)

func TestEncodeDecodeAvc1(t *testing.T) {
	adc := mp4.Av1CBox{
		CodecConfRec: av1.CodecConfRec{
			Version: 1,
		},
	}

	boxDiffAfterEncodeAndDecode(t, &adc)

}
