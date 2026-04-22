package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestEncodeDecodeCdat(t *testing.T) {

	cdat := mp4.CdatBox{
		Data: []byte{0x01, 0x02, 0x03, 0x04},
	}
	boxDiffAfterEncodeAndDecode(t, &cdat)
}
