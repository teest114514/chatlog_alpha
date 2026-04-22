package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestMimeBox(t *testing.T) {
	mimeZeroTerminated := mp4.MimeBox{
		Version:              0,
		Flags:                0,
		ContentType:          "image/png",
		LacksZeroTermination: false,
	}
	boxDiffAfterEncodeAndDecode(t, &mimeZeroTerminated)

	mimeWithoutZeroTermination := mp4.MimeBox{
		Version:              0,
		Flags:                0,
		ContentType:          "image/png",
		LacksZeroTermination: true,
	}
	boxDiffAfterEncodeAndDecode(t, &mimeWithoutZeroTermination)

}
