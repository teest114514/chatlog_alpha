package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestSdtp(t *testing.T) {
	entries := []mp4.SdtpEntry{
		mp4.NewSdtpEntry(0, 2, 0, 0),
		mp4.NewSdtpEntry(0, 1, 2, 0),
		mp4.NewSdtpEntry(1, 2, 1, 1),
	}

	boxDiffAfterEncodeAndDecode(t, mp4.CreateSdtpBox(entries))
}
