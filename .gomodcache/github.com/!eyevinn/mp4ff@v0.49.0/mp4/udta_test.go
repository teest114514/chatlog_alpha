package mp4_test

import (
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestUdta(t *testing.T) {
	udta := &mp4.UdtaBox{}
	unknown := mp4.CreateUnknownBox("\xa9enc", 12, []byte{0, 0, 0, 0})
	udta.AddChild(unknown) // Any arbitrary box
	boxDiffAfterEncodeAndDecode(t, udta)
}
