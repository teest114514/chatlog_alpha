package hevc

import (
	"encoding/hex"
	"math/bits"
	"testing"
)

func TestCodecString(t *testing.T) {
	testCases := []struct {
		hexSPS      string
		codecString string
	}{
		{
			"420101016000000300b0000003000003007ba003c08010e59447924525ac041400000300040000030067c36bdcf50007a12000f42640",
			"hvc1.1.6.L123.B0",
		},
		{
			"420101016000000300900000030000030078a0021c801e0596566924caf01680800001f480003a9804",
			"hvc1.1.6.L120.90",
		},
	}
	for _, tc := range testCases {
		spsBytes, err := hex.DecodeString(tc.hexSPS)
		if err != nil {
			t.Error(err)
		}
		sps, err := ParseSPSNALUnit(spsBytes)
		if err != nil {
			t.Error(err)
		}
		got := CodecString("hvc1", sps)
		if got != tc.codecString {
			t.Errorf("Got %q wanted %q", got, tc.codecString)
		}
	}

}

func TestReverseUint32bits(t *testing.T) {
	testCases := []struct {
		bits uint32
		rev  uint32
	}{
		{0x00000002, 0x40000000},
		{0x12345678, 0x1e6a2c48},
	}
	for _, tc := range testCases {
		got := bits.Reverse32(tc.bits)
		if got != tc.rev {
			t.Errorf("Got %04x instead of %04x for %04x", got, tc.rev, tc.bits)
		}
	}
}
