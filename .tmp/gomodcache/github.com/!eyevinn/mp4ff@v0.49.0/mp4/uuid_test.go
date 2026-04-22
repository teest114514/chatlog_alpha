package mp4_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestUUIDVariants(t *testing.T) {

	testInputs := []struct {
		expectedSubType string
		rawData         string
	}{
		{
			"tfxd", "0000002c757569646d1d9b0542d544e680e2141daff757b201000000000105c649bda4000000000000054600",
		},
		{
			"tfrf", "0000002d75756964d4807ef2ca3946958e5426cb9e46a79f0100000001000105c649c2ea000000000000054600",
		},
		{
			"unknown", "0000002c757569646e1d9b0542d544e680e2141daff757b201000000000105c649bda4000000000000054600",
		},
	}

	for _, ti := range testInputs {
		inRawBox, _ := hex.DecodeString(ti.rawData)
		inbuf := bytes.NewBuffer(inRawBox)
		hdr, err := mp4.DecodeHeader(inbuf)
		if err != nil {
			t.Error(err)
		}
		uuidRead, err := mp4.DecodeUUIDBox(hdr, 0, inbuf)
		if err != nil {
			t.Error(err)
		}
		uBox := uuidRead.(*mp4.UUIDBox)
		if uBox.SubType() != ti.expectedSubType {
			t.Errorf("got subtype %s instead of %s", uBox.SubType(), ti.expectedSubType)
		}

		outbuf := &bytes.Buffer{}

		err = uuidRead.Encode(outbuf)
		if err != nil {
			t.Error(err)
		}

		outRawBox := outbuf.Bytes()

		if !bytes.Equal(inRawBox, outRawBox) {
			for i := 0; i < len(inRawBox); i++ {
				t.Logf("%3d %02x %02x\n", i, inRawBox[i], outRawBox[i])
			}
			t.Errorf("%s: Non-matching in and out binaries", ti.expectedSubType)
		}
	}
}

func TestSetUUID(t *testing.T) {
	testCases := []struct {
		uuidStr    string
		expected   mp4.UUID
		shouldFail bool
	}{
		{
			uuidStr:    "6d1d9b05-42d5-44e6-80e2-141daff757b2",
			shouldFail: false,
		},
		{
			uuidStr:    "6d1d9b05-42d5-44e6-80e2-141daff757",
			shouldFail: true,
		},
	}
	for i, tc := range testCases {
		u := mp4.UUIDBox{}
		err := u.SetUUID(tc.uuidStr)
		if tc.shouldFail {
			if err == nil {
				t.Errorf("case %d did not fail as expected", i)
			}
			continue
		}
		if u.UUID() != tc.uuidStr {
			t.Errorf("got %s instead of %s", u.UUID(), tc.uuidStr)
		}
	}
}

func TestUUIDEncodeDecoder(t *testing.T) {

	tfrf := mp4.NewTfrfBox(1, []uint64{0}, []uint64{1000000})
	boxDiffAfterEncodeAndDecode(t, tfrf)

	tfxd := mp4.NewTfxdBox(0, 1_000_000)
	boxDiffAfterEncodeAndDecode(t, tfxd)
}

func TestUnpackKey(t *testing.T) {
	cases := []struct {
		desc        string
		keyStr      string
		expected    []byte
		expectedErr string
	}{
		{
			desc:   "valid hex key",
			keyStr: "00112233445566778899aabbccddeeff",
			expected: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			expectedErr: "",
		},
		{
			desc:        "invalid hex key",
			keyStr:      "0011223x445566778899aabbccddeeff",
			expectedErr: "bad hex 001122...ddeeff: encoding/hex: invalid byte: U+0078 'x'",
		},
		{
			desc:        "wrong length key",
			keyStr:      "00112233445566778899aab",
			expectedErr: "cannot decode key 00112233445566778899aab",
		},
		{
			desc:   "good uuid",
			keyStr: "00112233-4455-6677-8899-aabbccddeeff",
			expected: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			expectedErr: "",
		},
		{
			desc:        "bad uuid, misplaced dashes",
			keyStr:      "00----112233445566778899aabbccddeeff",
			expectedErr: "bad uuid format: 00----...ddeeff",
		},
		{
			desc:        "bad uuid too many dashes",
			keyStr:      "00112233-4-55-6677-8899-aabbccddeeff",
			expectedErr: "bad uuid format: 001122...ddeeff",
		},
		{
			desc:        "bad hex in uuid",
			keyStr:      "0011223x-4455-6677-8899-aabbccddeeff",
			expectedErr: "bad uuid 001122...ddeeff: encoding/hex: invalid byte: U+0078 'x'",
		},
		{
			desc:        "valid base64 key",
			keyStr:      "ABEiM0RVZneImaq7zN3u/w=-",
			expectedErr: "bad base64 ABEiM0...3u/w=-: illegal base64 data at input byte 22",
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			key, err := mp4.UnpackKey(c.keyStr)
			if c.expectedErr != "" {
				if err == nil {
					t.Error("expected error but got nil")
				}
				if err.Error() != c.expectedErr {
					t.Errorf("error %q not matching expected error %q", err, c.expectedErr)
				}
				return
			}
			if !bytes.Equal(key, c.expected) {
				t.Errorf("got %x instead of %x", key, c.expected)
			}
		})
	}

}
