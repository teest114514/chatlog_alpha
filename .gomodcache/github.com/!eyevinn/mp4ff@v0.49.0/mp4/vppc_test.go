package mp4_test

import (
	"bytes"
	"testing"

	"github.com/Eyevinn/mp4ff/mp4"
)

func TestVppC(t *testing.T) {
	// Create a sample VppC box
	vppc := &mp4.VppCBox{
		Version:                 1,
		Flags:                   0,
		Profile:                 1,
		Level:                   10,
		BitDepth:                10,
		ChromaSubsampling:       1,
		VideoFullRangeFlag:      1,
		ColourPrimaries:         1,
		TransferCharacteristics: 1,
		MatrixCoefficients:      1,
		CodecInitData:           []byte{0x01, 0x02, 0x03, 0x04},
	}

	boxDiffAfterEncodeAndDecode(t, vppc)

	buf := bytes.Buffer{}
	err := vppc.Encode(&buf)
	if err != nil {
		t.Error(err)
	}

	data := buf.Bytes()

	// Check that there is an error for Version != 0 (after 8-byte header)
	raw := make([]byte, len(data))
	copy(raw, data)
	raw[8] = 0
	_, err = mp4.DecodeBox(0, bytes.NewBuffer(raw))
	errMsg := "decode vpcC pos 0: version 0 not supported"
	if err == nil || err.Error() != errMsg {
		t.Errorf("Expected error msg: %q", errMsg)
	}

	// Check that there is an error if the CodecInitSize is not compatible withthe box size.
	copy(raw, data)
	raw[19] = 2
	assertBoxDecodeError(t, raw, 0, "decode vpcC pos 0: incorrect box size")

	// Check that there is an error if the box is too short
	tooShortSize := uint32(9)
	changeBoxSizeAndAssertError(t, data, 0, tooShortSize, "decode vpcC pos 0: box too short < 20 bytes")
}
