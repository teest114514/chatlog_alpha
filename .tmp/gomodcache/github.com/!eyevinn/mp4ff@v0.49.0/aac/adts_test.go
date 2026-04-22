package aac

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/go-test/deep"
)

func TestADTS(t *testing.T) {

	adtsHdrStart, err := NewADTSHeader(48000, 2, 2, 412)
	if err != nil {
		t.Error(err)
	}

	adtsBytes := adtsHdrStart.Encode()

	testCases := []struct {
		adtsBytes       []byte
		wantedHdr       *ADTSHeader
		wantedOffset    int
		wantedFrequency uint16
		wantedError     error
	}{
		{
			adtsBytes:       adtsBytes,
			wantedHdr:       adtsHdrStart,
			wantedOffset:    0,
			wantedFrequency: 48000,
		},
		{
			adtsBytes:       append([]byte{0xfe}, adtsBytes...),
			wantedHdr:       adtsHdrStart,
			wantedOffset:    1,
			wantedFrequency: 48000,
		},
	}

	for _, tc := range testCases {
		gotHdr, gotOffset, gotErr := DecodeADTSHeader(bytes.NewBuffer(tc.adtsBytes))
		if gotErr != tc.wantedError {
			t.Errorf("Got error %s instead of %s", gotErr, tc.wantedError)
		}
		if gotOffset != tc.wantedOffset {
			t.Errorf("Got offset %d instead of %d", gotOffset, tc.wantedOffset)
		}
		if tc.wantedFrequency != gotHdr.Frequency() {
			t.Errorf("Got frequency %d instead of %d", gotHdr.Frequency(), tc.wantedFrequency)
		}
		if diff := deep.Equal(gotHdr, tc.wantedHdr); diff != nil {
			t.Error(diff)
		}
	}
}

func TestAdtsHdrLengthWithCRC(t *testing.T) {
	hexData := "fff84c802cdffc1183"
	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Error(err)
	}
	gotHdr, gotOffset, err := DecodeADTSHeader(bytes.NewBuffer(data))
	if err != nil {
		t.Error(err)
	}
	if gotOffset != 0 {
		t.Errorf("Got offset %d instead of 0", gotOffset)
	}
	if gotHdr.HeaderLength != 9 {
		t.Errorf("Got header length %d instead of 9", gotHdr.HeaderLength)
	}
}

func TestAdtsHeaderParsingWithDoubleFF(t *testing.T) {
	hexData := "48fffff94cb02b5ffc21aa14"
	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Error(err)
	}
	_, gotOffset, err := DecodeADTSHeader(bytes.NewBuffer(data))
	if err != nil {
		t.Error(err)
	}
	wantedOffset := 2
	if gotOffset != wantedOffset {
		t.Errorf("Got offset %d instead of %d", gotOffset, wantedOffset)
	}
}
