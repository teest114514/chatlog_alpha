package aac

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/go-test/deep"
)

func TestAudioSpecificConfigEncodeDecode(t *testing.T) {

	testCases := []AudioSpecificConfig{
		{
			ObjectType:           AAClc,
			ChannelConfiguration: 2,
			SamplingFrequency:    48000,
			ExtensionFrequency:   0,
			SBRPresentFlag:       false,
			PSPresentFlag:        false,
		},
		{
			ObjectType:           HEAACv1,
			ChannelConfiguration: 2,
			SamplingFrequency:    24000,
			ExtensionFrequency:   48000,
			SBRPresentFlag:       true,
			PSPresentFlag:        false,
		},
		{
			ObjectType:           HEAACv2,
			ChannelConfiguration: 1,
			SamplingFrequency:    24000,
			ExtensionFrequency:   48000,
			SBRPresentFlag:       true,
			PSPresentFlag:        true,
		},
	}

	for _, asc := range testCases {

		buf := &bytes.Buffer{}
		err := asc.Encode(buf)
		if err != nil {
			t.Error(err)
		}
		ascBytes := buf.Bytes()
		t.Logf("ASC: %s\n", hex.EncodeToString(ascBytes))

		readBuf := bytes.NewBuffer(ascBytes)
		gotAsc, err := DecodeAudioSpecificConfig(readBuf)
		if err != nil {
			t.Error(err)
		}
		diff := deep.Equal(*gotAsc, asc)
		if diff != nil {
			t.Errorf("Diff %v for %+v", diff, asc)
		}
	}
}

func TestVariousInputs(t *testing.T) {

	testCases := []struct {
		desc          string
		data          []byte
		expectedError string
	}{
		{
			desc:          "unsupported object type",
			data:          []byte{0x0f, 0x00},
			expectedError: "unsupported object type: 1",
		},
		{
			desc:          "bad frequency index",
			data:          []byte{0x17, 0x30},
			expectedError: "strange frequency index",
		},
		{
			desc:          "too short extended frequency",
			data:          []byte{0x17, 0x80, 0x40},
			expectedError: "strange frequency index",
		},
	}

	for _, c := range testCases {
		t.Run(c.desc, func(t *testing.T) {
			readBuf := bytes.NewBuffer(c.data)
			_, err := DecodeAudioSpecificConfig(readBuf)
			if err == nil || err.Error() != c.expectedError {
				t.Errorf("Expected error: %s", c.expectedError)
			}
		})
	}

	t.Run("32768Hz", func(t *testing.T) {
		data := []byte{0x17, 0x80, 0x40, 0x00, 0x00}
		readBuf := bytes.NewBuffer(data)
		gotAsc, err := DecodeAudioSpecificConfig(readBuf)
		if err != nil {
			t.Error(err)
		}
		if gotAsc.SamplingFrequency != 32768 {
			t.Errorf("Expected 32768Hz, got %d", gotAsc.SamplingFrequency)
		}
	})
}
