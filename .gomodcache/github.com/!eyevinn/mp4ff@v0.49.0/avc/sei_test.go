package avc_test

import (
	"encoding/hex"
	"testing"

	"github.com/Eyevinn/mp4ff/avc"
	"github.com/Eyevinn/mp4ff/sei"
)

func TestSEIParsing(t *testing.T) {
	testCases := []struct {
		desc              string
		spsNALUHex        string
		seiNALUHex        string
		expectedMsgs      []sei.SEIMessage
		expectedTimeStamp string
		expectedErr       error
	}{
		{
			desc:              "Test SEI pic_timing with SPS HRD params",
			spsNALUHex:        "6764002aac2cac0780227e5c04f000003e90001d4c0e6a000337ec001bcef5ef80f8442370",
			seiNALUHex:        "06010e0000030000030000030002120806ff0b80",
			expectedMsgs:      []sei.SEIMessage{&sei.PicTimingAvcSEI{}},
			expectedTimeStamp: "11:56:31:03 offset=0",
			expectedErr:       sei.ErrRbspTrailingBitsMissing,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			spsBytes, err := hex.DecodeString(tc.spsNALUHex)
			if err != nil {
				t.Error(err)
			}
			sps, err := avc.ParseSPSNALUnit(spsBytes, true)
			if err != nil {
				t.Fatalf("ParseSPSNALU failed: %v", err)
			}
			seiBytes, err := hex.DecodeString(tc.seiNALUHex)
			if err != nil {
				t.Error(err)
			}
			msgs, err := avc.ParseSEINalu(seiBytes, sps)
			if err != tc.expectedErr {
				t.Fatalf("expected err %q got : %v", tc.expectedErr, err)
			}
			if len(msgs) != len(tc.expectedMsgs) {
				t.Fatalf("Expected %d messages, got %d", len(tc.expectedMsgs), len(msgs))
			}
			for i, msg := range msgs {
				msgType := msg.Type()
				if msgType != tc.expectedMsgs[i].Type() {
					t.Errorf("Expected message type %d, got %d", tc.expectedMsgs[i].Type(), msg.Type())
				}
				if (msg.Type() == sei.SEIPicTimingType) && tc.expectedTimeStamp != "" {
					picTimeSEI := msg.(*sei.PicTimingAvcSEI)
					gotTimestamp := picTimeSEI.Clocks[0].String()
					if gotTimestamp != tc.expectedTimeStamp {
						t.Errorf("Expected timestamp %s, got %s", tc.expectedTimeStamp, gotTimestamp)
					}
				}
			}
		})
	}
}
